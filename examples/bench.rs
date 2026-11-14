//! Latency benchmark against running daemons; started by scripts/bench.sh.
//! Usage: bench <a-http> <a-token> <a-sock> <b-http> <b-token> <b-sock> <repo-a> <repo-b> <exe> <n>

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wormhole::local::LocalClient;

async fn post(addr: SocketAddr, token: &str, body: &Value) -> Value {
    let b = body.to_string();
    let req = format!(
        "POST /hook HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{b}",
        b.len()
    );
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let body = out.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    serde_json::from_str(body).unwrap_or(json!({}))
}

fn input(event: &str, session: &str, cwd: &Path) -> Value {
    json!({"session_id": session, "cwd": cwd, "hook_event_name": event, "transcript_path": "/dev/null"})
}

fn report(name: &str, mut v: Vec<Duration>) {
    v.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let p = |q: f64| ms(v[((v.len() as f64 - 1.0) * q).round() as usize]);
    println!(
        "{name}: n={} p50={:.2}ms p95={:.2}ms p99={:.2}ms max={:.2}ms",
        v.len(),
        p(0.5),
        p(0.95),
        p(0.99),
        ms(*v.last().unwrap())
    );
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (a_http, a_tok, a_sock): (SocketAddr, &str, PathBuf) =
        (a[0].parse().unwrap(), &a[1], a[2].clone().into());
    let (b_http, b_tok, b_sock): (SocketAddr, &str, PathBuf) =
        (a[3].parse().unwrap(), &a[4], a[5].clone().into());
    let (repo_a, repo_b) = (PathBuf::from(&a[6]), PathBuf::from(&a[7]));
    let exe = PathBuf::from(&a[8]);
    let n: usize = a[9].parse().unwrap();
    let (sa, sb) = (
        "bench-a-0000-4000-8000-000000000001",
        "bench-b-0000-4000-8000-000000000002",
    );
    post(a_http, a_tok, &input("SessionStart", sa, &repo_a)).await;
    post(b_http, b_tok, &input("SessionStart", sb, &repo_b)).await;

    // PreToolUse on a file this session already leases (renew path).
    let mut pre = input("PreToolUse", sa, &repo_a);
    pre["tool_name"] = json!("Edit");
    pre["tool_input"] =
        json!({"file_path": repo_a.join("src/lib.rs"), "old_string": "a", "new_string": "b"});
    post(a_http, a_tok, &pre).await;
    let mut t = Vec::new();
    for _ in 0..n {
        let s = Instant::now();
        post(a_http, a_tok, &pre).await;
        t.push(s.elapsed());
    }
    report("hook PreToolUse (lease renew, via hub)", t);

    // PreToolUse that conflicts (warning path).
    let mut pre_b = input("PreToolUse", sb, &repo_b);
    pre_b["tool_name"] = json!("Edit");
    pre_b["tool_input"] =
        json!({"file_path": repo_b.join("src/lib.rs"), "old_string": "a", "new_string": "b"});
    let mut t = Vec::new();
    for _ in 0..n {
        let s = Instant::now();
        let r = post(b_http, b_tok, &pre_b).await;
        t.push(s.elapsed());
        assert!(r.to_string().contains("WARNING"));
    }
    report("hook PreToolUse (conflict warning, via hub)", t);

    // PostToolUse with nothing to deliver.
    let mut postb = input("PostToolUse", sa, &repo_a);
    postb["tool_name"] = json!("Bash");
    postb["tool_input"] = json!({"command": "ls"});
    postb["tool_response"] = json!({});
    let mut t = Vec::new();
    for _ in 0..n {
        let s = Instant::now();
        post(a_http, a_tok, &postb).await;
        t.push(s.elapsed());
    }
    report("hook PostToolUse (Bash, empty inbox)", t);

    // SessionStart through the `wormhole hook` command (process start + socket round trip).
    let ss = input("SessionStart", sa, &repo_a).to_string();
    let mut t = Vec::new();
    for _ in 0..n.min(100) {
        let s = Instant::now();
        let mut c = tokio::process::Command::new(&exe)
            .args(["hook", "--socket"])
            .arg(&a_sock)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(ss.as_bytes())
            .await
            .unwrap();
        c.wait().await.unwrap();
        t.push(s.elapsed());
    }
    report("hook SessionStart (wormhole hook command)", t);

    // Message delivery: A sends, B's attached channel client receives the push.
    let mut sub = LocalClient::connect(&b_sock).await.unwrap();
    sub.call("attach", json!({"session": sb})).await.unwrap();
    let mut sender = LocalClient::connect(&a_sock).await.unwrap();
    let mut t = Vec::new();
    for i in 0..n {
        let s = Instant::now();
        sender
            .call("tool", json!({"session": sa, "name": "send", "args": {"to": format!("session:{sb}"), "body": format!("bench {i}")}}))
            .await
            .unwrap();
        let p = sub.next_push(Duration::from_secs(5)).await.expect("push");
        assert!(p["text"].as_str().unwrap().contains(&format!("bench {i}")));
        t.push(s.elapsed());
    }
    report(
        "message A->B push to channel client (send + hub + fan-out)",
        t,
    );

    // Pull path: same messages are waiting for B's next PostToolUse.
    let mut postb2 = postb.clone();
    postb2["session_id"] = json!(sb);
    postb2["cwd"] = json!(repo_b);
    let s = Instant::now();
    let r = post(b_http, b_tok, &postb2).await;
    let fit = r
        .to_string()
        .matches("wormhole-message from_session")
        .count();
    println!(
        "hook PostToolUse delivering {fit} queued messages: {:.2}ms",
        s.elapsed().as_secs_f64() * 1000.0
    );
}
