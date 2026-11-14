#![allow(dead_code)]
//! Test harness: one hub and two daemons in-process over localhost, static identity.

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wormhole::daemon::{self, DaemonConfig, DaemonHandle};
use wormhole::hub::{self, identity::IdentityConfig, HubConfig, HubHandle};
use wormhole::local::LocalClient;

static N: AtomicUsize = AtomicUsize::new(0);

pub fn tmpdir() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let d = base.join(format!(
        "t{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A checkout of the shared test repository at `dir`.
pub fn make_repo(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join(".git/config"),
        "[remote \"origin\"]\n\turl = git@example.com:team/proj.git\n",
    )
    .unwrap();
    std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    dir.to_path_buf()
}

pub struct Opts {
    pub lease_ttl: Duration,
    pub protected: Vec<String>,
    pub reconnect_min: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            lease_ttl: Duration::from_secs(60),
            protected: vec![],
            reconnect_min: Duration::from_millis(100),
        }
    }
}

pub struct Net {
    pub hub: HubHandle,
    pub a: DaemonHandle,
    pub b: DaemonHandle,
    pub repo_a: PathBuf,
    pub repo_b: PathBuf,
    pub dir: PathBuf,
}

pub async fn start_hub(dir: &Path) -> HubHandle {
    hub::start(HubConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        db: dir.join("hub.sqlite"),
        identity: IdentityConfig::Static,
        hostnames: vec![],
    })
    .await
    .unwrap()
}

pub fn daemon_config(dir: &Path, hub_url: String, who: &str, opts: &Opts) -> DaemonConfig {
    let mut c = DaemonConfig::new(hub_url, dir.join(format!("run-{}/d.sock", &who[..1])));
    c.http_listen = "127.0.0.1:0".parse().unwrap();
    c.static_identity = Some(who.to_string());
    c.protected = opts.protected.clone();
    c.lease_ttl = opts.lease_ttl;
    c.reconnect_min = opts.reconnect_min;
    c
}

pub async fn net(opts: Opts) -> Net {
    let dir = tmpdir();
    let hub = start_hub(&dir).await;
    let url = format!("ws://{}/ws", hub.addr);
    let a = daemon::start(daemon_config(&dir, url.clone(), "alice@machine-a", &opts))
        .await
        .unwrap();
    let b = daemon::start(daemon_config(&dir, url, "bob@machine-b", &opts))
        .await
        .unwrap();
    wait_connected(&a).await;
    wait_connected(&b).await;
    let repo_a = make_repo(&dir.join("a/proj"));
    let repo_b = make_repo(&dir.join("b/proj"));
    Net {
        hub,
        a,
        b,
        repo_a,
        repo_b,
        dir,
    }
}

pub async fn wait_connected(d: &DaemonHandle) {
    let t = Instant::now();
    while d.connects() == 0 {
        assert!(t.elapsed() < Duration::from_secs(5), "daemon never connected");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Minimal HTTP/1.1 request; returns (status, headers, body).
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: {addr}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let out = String::from_utf8_lossy(&out).to_string();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head.split(' ').nth(1).unwrap_or("0").parse().unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

/// POST a hook input the way Claude Code does and return the parsed JSON output
/// (`{}` for an empty body).
pub async fn hook(d: &DaemonHandle, input: Value) -> Value {
    let auth = format!("Bearer {}", d.hook_token);
    let (status, _, body) = http(
        d.http_addr,
        "POST",
        "/hook",
        &[("Content-Type", "application/json"), ("Authorization", &auth)],
        &input.to_string(),
    )
    .await;
    assert_eq!(status, 200, "hook status, body: {body}");
    if body.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body).unwrap()
    }
}

pub fn base(event: &str, session: &str, cwd: &Path) -> Value {
    json!({
        "session_id": session,
        "transcript_path": "/dev/null",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": event,
    })
}

pub fn session_start(session: &str, cwd: &Path) -> Value {
    let mut v = base("SessionStart", session, cwd);
    v["source"] = json!("startup");
    v
}

pub fn pre_edit(session: &str, cwd: &Path, file: &str) -> Value {
    let mut v = base("PreToolUse", session, cwd);
    v["tool_name"] = json!("Edit");
    v["tool_input"] = json!({"file_path": cwd.join(file), "old_string": "a", "new_string": "b"});
    v["tool_use_id"] = json!("toolu_1");
    v
}

pub fn post(session: &str, cwd: &Path, tool: &str, input: Value) -> Value {
    let mut v = base("PostToolUse", session, cwd);
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_response"] = json!({"ok": true});
    v["tool_use_id"] = json!("toolu_2");
    v
}

pub fn post_edit(session: &str, cwd: &Path, file: &str) -> Value {
    post(session, cwd, "Edit", json!({"file_path": cwd.join(file), "old_string": "a", "new_string": "b"}))
}

pub fn post_read(session: &str, cwd: &Path, file: &str) -> Value {
    post(session, cwd, "Read", json!({"file_path": cwd.join(file)}))
}

pub fn post_bash(session: &str, cwd: &Path) -> Value {
    post(session, cwd, "Bash", json!({"command": "ls"}))
}

/// `hookSpecificOutput.additionalContext`, or "".
pub fn ctx(v: &Value) -> String {
    v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

pub fn decision(v: &Value) -> Option<String> {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .map(str::to_string)
}

pub async fn client(d: &DaemonHandle) -> LocalClient {
    LocalClient::connect(&d.socket_path).await.unwrap()
}

pub async fn tool(d: &DaemonHandle, session: &str, name: &str, args: Value) -> Result<String, String> {
    let mut c = client(d).await;
    c.call("tool", json!({"session": session, "name": name, "args": args}))
        .await
        .map(|v| v["text"].as_str().unwrap_or("").to_string())
}

/// Retry `f` until it returns Some or `secs` pass.
pub async fn eventually<T, F, Fut>(secs: u64, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let t = Instant::now();
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(secs), "condition not met in {secs}s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
