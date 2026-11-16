#![allow(dead_code)]
//! Test harness: one hub and two daemons in-process over localhost, static identity.

use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// Delegation policy file for daemon b only.
    pub policy_b: Option<PathBuf>,
    /// Hub team-log retention (see `hub::DEFAULT_LOG_MAX_ENTRIES`, `hub::DEFAULT_LOG_MAX_AGE_SECS`).
    pub log_max_entries: usize,
    pub log_max_age_secs: u64,
    /// File the hub reads its update target from.
    pub target_file: Option<PathBuf>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            lease_ttl: Duration::from_secs(60),
            protected: vec![],
            reconnect_min: Duration::from_millis(100),
            policy_b: None,
            log_max_entries: hub::DEFAULT_LOG_MAX_ENTRIES,
            log_max_age_secs: hub::DEFAULT_LOG_MAX_AGE_SECS,
            target_file: None,
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
    start_hub_with(dir, &Opts::default()).await
}

pub async fn start_hub_with(dir: &Path, opts: &Opts) -> HubHandle {
    hub::start(HubConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        db: dir.join("hub.sqlite"),
        identity: IdentityConfig::Static,
        hostnames: vec![],
        allow_users: vec![],
        tls: None,
        log_max_entries: opts.log_max_entries,
        log_max_age_secs: opts.log_max_age_secs,
        target_file: opts.target_file.clone(),
    })
    .await
    .unwrap()
}

/// A repository whose origin differs from `make_repo`'s, so its id differs.
pub fn make_other_repo(dir: &Path) -> PathBuf {
    let r = make_repo(dir);
    std::fs::write(
        r.join(".git/config"),
        "[remote \"origin\"]\n\turl = git@example.com:team/other.git\n",
    )
    .unwrap();
    r
}

/// Another daemon on the same hub (socket and hook port are its own).
pub async fn add_daemon(
    n: &Net,
    who: &str,
    policy: Option<PathBuf>,
    opts: &Opts,
) -> (DaemonHandle, PathBuf) {
    let mut c = daemon_config(&n.dir, format!("ws://{}/ws", n.hub.addr), who, opts);
    c.delegation_policy = policy;
    let d = daemon::start(c).await.unwrap();
    wait_connected(&d).await;
    let repo = make_repo(&n.dir.join(format!("{}/proj", &who[..1])));
    (d, repo)
}

/// `GET /api/state` as a page viewer, parsed.
pub async fn api_state(hub: &HubHandle) -> Value {
    let id = ("x-wormhole-static-identity", "viewer@viewer-machine");
    let (s, _, body) = http(hub.addr, "GET", "/api/state", &[id], "").await;
    assert_eq!(s, 200, "{body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("state not json ({e}): {body}"))
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
    let hub = start_hub_with(&dir, &opts).await;
    let url = format!("ws://{}/ws", hub.addr);
    let a = daemon::start(daemon_config(&dir, url.clone(), "alice@machine-a", &opts))
        .await
        .unwrap();
    let mut cb = daemon_config(&dir, url, "bob@machine-b", &opts);
    cb.delegation_policy = opts.policy_b.clone();
    let b = daemon::start(cb).await.unwrap();
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
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "daemon never connected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A TCP proxy to `upstream`. While the flag is set it holds what upstream sends without
/// closing anything, so the hub looks alive but stops answering.
pub async fn stall_proxy(upstream: SocketAddr) -> (SocketAddr, std::sync::Arc<AtomicBool>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let stall = std::sync::Arc::new(AtomicBool::new(false));
    let flag = stall.clone();
    tokio::spawn(async move {
        while let Ok((down, _)) = l.accept().await {
            let up = TcpStream::connect(upstream).await.unwrap();
            let (mut dr, mut dw) = down.into_split();
            let (mut ur, mut uw) = up.into_split();
            tokio::spawn(async move {
                // The hub checks the Host header, so the upgrade request names the hub.
                let mut head = vec![0u8; 16 * 1024];
                let n = dr.read(&mut head).await?;
                let head = String::from_utf8_lossy(&head[..n]).replacen(
                    &addr.to_string(),
                    &upstream.to_string(),
                    1,
                );
                uw.write_all(head.as_bytes()).await?;
                tokio::io::copy(&mut dr, &mut uw).await
            });
            let flag = flag.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = ur.read(&mut buf).await {
                    while flag.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    if n == 0 || dw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, stall)
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
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
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
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
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
    post(
        session,
        cwd,
        "Edit",
        json!({"file_path": cwd.join(file), "old_string": "a", "new_string": "b"}),
    )
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

pub async fn tool(
    d: &DaemonHandle,
    session: &str,
    name: &str,
    args: Value,
) -> Result<String, String> {
    let mut c = client(d).await;
    c.call(
        "tool",
        json!({"session": session, "name": name, "args": args}),
    )
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
        assert!(
            t.elapsed() < Duration::from_secs(secs),
            "condition not met in {secs}s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A test CA and leaves signed by it (tests only; the daemon is given the CA as an extra root).
pub struct Ca {
    pub params: rcgen::CertificateParams,
    pub cert: rcgen::Certificate,
    pub key: rcgen::KeyPair,
}

pub fn ca() -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "wormhole test CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { params, cert, key }
}

pub fn write_ca(ca: &Ca, path: &Path) -> PathBuf {
    std::fs::write(path, ca.cert.pem()).unwrap();
    path.to_path_buf()
}

pub fn leaf(ca: &Ca, names: &[&str], expired: bool, dir: &Path) -> wormhole::tls::TlsFiles {
    let mut p =
        rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    if expired {
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(2021, 1, 1);
    }
    let key = rcgen::KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::new(ca.params.clone(), &ca.key);
    let cert = p.signed_by(&key, &issuer).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let files = wormhole::tls::TlsFiles {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    };
    std::fs::write(&files.cert, cert.pem()).unwrap();
    std::fs::write(&files.key, key.serialize_pem()).unwrap();
    files
}

/// The repository id the daemons report for `make_repo` checkouts.
pub fn proj_id() -> String {
    wormhole::repo::find(&make_repo(&tmpdir().join("id-proj")))
        .unwrap()
        .id
}

/// The repository id of `make_other_repo` checkouts.
pub fn other_id() -> String {
    wormhole::repo::find(&make_other_repo(&tmpdir().join("id-other")))
        .unwrap()
        .id
}

type RawWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A bare WebSocket peer speaking the wire protocol by hand, for what a real daemon would never
/// do: an old daemon that advertises no capability, an oversized query, a malformed frame.
pub struct Raw {
    tx: futures_util::stream::SplitSink<RawWs, tokio_tungstenite::tungstenite::Message>,
    rx: futures_util::stream::SplitStream<RawWs>,
    id: u64,
    /// The Welcome frame.
    pub welcome: Value,
    /// Every non-response frame seen so far.
    pub frames: Vec<Value>,
}

impl Raw {
    /// Connect as `who` (`user@machine`). `caps` goes in `Resume`; empty omits the field, as a
    /// daemon from before capabilities did.
    pub async fn connect(addr: SocketAddr, who: &str, caps: &[&str]) -> Raw {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
        let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
        req.headers_mut()
            .insert(wormhole::proto::STATIC_ID_HEADER, who.parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mut tx, mut rx) = ws.split();
        let resume = if caps.is_empty() {
            json!({"op": "resume", "from": null})
        } else {
            json!({"op": "resume", "from": null, "caps": caps})
        };
        tx.send(Message::Text(resume.to_string().into()))
            .await
            .unwrap();
        let mut frames = Vec::new();
        let welcome = loop {
            let m = tokio::time::timeout(Duration::from_secs(5), rx.next())
                .await
                .expect("no welcome")
                .expect("closed before welcome")
                .unwrap();
            if let Message::Text(t) = m {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["op"] == "welcome" {
                    break v;
                }
                frames.push(v);
            }
        };
        Raw {
            tx,
            rx,
            id: 0,
            welcome,
            frames,
        }
    }

    /// Send one request and wait for its response: `Ok(data)` or `Err(error)`.
    pub async fn req(&mut self, req: Value) -> Result<Value, String> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        self.id += 1;
        let id = self.id;
        self.tx
            .send(Message::Text(
                json!({"op": "req", "id": id, "req": req}).to_string().into(),
            ))
            .await
            .unwrap();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), self.rx.next())
                .await
                .expect("no response")
                .expect("connection closed")
                .unwrap();
            let Message::Text(t) = m else { continue };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["op"] == "resp" && v["id"] == id {
                return if v["ok"] == true {
                    Ok(v["data"].clone())
                } else {
                    Err(v["error"].as_str().unwrap_or("").to_string())
                };
            }
            self.frames.push(v);
        }
    }

    pub async fn hello(&mut self, session: &str, repo: &str) {
        self.req(json!({"type": "hello", "session": session, "repo": repo, "branch": "main",
                        "task": ""}))
            .await
            .unwrap();
    }

    /// Send a message to everyone; returns its seq.
    pub async fn send_all(&mut self, session: &str, body: &str) -> u64 {
        self.req(json!({"type": "send", "session": session, "to": {"kind": "broadcast"},
                        "body": body, "reply_to": null}))
            .await
            .unwrap()["seq"]
            .as_u64()
            .unwrap()
    }

    /// A `log` request for `session` (hello is the caller's business).
    pub async fn log(&mut self, session: &str, query: Value) -> Result<Value, String> {
        self.req(json!({"type": "log", "session": session, "query": query}))
            .await
    }

    /// Read frames for `ms` milliseconds into `frames`.
    pub async fn drain(&mut self, ms: u64) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let end = Instant::now() + Duration::from_millis(ms);
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(left, self.rx.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    self.frames.push(serde_json::from_str(&t).unwrap_or_default())
                }
                Ok(Some(Ok(_))) => {}
                _ => break,
            }
        }
    }
}

/// The value of `name="..."` in one tag's attribute text.
pub fn attr_of(tag: &str, name: &str) -> Option<String> {
    let pat = format!(" {name}=\"");
    let i = tag.find(&pat)? + pat.len();
    let j = tag[i..].find('"')?;
    Some(tag[i..i + j].to_string())
}

/// Opening tags `<tag ...>` in `text`, each with the text up to its closing tag.
pub fn tag_blocks(text: &str, tag: &str) -> Vec<(String, String)> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i..];
        let Some(gt) = after.find(">\n") else { break };
        let head = after[..gt].to_string();
        let body_start = gt + 2;
        let end = after[body_start..]
            .find(&close)
            .map_or(after.len(), |e| body_start + e);
        out.push((head, after[body_start..end].to_string()));
        rest = &after[end.min(after.len())..];
        if rest.starts_with(&close) {
            rest = &rest[close.len()..];
        }
    }
    out
}

pub const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
pub const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
pub const SC: &str = "cccccccc-0000-4000-8000-000000000003";
pub const NOTICE: &str = "[wormhole delegation] request";

/// Next PostToolUse context for `session` that satisfies `pred`.
pub async fn wait_ctx(
    d: &DaemonHandle,
    session: &str,
    cwd: &Path,
    pred: impl Fn(&str) -> bool,
) -> String {
    let t = Instant::now();
    loop {
        let c = ctx(&hook(d, post_bash(session, cwd)).await);
        if pred(&c) {
            return c;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "no matching context; last: {c}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Everything `session` is told over `ms` milliseconds.
pub async fn gather_ctx(d: &DaemonHandle, session: &str, cwd: &Path, ms: u64) -> String {
    let t = Instant::now();
    let mut all = String::new();
    while t.elapsed() < Duration::from_millis(ms) {
        all.push_str(&ctx(&hook(d, post_bash(session, cwd)).await));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    all
}

/// A PreToolUse with an explicit `tool_use_id`.
pub fn pre_tool(session: &str, cwd: &Path, tool: &str, input: Value, id: &str) -> Value {
    let mut v = base("PreToolUse", session, cwd);
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_use_id"] = json!(id);
    v
}

/// A PostToolUse with an explicit `tool_use_id`.
pub fn post_tool(session: &str, cwd: &Path, tool: &str, input: Value, id: &str) -> Value {
    let mut v = base("PostToolUse", session, cwd);
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_response"] = json!({"ok": true});
    v["tool_use_id"] = json!(id);
    v
}

/// A delegation policy file granting `alice@machine-a` `level` on the shared test repository
/// for any task id and the kinds the tests use.
pub fn grant_policy(level: &str) -> PathBuf {
    let p = tmpdir().join("policy.json");
    std::fs::write(
        &p,
        json!({"grants": [{
            "from": ["alice@machine-a"], "repos": [proj_id()], "task_ids": ["*"],
            "level": level, "paths": ["src/**"],
            "kinds": ["tests", "fix", "any", "review", "task"],
        }], "safe_programs": []})
        .to_string(),
    )
    .unwrap();
    p
}

/// The first integer after `marker` in `s` (`sent (seq 5)` gives 5).
pub fn num_after(s: &str, marker: &str) -> u64 {
    let i = s.find(marker).unwrap_or_else(|| panic!("no {marker} in {s}")) + marker.len();
    s[i..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after {marker} in {s}"))
}

/// Send a message through a daemon's `send` tool; returns its seq.
pub async fn send(d: &DaemonHandle, from: &str, to: &str, body: &str) -> u64 {
    let r = tool(d, from, "send", json!({"to": to, "body": body}))
        .await
        .unwrap();
    num_after(&r, "seq")
}

/// The `delegate` tool, `extra` keys overriding the defaults.
pub async fn delegate_tool(
    d: &DaemonHandle,
    from: &str,
    to: &str,
    task: &str,
    kind: &str,
    text: &str,
    extra: Value,
) -> Result<String, String> {
    let mut a = json!({"to_session": to, "to": to, "task_id": task, "kind": kind, "text": text});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    tool(d, from, "delegate", a).await
}

/// The request id in a delegation notice.
pub fn request_id(notice: &str) -> u64 {
    num_after(notice, NOTICE)
}

/// Everything `session` is told until every marker has appeared (across several hooks).
pub async fn wait_all(d: &DaemonHandle, session: &str, cwd: &Path, markers: &[&str]) -> String {
    let t = Instant::now();
    let mut all = String::new();
    loop {
        all.push_str(&ctx(&hook(d, post_bash(session, cwd)).await));
        if markers.iter().all(|m| all.contains(m)) {
            return all;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "missing markers {markers:?}; got: {all}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
