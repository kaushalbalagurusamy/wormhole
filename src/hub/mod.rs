//! The hub: one process holding the ordered event log, presence, leases and inboxes.

pub mod identity;
mod page;
pub mod store;

use crate::proto::*;
use crate::text;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use identity::{Identifier, IdentityConfig, Peer};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::{Acquired, Holder, LeaseError, Store};
use tokio::sync::{broadcast, mpsc};

#[derive(Clone, Debug)]
pub struct HubConfig {
    pub listen: SocketAddr,
    pub db: PathBuf,
    pub identity: IdentityConfig,
    /// DNS names clients may use for the hub (e.g. its tailnet name). Requests whose Host
    /// is not the listen address or one of these are refused, to stop DNS rebinding.
    pub hostnames: Vec<String>,
    /// Users (login names, or `tag:...` for tagged nodes) the hub accepts. Empty accepts any
    /// peer the identity source can identify.
    pub allow_users: Vec<String>,
    /// Serve wss:// and https:// with this certificate. Without it, the hub serves plaintext
    /// only on loopback or a Tailscale address.
    pub tls: Option<crate::tls::TlsFiles>,
}

/// A session with no heartbeat for this long is reported gone.
const PRESENCE_TIMEOUT_MS: u64 = 120_000;
/// Lease length after a transfer; the recipient's daemon renews it on its next edit.
const TRANSFER_TTL_MS: u64 = 600_000;
const REPLAY_BATCH: usize = 500;
const ACTIVITY_KINDS: &[&str] = &["edit", "command", "commit", "push", "pr"];

struct Sess {
    info: SessionInfo,
    owner: Peer,
}

pub(crate) struct Hub {
    store: Mutex<Store>,
    tx: broadcast::Sender<Event>,
    sessions: Mutex<HashMap<String, Sess>>,
    ident: Identifier,
    kick: broadcast::Sender<String>,
    /// Bound address and accepted host names, for the Host check.
    endpoint: std::sync::OnceLock<(SocketAddr, Vec<String>)>,
    /// The server certificate when TLS is on; its names are also accepted as Host.
    tls: Option<Arc<crate::tls::ServerTls>>,
    /// Open connections per `user@machine` whose daemon advertised the delegation capability.
    delegating: Mutex<HashMap<String, usize>>,
}

/// Counts a connection as delegation-capable for as long as it lives.
struct CapGuard {
    hub: Arc<Hub>,
    key: Option<String>,
}

impl Drop for CapGuard {
    fn drop(&mut self) {
        if let Some(k) = &self.key {
            let mut m = self.hub.delegating.lock().unwrap();
            if let Some(n) = m.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
    }
}

/// Frames queued per connection before a slow consumer is dropped.
const OUT_QUEUE: usize = 256;
/// Longest a replay waits for a slow consumer before dropping it.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

pub struct HubHandle {
    pub addr: SocketAddr,
    hub: Arc<Hub>,
    server: tokio::task::JoinHandle<()>,
    sweeper: tokio::task::JoinHandle<()>,
    /// TLS accept loop and SIGHUP reload task, when TLS is on.
    tls_tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// The peer address of a connection, for both plain and TLS listeners.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RemoteAddr(pub SocketAddr);

impl
    axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::TcpListener>>
    for RemoteAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        RemoteAddr(*stream.remote_addr())
    }
}

impl
    axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, crate::tls::TlsListener>>
    for RemoteAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, crate::tls::TlsListener>) -> Self {
        RemoteAddr(*stream.remote_addr())
    }
}

impl HubHandle {
    /// Close every connection from `machine` (used by tests to simulate a network drop).
    pub fn kick(&self, machine: &str) {
        let _ = self.hub.kick.send(machine.to_string());
    }

    /// Re-read the TLS certificate and key (also done on SIGHUP).
    pub fn reload_tls(&self) -> Result<(), String> {
        match &self.hub.tls {
            Some(t) => t.reload(),
            None => Err("TLS is not enabled".into()),
        }
    }

    /// Run the lease and presence sweep as if the clock read `t` (milliseconds since the
    /// epoch). For tests that need sessions to time out.
    pub fn sweep_at(&self, t: u64) {
        self.hub.sweep_once(t);
    }

    pub async fn shutdown(self) {
        let _ = self.hub.kick.send("*".into());
        self.server.abort();
        self.sweeper.abort();
        for t in &self.tls_tasks {
            t.abort();
        }
        let _ = self.server.await;
    }
}

pub async fn start(cfg: HubConfig) -> Result<HubHandle, String> {
    if matches!(cfg.identity, IdentityConfig::Static) && !cfg.listen.ip().is_loopback() {
        return Err("static identity is only allowed when the hub listens on loopback".into());
    }
    // Off loopback and the tailnet nothing encrypts the path, so plaintext is refused there.
    if cfg.tls.is_none() && !crate::tls::plaintext_ok_ip(cfg.listen.ip()) {
        return Err(format!(
            "refusing to serve plaintext on {}: listen on loopback or a Tailscale address, or pass --tls-cert and --tls-key",
            cfg.listen.ip()
        ));
    }
    let tls = match &cfg.tls {
        Some(files) => Some(Arc::new(crate::tls::ServerTls::load(files.clone())?)),
        None => None,
    };
    let store = Store::open(&cfg.db)?;
    let mut hub = Hub::new(store, cfg.identity.clone());
    hub.ident = Identifier::with_allowlist(cfg.identity.clone(), cfg.allow_users.clone());
    hub.tls = tls.clone();
    let hub = Arc::new(hub);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let _ = hub.endpoint.set((addr, cfg.hostnames.clone()));
    let app = axum::Router::new()
        .route("/ws", get(ws))
        .merge(page::routes())
        .with_state(hub.clone());
    let mut tls_tasks = Vec::new();
    let server = match tls {
        None => tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<RemoteAddr>(),
            )
            .await;
        }),
        Some(t) => {
            let (tls_listener, accept) = crate::tls::TlsListener::new(listener, t.server_config()?);
            tls_tasks.push(accept);
            tls_tasks.push(tokio::spawn(reload_on_sighup(t)));
            tokio::spawn(async move {
                let _ = axum::serve(
                    tls_listener,
                    app.into_make_service_with_connect_info::<RemoteAddr>(),
                )
                .await;
            })
        }
    };
    let sweeper = tokio::spawn(sweep(hub.clone()));
    Ok(HubHandle {
        addr,
        hub,
        server,
        sweeper,
        tls_tasks,
    })
}

/// Tailscale certificates last 90 days: `tailscale cert` renews the files, SIGHUP reloads them.
async fn reload_on_sighup(tls: Arc<crate::tls::ServerTls>) {
    let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else {
        return;
    };
    while hup.recv().await.is_some() {
        match tls.reload() {
            Ok(()) => eprintln!("wormhole hub: reloaded TLS certificate"),
            Err(e) => {
                eprintln!("wormhole hub: TLS reload failed, keeping the current certificate: {e}")
            }
        }
    }
}

/// Identify an HTTP or WebSocket peer. Requests from browsers (with an `Origin`) are
/// refused on the WebSocket; the page routes allow same-origin reads.
pub(crate) async fn who(
    hub: &Hub,
    addr: SocketAddr,
    headers: &HeaderMap,
) -> Result<Peer, StatusCode> {
    if let Some((listen, names)) = hub.endpoint.get() {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        // With TLS on, the certificate's names (as Host, with or without the port) also count.
        let cert_name = hub.tls.as_ref().is_some_and(|t| {
            let (name, port) = match host.rsplit_once(':') {
                Some((n, p)) if !n.ends_with(']') || host.starts_with('[') => {
                    (n, p.parse::<u16>().ok())
                }
                _ => (host, None),
            };
            port.is_none_or(|p| p == listen.port()) && t.host_matches(name)
        });
        if !host_allowed(host, *listen, names) && !cert_name {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let claim = headers.get(STATIC_ID_HEADER).and_then(|v| v.to_str().ok());
    hub.ident
        .identify(addr, claim)
        .await
        .ok_or(StatusCode::FORBIDDEN)
}

async fn ws(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(RemoteAddr(addr)): ConnectInfo<RemoteAddr>,
    headers: HeaderMap,
    up: WebSocketUpgrade,
) -> Response {
    if headers.contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let peer = match who(&hub, addr, &headers).await {
        Ok(p) => p,
        Err(s) => return s.into_response(),
    };
    up.max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |sock| connection(hub, peer, sock))
}

/// Queue a frame without waiting. False if the queue is full (slow consumer) or closed.
fn try_down(out: &mpsc::Sender<Message>, d: &Down) -> bool {
    match serde_json::to_string(d) {
        Ok(s) => out.try_send(Message::Text(s.into())).is_ok(),
        Err(_) => true,
    }
}

async fn connection(hub: Arc<Hub>, peer: Peer, sock: WebSocket) {
    let (mut sink, mut stream) = sock.split();
    let (out, mut out_rx) = mpsc::channel::<Message>(OUT_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });
    let mut kick = hub.kick.subscribe();

    // First frame must be Resume.
    let (from, caps) = match tokio::time::timeout(Duration::from_secs(10), stream.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => match serde_json::from_str::<Up>(&t) {
            Ok(Up::Resume { from, caps }) => (from, caps),
            _ => {
                writer.abort();
                return;
            }
        },
        _ => {
            writer.abort();
            return;
        }
    };
    let _caps = CapGuard {
        hub: hub.clone(),
        key: caps.iter().any(|c| c == CAP_DELEGATION).then(|| {
            *hub.delegating
                .lock()
                .unwrap()
                .entry(peer.key())
                .or_default() += 1;
            peer.key()
        }),
    };
    // Subscribe before reading the log so nothing falls between replay and live.
    let mut rx = hub.tx.subscribe();
    let (head, cursor) = {
        let st = hub.store.lock().unwrap();
        (
            st.head().unwrap_or(0),
            st.cursor(&peer.key()).ok().flatten(),
        )
    };
    try_down(
        &out,
        &Down::Welcome {
            user: peer.user.clone(),
            machine: peer.machine.clone(),
            head,
            caps: vec![CAP_DELEGATION.to_string()],
        },
    );
    let mut last = resume_point(from, cursor, head);
    if !hub.replay(&peer, &out, &mut last).await {
        writer.abort();
        return;
    }

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => {
                    if e.seq > last {
                        // A consumer that cannot keep up is dropped; it resumes from its cursor.
                        if hub.visible(&e, &peer) && !try_down(&out, &Down::Event { event: e.clone() }) {
                            break;
                        }
                        last = e.seq;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if !hub.replay(&peer, &out, &mut last).await { break; }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            frame = stream.next() => match frame {
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<Up>(&t) {
                    Ok(Up::Ack { seq }) => {
                        let _ = hub.store.lock().unwrap().set_cursor(&peer.key(), seq.min(last));
                    }
                    Ok(Up::Req { id, req }) => {
                        let d = match hub.handle(&peer, req) {
                            Ok(data) => Down::Resp { id, ok: true, data, error: None },
                            Err(e) => Down::Resp { id, ok: false, data: Value::Null, error: Some(e) },
                        };
                        if !try_down(&out, &d) { break; }
                    }
                    Ok(Up::Resume { .. }) | Err(_) => break,
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            k = kick.recv() => {
                if let Ok(m) = k {
                    if m == "*" || m == peer.machine { break; }
                }
            }
        }
    }
    writer.abort();
}

/// Furthest back a resuming connection is replayed.
const MAX_REPLAY: u64 = 100_000;

/// Where to resume a connection: the daemon's last sequence, else its stored cursor, else
/// the head; never past the head and never more than `MAX_REPLAY` behind it.
fn resume_point(from: Option<u64>, cursor: Option<u64>, head: u64) -> u64 {
    from.or(cursor)
        .unwrap_or(head)
        .min(head)
        .max(head.saturating_sub(MAX_REPLAY))
}

/// Is `host` (a Host header) one of the names this hub answers to?
pub(crate) fn host_allowed(host: &str, listen: SocketAddr, names: &[String]) -> bool {
    let port = listen.port();
    if host == listen.to_string() {
        return true;
    }
    let mut ok_names: Vec<&str> = names.iter().map(String::as_str).collect();
    if listen.ip().is_loopback() {
        ok_names.push("localhost");
    }
    ok_names.iter().any(|n| {
        !n.is_empty()
            && (host.eq_ignore_ascii_case(n) || host.eq_ignore_ascii_case(&format!("{n}:{port}")))
    })
}

fn now() -> u64 {
    now_ms()
}

fn field(name: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_FIELD || s.chars().any(text::unsafe_in_name) {
        return Err(format!("invalid {name}"));
    }
    Ok(())
}

fn lease_err(e: LeaseError) -> String {
    match e {
        LeaseError::NotHeld => "not_held: no live lease on that scope".into(),
        LeaseError::StaleToken => "stale_token: that token is no longer the current one".into(),
        LeaseError::NotHolder => "not_holder: another session holds that lease".into(),
        LeaseError::GrantorHoldsBroader(l) => format!(
            "grantor_holds_broader: you also hold {}, which overlaps this scope; narrow or release it first",
            l.scope
        ),
        LeaseError::Conflict(l) => format!(
            "conflict: session {} holds overlapping scope {}",
            l.session, l.scope
        ),
    }
}

fn db<T>(r: rusqlite::Result<T>) -> Result<T, String> {
    r.map_err(|e| {
        eprintln!("wormhole hub: database error: {e}");
        "internal error".to_string()
    })
}

impl Hub {
    fn new(store: Store, identity: IdentityConfig) -> Hub {
        let (tx, _) = broadcast::channel(1024);
        let (kick, _) = broadcast::channel(16);
        Hub {
            store: Mutex::new(store),
            tx,
            sessions: Mutex::new(HashMap::new()),
            ident: Identifier::new(identity),
            kick,
            endpoint: std::sync::OnceLock::new(),
            tls: None,
            delegating: Mutex::new(HashMap::new()),
        }
    }

    /// Expire leases and presence as of `t`.
    fn sweep_once(&self, t: u64) {
        let expired = self.store.lock().unwrap().expire(t).unwrap_or_default();
        for l in expired {
            let _ = self.emit_lease("lease.expired", &l, json!({}));
        }
        let gone: Vec<(String, Peer)> = {
            let mut ss = self.sessions.lock().unwrap();
            let ids: Vec<String> = ss
                .iter()
                .filter(|(_, s)| t.saturating_sub(s.info.last_seen) > PRESENCE_TIMEOUT_MS)
                .map(|(k, _)| k.clone())
                .collect();
            ids.into_iter()
                .filter_map(|k| ss.remove(&k).map(|s| (k, s.owner)))
                .collect()
        };
        for (session, owner) in gone {
            let released = self
                .store
                .lock()
                .unwrap()
                .release_session(&session)
                .unwrap_or_default();
            for l in released {
                let _ =
                    self.emit_lease("lease.released", &l, json!({"reason": "session timed out"}));
            }
            let _ = self.emit("bye", &owner, &session, json!({"reason": "timeout"}));
        }
    }

    /// Send everything after `last` that `peer` may see. False if the database failed.
    /// Waits for queue space, but drops a consumer that stalls past `SEND_TIMEOUT`.
    async fn replay(&self, peer: &Peer, out: &mpsc::Sender<Message>, last: &mut u64) -> bool {
        loop {
            let batch = match self.store.lock().unwrap().events_after(*last, REPLAY_BATCH) {
                Ok(b) => b,
                Err(_) => return false,
            };
            if batch.is_empty() {
                return true;
            }
            for e in batch {
                if self.visible(&e, peer) {
                    let Ok(s) = serde_json::to_string(&Down::Event { event: e.clone() }) else {
                        continue;
                    };
                    if out
                        .send_timeout(Message::Text(s.into()), SEND_TIMEOUT)
                        .await
                        .is_err()
                    {
                        return false;
                    }
                }
                *last = e.seq;
            }
        }
    }

    /// Messages go only to the machines they are addressed to; everything else to all.
    fn visible(&self, e: &Event, peer: &Peer) -> bool {
        if e.kind != "msg" {
            return true;
        }
        match serde_json::from_value::<Target>(e.data["to"].clone()) {
            Ok(Target::Broadcast) => true,
            Ok(Target::User(u)) => u == peer.user,
            // The recipient is fixed when the message is sent.
            Ok(Target::Session(_)) => {
                e.data["to_user"].as_str() == Some(peer.user.as_str())
                    && e.data["to_machine"].as_str() == Some(peer.machine.as_str())
            }
            Err(_) => false,
        }
    }

    /// Append to the log and fan out, in sequence order.
    fn emit(&self, kind: &str, peer: &Peer, session: &str, data: Value) -> Result<Event, String> {
        let mut st = self.store.lock().unwrap();
        let e = db(st.append(now(), kind, &peer.user, &peer.machine, session, data))?;
        let _ = self.tx.send(e.clone());
        Ok(e)
    }

    fn emit_lease(&self, kind: &str, l: &LeaseInfo, extra: Value) -> Result<Event, String> {
        let peer = Peer {
            user: l.user.clone(),
            machine: l.machine.clone(),
        };
        let mut data =
            json!({"repo": l.repo, "scope": l.scope, "token": l.token, "expires": l.expires});
        if let (Some(d), Value::Object(x)) = (data.as_object_mut(), extra) {
            d.extend(x);
        }
        self.emit(kind, &peer, &l.session, data)
    }

    fn own(&self, peer: &Peer, session: &str) -> Result<(), String> {
        match self.sessions.lock().unwrap().get(session) {
            Some(s) if &s.owner == peer => Ok(()),
            Some(_) => Err("session belongs to another machine".into()),
            None => Err("unknown session; send hello first".into()),
        }
    }

    fn owner_of(&self, session: &str) -> Option<Peer> {
        self.sessions
            .lock()
            .unwrap()
            .get(session)
            .map(|s| s.owner.clone())
    }

    fn handle(&self, peer: &Peer, req: Request) -> Result<Value, String> {
        let t = now();
        match req {
            Request::Hello {
                session,
                repo,
                branch,
                task,
            } => {
                field("session", &session)?;
                let repo = text::plain(&repo, MAX_FIELD);
                let branch = text::plain(&branch, MAX_FIELD);
                let task = text::plain(&task, MAX_TASK);
                // A session id belongs to the first peer that registers it, permanently.
                if !db(self.store.lock().unwrap().bind_session(
                    &session,
                    &peer.user,
                    &peer.machine,
                ))? {
                    return Err("session belongs to another machine".into());
                }
                let changed = {
                    let mut ss = self.sessions.lock().unwrap();
                    match ss.get_mut(&session) {
                        Some(s) if &s.owner != peer => {
                            return Err("session belongs to another machine".into())
                        }
                        Some(s) => {
                            s.info.last_seen = t;
                            let changed = s.info.repo != repo
                                || s.info.branch != branch
                                || s.info.task != task;
                            s.info.repo = repo.clone();
                            s.info.branch = branch.clone();
                            s.info.task = task.clone();
                            changed
                        }
                        None => {
                            ss.insert(
                                session.clone(),
                                Sess {
                                    info: SessionInfo {
                                        session: session.clone(),
                                        user: peer.user.clone(),
                                        machine: peer.machine.clone(),
                                        repo: repo.clone(),
                                        branch: branch.clone(),
                                        task: task.clone(),
                                        since: t,
                                        last_seen: t,
                                    },
                                    owner: peer.clone(),
                                },
                            );
                            true
                        }
                    }
                };
                if changed {
                    self.emit(
                        "hello",
                        peer,
                        &session,
                        json!({"repo": repo, "branch": branch, "task": task}),
                    )?;
                }
                Ok(json!({}))
            }
            Request::Heartbeat { session } => {
                self.own(peer, &session)?;
                if let Some(s) = self.sessions.lock().unwrap().get_mut(&session) {
                    s.info.last_seen = t;
                }
                Ok(json!({}))
            }
            Request::Bye { session } => {
                self.own(peer, &session)?;
                self.sessions.lock().unwrap().remove(&session);
                let gone = db(self.store.lock().unwrap().release_session(&session))?;
                for l in gone {
                    self.emit_lease("lease.released", &l, json!({}))?;
                }
                self.emit("bye", peer, &session, json!({"reason": "ended"}))?;
                Ok(json!({}))
            }
            Request::Activity {
                session,
                kind,
                repo,
                paths,
                summary,
            } => {
                self.own(peer, &session)?;
                if !ACTIVITY_KINDS.contains(&kind.as_str()) {
                    return Err("invalid activity kind".into());
                }
                field("repo", &repo)?;
                if paths.len() > MAX_PATHS {
                    return Err("too many paths".into());
                }
                for p in &paths {
                    field("path", p)?;
                }
                let summary = text::plain(&summary, MAX_SUMMARY);
                let e = self.emit(
                    "activity",
                    peer,
                    &session,
                    json!({"kind": kind, "repo": repo, "paths": paths, "summary": summary}),
                )?;
                Ok(json!({"seq": e.seq}))
            }
            Request::Send {
                session,
                to,
                body,
                reply_to,
            } => {
                self.own(peer, &session)?;
                if body.len() > MAX_BODY {
                    return Err(format!("message body too large (max {MAX_BODY} bytes)"));
                }
                if body.trim().is_empty() {
                    return Err("empty message".into());
                }
                let mut data = json!({"to": to, "body": body, "reply_to": reply_to});
                match &to {
                    Target::Session(s) => {
                        let (u, m) = db(self.store.lock().unwrap().session_owner(s))?
                            .ok_or("no such session")?;
                        data["to_user"] = json!(u);
                        data["to_machine"] = json!(m);
                    }
                    Target::User(u) => field("user", u)?,
                    Target::Broadcast => {}
                }
                let e = self.emit("msg", peer, &session, data)?;
                Ok(json!({"seq": e.seq}))
            }
            Request::MsgRead { session, seq } => {
                self.own(peer, &session)?;
                self.emit("msg.read", peer, &session, json!({"seq": seq}))?;
                Ok(json!({}))
            }
            Request::LeaseAcquire {
                session,
                repo,
                scope,
                ttl_ms,
            } => {
                self.own(peer, &session)?;
                field("repo", &repo)?;
                field("scope", &scope)?;
                if !crate::glob::valid(&scope) {
                    return Err("scope has too many ** segments".into());
                }
                let who = Holder {
                    session: &session,
                    user: &peer.user,
                    machine: &peer.machine,
                };
                let r = db(self
                    .store
                    .lock()
                    .unwrap()
                    .acquire(t, &who, &repo, &scope, ttl_ms))?;
                let res = match r {
                    Acquired::Granted { lease, fresh } => {
                        if fresh {
                            self.emit_lease("lease.granted", &lease, json!({"via": "acquire"}))?;
                        }
                        LeaseResult::Granted { lease }
                    }
                    Acquired::Held(lease) => LeaseResult::Held { lease },
                };
                Ok(serde_json::to_value(res).unwrap_or(Value::Null))
            }
            Request::LeaseRenew {
                session,
                repo,
                scope,
                token,
                ttl_ms,
            } => {
                self.own(peer, &session)?;
                let r = db(self
                    .store
                    .lock()
                    .unwrap()
                    .renew(t, &session, &repo, &scope, token, ttl_ms))?;
                let lease = r.map_err(lease_err)?;
                Ok(serde_json::to_value(LeaseResult::Granted { lease }).unwrap_or(Value::Null))
            }
            Request::LeaseRelease {
                session,
                repo,
                scope,
                token,
            } => {
                self.own(peer, &session)?;
                let r = db(self
                    .store
                    .lock()
                    .unwrap()
                    .release(t, &session, &repo, &scope, token))?;
                let l = r.map_err(lease_err)?;
                self.emit_lease("lease.released", &l, json!({}))?;
                Ok(json!({}))
            }
            Request::LeaseRequestTransfer {
                session,
                repo,
                scope,
                reason,
            } => {
                self.own(peer, &session)?;
                let l = db(self.store.lock().unwrap().lease(t, &repo, &scope))?
                    .ok_or("not_held: no live lease on that scope")?;
                if l.session == session {
                    return Err("you already hold that lease".into());
                }
                self.emit(
                    "lease.transfer_requested",
                    peer,
                    &session,
                    json!({"repo": repo, "scope": scope, "holder": l.session, "reason": text::plain(&reason, MAX_SUMMARY)}),
                )?;
                Ok(json!({}))
            }
            Request::LeaseGrant {
                session,
                repo,
                scope,
                to,
            } => {
                self.own(peer, &session)?;
                let owner = self.owner_of(&to).ok_or("no such session")?;
                let who = Holder {
                    session: &to,
                    user: &owner.user,
                    machine: &owner.machine,
                };
                let r = db(self.store.lock().unwrap().transfer(
                    t,
                    &session,
                    &repo,
                    &scope,
                    &who,
                    TRANSFER_TTL_MS,
                ))?;
                let (l, released) = r.map_err(lease_err)?;
                for x in &released {
                    self.emit_lease(
                        "lease.released",
                        x,
                        json!({"reason": "transferred with a wider scope"}),
                    )?;
                }
                self.emit_lease(
                    "lease.granted",
                    &l,
                    json!({"via": "transfer", "from": session}),
                )?;
                Ok(json!({}))
            }
            Request::LeaseDeny {
                session,
                repo,
                scope,
                to,
                reason,
            } => {
                self.own(peer, &session)?;
                if self.owner_of(&to).is_none() {
                    return Err("no such session".into());
                }
                let l = db(self.store.lock().unwrap().lease(t, &repo, &scope))?;
                if l.map(|l| l.session) != Some(session.clone()) {
                    return Err("not_holder: you do not hold that lease".into());
                }
                self.emit(
                    "lease.denied",
                    peer,
                    &session,
                    json!({"repo": repo, "scope": scope, "to": to, "reason": text::plain(&reason, MAX_SUMMARY)}),
                )?;
                Ok(json!({}))
            }
            Request::Snapshot => {
                let mut snap = self.snapshot()?;
                // Newest first, capped so the reply fits in one frame.
                snap.sessions.reverse();
                snap.sessions.truncate(MAX_SNAPSHOT_SESSIONS);
                snap.leases.reverse();
                snap.leases.truncate(MAX_SNAPSHOT_LEASES);
                Ok(serde_json::to_value(snap).unwrap_or(Value::Null))
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Result<Snapshot, String> {
        let mut sessions: Vec<SessionInfo> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.info.clone())
            .collect();
        sessions.sort_by_key(|s| s.since);
        let leases = db(self.store.lock().unwrap().leases(now()))?;
        Ok(Snapshot {
            sessions,
            leases,
            delegations: vec![],
        })
    }

    pub(crate) fn recent(&self, n: usize) -> Result<Vec<Event>, String> {
        db(self.store.lock().unwrap().recent(n))
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

async fn sweep(hub: Arc<Hub>) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        hub.sweep_once(now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> Hub {
        Hub::new(Store::open_memory().unwrap(), IdentityConfig::Static)
    }

    fn p(u: &str, m: &str) -> Peer {
        Peer {
            user: u.into(),
            machine: m.into(),
        }
    }

    fn hello(s: &str) -> Request {
        Request::Hello {
            session: s.into(),
            repo: "r".into(),
            branch: "main".into(),
            task: String::new(),
        }
    }

    fn last_event(h: &Hub) -> Event {
        h.recent(1).unwrap().pop().unwrap()
    }

    #[test]
    fn session_id_cannot_be_taken_over() {
        let h = hub();
        let (a, b) = (p("alice", "ma"), p("bob", "mb"));
        h.handle(&a, hello("s1")).unwrap();
        assert!(h.handle(&b, hello("s1")).is_err());
        h.handle(
            &a,
            Request::LeaseAcquire {
                session: "s1".into(),
                repo: "r".into(),
                scope: "f".into(),
                ttl_ms: 3_600_000,
            },
        )
        .unwrap();
        // Presence times out: the session's leases go with it, but the id stays bound.
        h.sweep_once(now() + PRESENCE_TIMEOUT_MS + 1000);
        assert!(h.snapshot().unwrap().leases.is_empty());
        assert!(h.snapshot().unwrap().sessions.is_empty());
        assert!(h.handle(&b, hello("s1")).is_err());
        // The owner can come back.
        h.handle(&a, hello("s1")).unwrap();
        // Ending a session does not free its id for others either.
        h.handle(
            &a,
            Request::Bye {
                session: "s1".into(),
            },
        )
        .unwrap();
        assert!(h.handle(&b, hello("s1")).is_err());
    }

    #[test]
    fn transfer_announces_released_sub_leases() {
        let h = hub();
        let (a, b) = (p("alice", "ma"), p("bob", "mb"));
        h.handle(&a, hello("s1")).unwrap();
        h.handle(&b, hello("s2")).unwrap();
        for scope in ["src/hub/*", "src/hub/a.rs"] {
            h.handle(
                &a,
                Request::LeaseAcquire {
                    session: "s1".into(),
                    repo: "r".into(),
                    scope: scope.into(),
                    ttl_ms: 60_000,
                },
            )
            .unwrap();
        }
        h.handle(
            &a,
            Request::LeaseGrant {
                session: "s1".into(),
                repo: "r".into(),
                scope: "src/hub/*".into(),
                to: "s2".into(),
            },
        )
        .unwrap();
        let events = h.recent(10).unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.kind == "lease.released" && e.data["scope"] == "src/hub/a.rs"),
            "{events:?}"
        );
    }

    #[test]
    fn message_visibility_is_fixed_at_send_time() {
        let h = hub();
        let (a, b, c) = (p("alice", "ma"), p("bob", "mb"), p("carol", "mc"));
        h.handle(&a, hello("s1")).unwrap();
        h.handle(&c, hello("s3")).unwrap();
        h.handle(
            &c,
            Request::Send {
                session: "s3".into(),
                to: Target::Session("s1".into()),
                body: "for alice".into(),
                reply_to: None,
            },
        )
        .unwrap();
        let e = last_event(&h);
        assert!(h.visible(&e, &a));
        assert!(!h.visible(&e, &b));
        h.sweep_once(now() + PRESENCE_TIMEOUT_MS + 1000);
        // After expiry the recipient can still replay it and nobody else can.
        assert!(h.visible(&e, &a));
        assert!(!h.visible(&e, &b));
    }

    #[test]
    fn resume_point_is_bounded() {
        assert_eq!(resume_point(Some(0), None, 250_000), 250_000 - MAX_REPLAY);
        assert_eq!(resume_point(None, Some(10), 20), 10);
        assert_eq!(resume_point(None, None, 20), 20);
        assert_eq!(resume_point(Some(30), None, 20), 20);
    }

    #[test]
    fn host_header_must_name_the_hub() {
        let listen: SocketAddr = "100.64.0.1:7420".parse().unwrap();
        let names = vec!["hub.example.ts.net".to_string()];
        assert!(host_allowed("100.64.0.1:7420", listen, &names));
        assert!(host_allowed("hub.example.ts.net:7420", listen, &names));
        assert!(host_allowed("hub.example.ts.net", listen, &names));
        assert!(!host_allowed("evil.example:7420", listen, &names));
        assert!(!host_allowed("100.64.0.1:7421", listen, &names));
        assert!(!host_allowed("", listen, &names));
        let lo: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert!(host_allowed("localhost:9000", lo, &[]));
        assert!(!host_allowed("localhost:9000", listen, &[]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_consumer_is_dropped_and_resumes_from_its_cursor() {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as M};
        let dir = std::env::temp_dir().join(format!("wh-slow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hh = start(HubConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            db: dir.join("hub.sqlite"),
            identity: IdentityConfig::Static,
            hostnames: vec![],
            allow_users: vec![],
            tls: None,
        })
        .await
        .unwrap();
        let url = format!("ws://{}/ws", hh.addr);
        let connect = |from: Option<u64>| {
            let url = url.clone();
            async move {
                let mut req = url.into_client_request().unwrap();
                req.headers_mut()
                    .insert(STATIC_ID_HEADER, "alice@ma".parse().unwrap());
                let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
                ws.send(M::text(
                    serde_json::to_string(&Up::Resume { from, caps: vec![] }).unwrap(),
                ))
                .await
                .unwrap();
                ws
            }
        };
        async fn read_seqs(
            ws: &mut tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            until: u64,
            seqs: &mut Vec<u64>,
        ) -> bool {
            loop {
                match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
                    Ok(Some(Ok(M::Text(t)))) => {
                        if let Ok(Down::Event { event }) = serde_json::from_str::<Down>(&t) {
                            seqs.push(event.seq);
                            if event.seq >= until {
                                return true;
                            }
                        }
                    }
                    Ok(Some(Ok(_))) => {}
                    _ => return false,
                }
            }
        }
        let head = hh.hub.store.lock().unwrap().head().unwrap();
        let mut ws = connect(Some(head)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The client stops reading while far more is produced than any buffer holds.
        let peer = p("alice", "ma");
        let pad = "x".repeat(8000);
        let total = 4000;
        for i in 0..total {
            hh.hub
                .emit("activity", &peer, "s", json!({"pad": pad, "i": i}))
                .unwrap();
        }
        let end = head + total;
        // Stay stalled past the hub's send timeout.
        tokio::time::sleep(SEND_TIMEOUT + Duration::from_secs(1)).await;
        let mut seqs = Vec::new();
        let finished = read_seqs(&mut ws, end, &mut seqs).await;
        assert!(!finished, "slow consumer was not dropped");
        let last = *seqs.last().unwrap_or(&head);
        // Reconnect from the last sequence seen: the rest arrives, without gaps.
        let mut ws = connect(Some(last)).await;
        assert!(read_seqs(&mut ws, end, &mut seqs).await);
        let want: Vec<u64> = (head + 1..=end).collect();
        assert_eq!(seqs, want);
        hh.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
