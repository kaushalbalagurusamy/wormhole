//! The daemon: one per machine. Keeps one WebSocket to the hub and serves local sessions
//! over a Unix socket and HTTP hooks on loopback.

mod hooks;
mod shrink;
pub use hooks::{STALE_DAEMON, STALE_HUB};
mod sock;
mod state;

use crate::proto::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use state::State;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, Message};

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// `ws://host:port/ws`
    pub hub_url: String,
    /// Loopback address for Claude Code HTTP hooks.
    pub http_listen: SocketAddr,
    /// Unix socket path; its directory is created with mode 0700 if missing.
    pub socket_path: PathBuf,
    /// Sent only when the hub runs with static identity.
    pub static_identity: Option<String>,
    /// Repo-relative globs where a conflicting edit is denied instead of warned.
    pub protected: Vec<String>,
    pub lease_ttl: Duration,
    /// Longest a hook waits on the hub before failing open.
    pub hub_deadline: Duration,
    /// First reconnect delay; doubles up to 10 s.
    pub reconnect_min: Duration,
    /// PEM CA certificates trusted for a wss:// hub in addition to the system roots, for a
    /// private CA or tests. Certificates are always verified.
    pub extra_roots: Vec<PathBuf>,
}

impl DaemonConfig {
    pub fn new(hub_url: String, socket_path: PathBuf) -> DaemonConfig {
        DaemonConfig {
            hub_url,
            http_listen: SocketAddr::from(([127, 0, 0, 1], 7421)),
            socket_path,
            static_identity: None,
            protected: Vec::new(),
            lease_ttl: Duration::from_secs(600),
            hub_deadline: Duration::from_millis(800),
            reconnect_min: Duration::from_millis(250),
            extra_roots: Vec::new(),
        }
    }
}

pub struct DaemonHandle {
    pub http_addr: SocketAddr,
    pub socket_path: PathBuf,
    /// Secret the HTTP hook requests must carry as `Authorization: Bearer <token>`.
    pub hook_token: String,
    d: Arc<Daemon>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl DaemonHandle {
    /// How many times the daemon has completed a handshake with the hub.
    pub fn connects(&self) -> u64 {
        self.d.link.generation.load(Ordering::SeqCst)
    }

    pub async fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
        for t in self.tasks {
            let _ = t.await;
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[derive(Debug)]
pub(crate) enum HubError {
    /// Not connected, or no answer before the deadline: fail open.
    Unavailable,
    /// The hub answered with an error.
    Rejected(String),
}

#[derive(Default)]
pub(crate) struct Link {
    out: Mutex<Option<mpsc::UnboundedSender<Up>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>,
    next_id: AtomicU64,
    pub generation: AtomicU64,
    pub connected: AtomicBool,
}

pub(crate) struct Daemon {
    pub cfg: DaemonConfig,
    pub st: Mutex<State>,
    pub link: Link,
    pub http_port: AtomicU64,
    pub hook_token: String,
}

impl Daemon {
    /// One request to the hub, answered by `deadline` or `Unavailable`. If the hub has
    /// forgotten the session (it timed out while idle), register it again and retry once.
    pub async fn request(&self, req: Request, deadline: Instant) -> Result<Value, HubError> {
        let r = self.send_request(req.clone(), deadline).await;
        let session = match &r {
            Err(HubError::Rejected(e)) if e.starts_with("unknown session") => request_session(&req),
            _ => None,
        };
        let Some(session) = session else { return r };
        self.st.lock().unwrap().sess(&session).hello_gen = 0;
        self.hello(&session, deadline).await?;
        self.send_request(req, deadline).await
    }

    async fn send_request(&self, req: Request, deadline: Instant) -> Result<Value, HubError> {
        if !self.link.connected.load(Ordering::SeqCst) {
            return Err(HubError::Unavailable);
        }
        let id = self.link.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.link.pending.lock().unwrap().insert(id, tx);
        let sent = self
            .link
            .out
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|o| o.send(Up::Req { id, req }).is_ok());
        if !sent {
            self.link.pending.lock().unwrap().remove(&id);
            return Err(HubError::Unavailable);
        }
        match tokio::time::timeout_at(deadline.into(), rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(HubError::Rejected(e)),
            _ => {
                self.link.pending.lock().unwrap().remove(&id);
                Err(HubError::Unavailable)
            }
        }
    }

    pub(crate) fn send_up(&self, up: Up) {
        if let Some(o) = self.link.out.lock().unwrap().as_ref() {
            let _ = o.send(up);
        }
    }

    /// Register `session` with the hub on the current connection if not done yet.
    pub async fn hello(&self, session: &str, deadline: Instant) -> Result<(), HubError> {
        let gen = self.link.generation.load(Ordering::SeqCst);
        let req = {
            let mut st = self.st.lock().unwrap();
            let s = st.sess(session);
            if s.hello_gen == gen && gen != 0 {
                return Ok(());
            }
            Request::Hello {
                session: session.to_string(),
                repo: s.repo.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
                branch: s
                    .repo
                    .as_ref()
                    .map(|r| r.branch.clone())
                    .unwrap_or_default(),
                task: s.task.clone(),
            }
        };
        self.send_request(req, deadline).await?;
        self.st.lock().unwrap().sess(session).hello_gen = gen;
        Ok(())
    }
}

/// The hook token stored next to a daemon socket, for `wormhole install`.
pub fn read_hook_token(socket_path: &std::path::Path) -> Result<Option<String>, String> {
    match socket_path.parent() {
        Some(d) => sock::read_hook_token(&d.join("hook-token")),
        None => Ok(None),
    }
}

/// The session a request acts for, if any.
fn request_session(r: &Request) -> Option<String> {
    use Request::*;
    match r {
        Hello { .. } | Snapshot => None,
        Heartbeat { session }
        | Bye { session }
        | Activity { session, .. }
        | Send { session, .. }
        | MsgRead { session, .. }
        | LeaseAcquire { session, .. }
        | LeaseRenew { session, .. }
        | LeaseRelease { session, .. }
        | LeaseRequestTransfer { session, .. }
        | LeaseGrant { session, .. }
        | LeaseDeny { session, .. } => Some(session.clone()),
    }
}

pub async fn start(cfg: DaemonConfig) -> Result<DaemonHandle, String> {
    if !cfg.http_listen.ip().is_loopback() {
        return Err("the hook HTTP endpoint must listen on loopback".into());
    }
    let unix = sock::bind(&cfg.socket_path)?;
    let hook_token = sock::hook_token(
        cfg.socket_path
            .parent()
            .ok_or("socket path has no directory")?,
    )?;
    let d = Arc::new(Daemon {
        cfg: cfg.clone(),
        st: Mutex::new(State::default()),
        link: Link::default(),
        http_port: AtomicU64::new(0),
        hook_token: hook_token.clone(),
    });
    let http = tokio::net::TcpListener::bind(cfg.http_listen)
        .await
        .map_err(|e| format!("bind {}: {e}", cfg.http_listen))?;
    let http_addr = http.local_addr().map_err(|e| e.to_string())?;
    d.http_port.store(http_addr.port() as u64, Ordering::SeqCst);
    let tasks = vec![
        tokio::spawn(link_loop(d.clone())),
        tokio::spawn(heartbeat(d.clone())),
        tokio::spawn(sock::serve(d.clone(), unix)),
        tokio::spawn(hooks::serve_http(d.clone(), http)),
    ];
    Ok(DaemonHandle {
        http_addr,
        socket_path: cfg.socket_path,
        hook_token,
        d,
        tasks,
    })
}

async fn link_loop(d: Arc<Daemon>) {
    let max = Duration::from_secs(10);
    let mut delay = d.cfg.reconnect_min;
    loop {
        if let Ok(ws) = connect(&d).await {
            if run_connection(&d, ws).await {
                delay = d.cfg.reconnect_min;
            }
        }
        // Up to 25% jitter, without a random-number dependency.
        let jitter = (Instant::now().elapsed().subsec_nanos() as u64 ^ now_ms())
            % (delay.as_millis() as u64 / 4 + 1);
        tokio::time::sleep(delay + Duration::from_millis(jitter)).await;
        delay = (delay * 2).min(max);
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(d: &Daemon) -> Result<Ws, String> {
    let mut req = d
        .cfg
        .hub_url
        .as_str()
        .into_client_request()
        .map_err(|e| e.to_string())?;
    if let Some(id) = &d.cfg.static_identity {
        req.headers_mut().insert(
            STATIC_ID_HEADER,
            id.parse().map_err(|_| "bad static identity")?,
        );
    }
    let conf = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME));
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async_with_config(req, Some(conf), false),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Run one hub connection until it drops. True if the handshake completed.
async fn run_connection(d: &Arc<Daemon>, ws: Ws) -> bool {
    let (mut sink, mut stream) = ws.split();
    let from = d.st.lock().unwrap().last_seq;
    let resume = serde_json::to_string(&Up::Resume { from }).unwrap_or_default();
    if sink.send(Message::text(resume)).await.is_err() {
        return false;
    }
    match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => match serde_json::from_str::<Down>(&t) {
            Ok(Down::Welcome { head, .. }) => {
                // A hub log behind our cursor (database reset, or commits lost on power
                // failure) would otherwise make us drop every new event as already seen.
                let mut st = d.st.lock().unwrap();
                if st.last_seq.is_some_and(|l| l > head) {
                    st.last_seq = Some(head);
                }
            }
            _ => return false,
        },
        _ => return false,
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Up>();
    *d.link.out.lock().unwrap() = Some(out_tx);
    d.link.generation.fetch_add(1, Ordering::SeqCst);
    d.link.connected.store(true, Ordering::SeqCst);

    // Re-register every known session on the new connection.
    let rehello = {
        let d = d.clone();
        tokio::spawn(async move {
            let ids: Vec<String> = d.st.lock().unwrap().sessions.keys().cloned().collect();
            for id in ids {
                let _ = d.hello(&id, Instant::now() + Duration::from_secs(5)).await;
            }
        })
    };

    let mut ping = tokio::time::interval(Duration::from_secs(15));
    let mut last_rx = Instant::now();
    loop {
        tokio::select! {
            up = out_rx.recv() => match up {
                Some(up) => {
                    let s = serde_json::to_string(&up).unwrap_or_default();
                    if sink.send(Message::text(s)).await.is_err() { break; }
                }
                None => break,
            },
            frame = stream.next() => {
                last_rx = Instant::now();
                match frame {
                    Some(Ok(Message::Text(t))) => match serde_json::from_str::<Down>(&t) {
                        Ok(Down::Event { event }) => {
                            let ack = {
                                let mut st = d.st.lock().unwrap();
                                st.apply(&event);
                                st.ack_point()
                            };
                            if let Some(seq) = ack {
                                d.send_up(Up::Ack { seq });
                            }
                        }
                        Ok(Down::Resp { id, ok, data, error }) => {
                            if let Some(tx) = d.link.pending.lock().unwrap().remove(&id) {
                                let _ = tx.send(if ok { Ok(data) } else { Err(error.unwrap_or_default()) });
                            }
                        }
                        _ => {}
                    },
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = ping.tick() => {
                if last_rx.elapsed() > Duration::from_secs(45) { break; }
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() { break; }
            }
        }
    }
    rehello.abort();
    d.link.connected.store(false, Ordering::SeqCst);
    *d.link.out.lock().unwrap() = None;
    d.link.pending.lock().unwrap().clear();
    true
}

/// Keep presence alive for sessions that were active recently or have a channel attached.
async fn heartbeat(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        let ids: Vec<String> = {
            let mut st = d.st.lock().unwrap();
            st.sessions
                .iter_mut()
                .filter_map(|(id, s)| {
                    s.subs.retain(|x| !x.is_closed());
                    (s.last_active.elapsed() < Duration::from_secs(1800) || !s.subs.is_empty())
                        .then(|| id.clone())
                })
                .collect()
        };
        for id in ids {
            let _ = d
                .request(
                    Request::Heartbeat { session: id },
                    Instant::now() + Duration::from_secs(5),
                )
                .await;
        }
    }
}
