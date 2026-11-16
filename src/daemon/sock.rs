//! The daemon's Unix socket: newline-delimited JSON for the channel MCP server and the
//! `wormhole hook` command. The socket lives in a directory only this user can enter, has
//! mode 0600, and every peer's uid is checked.

use super::{deleg, hooks, Daemon, HubError};
use crate::proto::*;
use crate::text;
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Longest request line accepted. Hook inputs carry file contents, so this is generous.
const MAX_LINE: u64 = 64 * 1024 * 1024;

pub(crate) struct Bound {
    listener: UnixListener,
    uid: u32,
}

/// Create `dir` with mode 0700 if missing, then require that it is a real directory (not
/// a symlink), owned by our effective uid, with no group or other access.
pub(crate) fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
        Ok(_) => {}
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(format!(
            "{} must be a directory, not a symlink",
            dir.display()
        ));
    }
    if m.uid() != euid() || m.mode() & 0o077 != 0 {
        return Err(format!(
            "{} must be owned by this user and not accessible to others (chmod 700)",
            dir.display()
        ));
    }
    Ok(())
}

pub(crate) fn bind(path: &Path) -> Result<Bound, String> {
    use std::os::unix::fs::FileTypeExt;
    let dir = path.parent().ok_or("socket path has no directory")?;
    private_dir(dir)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(format!(
                    "a daemon is already listening on {}",
                    path.display()
                ));
            }
            std::fs::remove_file(path)
                .map_err(|e| format!("remove stale {}: {e}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a socket; refusing to replace it",
                path.display()
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    // The directory is ours and closed to others, so nothing can swap the path in between.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(Bound {
        listener,
        uid: euid(),
    })
}

/// The secret HTTP hook requests must carry, kept in `dir/hook-token` (mode 0600) so it
/// survives daemon restarts and `wormhole install` can print it.
pub(crate) fn hook_token(dir: &Path) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    private_dir(dir)?;
    let p = dir.join("hook-token");
    if let Some(t) = read_hook_token(&p)? {
        return Ok(t);
    }
    let mut raw = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .map_err(|e| format!("create {}: {e}", p.display()))?;
    f.write_all(token.as_bytes()).map_err(|e| e.to_string())?;
    Ok(token)
}

/// Read an existing token file, refusing one that is a symlink, not ours, or readable by others.
pub(crate) fn read_hook_token(p: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
        Ok(m) => {
            if !m.file_type().is_file() || m.uid() != euid() || m.mode() & 0o077 != 0 {
                return Err(format!(
                    "{} must be a regular file owned by this user with mode 600",
                    p.display()
                ));
            }
            let t = std::fs::read_to_string(p)
                .map_err(|e| e.to_string())?
                .trim()
                .to_string();
            if t.len() < 32 {
                return Err(format!(
                    "{} is too short; delete it to regenerate",
                    p.display()
                ));
            }
            Ok(Some(t))
        }
    }
}

pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub(crate) fn peer_allowed(peer: Option<u32>, euid: u32) -> bool {
    peer == Some(euid)
}

pub(crate) async fn serve(d: Arc<Daemon>, b: Bound) {
    while let Ok((s, _)) = b.listener.accept().await {
        if !peer_allowed(s.peer_cred().ok().map(|c| c.uid()), b.uid) {
            continue;
        }
        tokio::spawn(client(d.clone(), s));
    }
}

async fn client(d: Arc<Daemon>, s: UnixStream) {
    let (r, mut w) = s.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(v) = rx.recv().await {
            let mut line = v.to_string();
            line.push('\n');
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut r = BufReader::new(r);
    loop {
        let mut line = String::new();
        match (&mut r).take(MAX_LINE).read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) if !line.ends_with('\n') => break,
            Ok(_) => {}
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            break;
        };
        let id = req["id"].clone();
        let res = op(&d, &req, &tx).await;
        let resp = match res {
            Ok(data) => json!({"id": id, "ok": true, "data": data}),
            Err(e) => json!({"id": id, "ok": false, "error": e}),
        };
        if tx.send(resp).is_err() {
            break;
        }
    }
    writer.abort();
}

async fn op(d: &Daemon, req: &Value, tx: &mpsc::UnboundedSender<Value>) -> Result<Value, String> {
    match req["op"].as_str().unwrap_or("") {
        "ping" => Ok(json!({})),
        "hook" => Ok(hooks::handle(d, req["input"].clone()).await),
        "attach" => {
            let session = session_arg(req)?;
            let sub = tx.clone();
            let mut st = d.st.lock().unwrap();
            st.sess(session).subs.push(sub);
            Ok(json!({}))
        }
        "revoke" => {
            if d.cfg.delegation_policy.is_none() {
                return Err("this daemon has no delegation policy".into());
            }
            deleg::kill(d).await;
            Ok(json!({}))
        }
        "tool" => {
            let session = session_arg(req)?;
            if !d.st.lock().unwrap().sessions.contains_key(session) {
                return Err("unknown session: no hook has run for it on this machine".into());
            }
            let text = tool(d, session, req["name"].as_str().unwrap_or(""), &req["args"]).await?;
            Ok(json!({"text": text}))
        }
        _ => Err("unknown op".into()),
    }
}

fn session_arg(req: &Value) -> Result<&str, String> {
    req["session"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= MAX_FIELD)
        .ok_or_else(|| "missing session".to_string())
}

fn hub_err(e: HubError) -> String {
    match e {
        HubError::Unavailable => "the wormhole hub is unreachable; try again later".into(),
        HubError::Rejected(e) => e,
    }
}

fn arg<'a>(args: &'a Value, k: &str) -> Result<&'a str, String> {
    args[k].as_str().ok_or_else(|| format!("missing {k}"))
}

/// Resolve a scope argument against the session's repo: an `area:` name, a repo-relative
/// path or glob, or an absolute path inside the repo.
fn scope(d: &Daemon, session: &str, args: &Value) -> Result<(String, String), String> {
    resolve(d, session, arg(args, "scope")?)
}

fn resolve(d: &Daemon, session: &str, raw: &str) -> Result<(String, String), String> {
    let raw = raw.trim();
    let st = d.st.lock().unwrap();
    let s = st.sessions.get(session).ok_or("unknown session")?;
    let r = s
        .repo
        .as_ref()
        .ok_or("this session is not in a git repository")?;
    let sc = if raw.starts_with('/') {
        crate::repo::relative(&r.root, &r.root, raw).ok_or("path is outside the repository")?
    } else {
        raw.trim_start_matches("./").to_string()
    };
    if sc.is_empty() || sc.len() > MAX_FIELD || sc.split('/').any(|p| p == "..") {
        return Err("invalid scope".into());
    }
    // A directory scope ends with `/` so it covers what is under it; plain scopes are files.
    let plain = !sc.contains('*') && !sc.starts_with("area:");
    let sc = if plain && !sc.ends_with('/') && r.root.join(&sc).is_dir() {
        format!("{sc}/")
    } else {
        sc
    };
    Ok((r.id.clone(), sc))
}

fn strings(args: &Value, k: &str) -> Result<Vec<String>, String> {
    match &args[k] {
        Value::Null => Ok(vec![]),
        Value::Array(a) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or(format!("{k} must be strings"))
            })
            .collect(),
        _ => Err(format!("{k} must be an array")),
    }
}

async fn tool(d: &Daemon, session: &str, name: &str, args: &Value) -> Result<String, String> {
    // Checked before anything is sent: a hub that did not advertise delegation must never
    // see a delegation frame.
    if matches!(name, "delegate" | "result") && !d.hub_delegates() {
        return Err("this wormhole hub does not support delegation".into());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    d.hello(session, deadline).await.map_err(hub_err)?;
    let req = |r: Request| d.request(r, deadline);
    let s = session.to_string();
    match name {
        "who" => hooks::who_text(d, session, deadline).await.map_err(hub_err),
        "send" => {
            let to = match arg(args, "to")? {
                "all" | "broadcast" => Target::Broadcast,
                t => match t.split_once(':') {
                    Some(("session", id)) => Target::Session(id.into()),
                    Some(("user", u)) => Target::User(u.into()),
                    _ => return Err("to must be session:<id>, user:<name> or all".into()),
                },
            };
            let body = arg(args, "body")?.to_string();
            let reply_to = args["reply_to"].as_u64();
            let v = req(Request::Send {
                session: s,
                to,
                body,
                reply_to,
            })
            .await
            .map_err(hub_err)?;
            Ok(format!("sent (seq {})", v["seq"]))
        }
        "lease" => {
            let (repo, scope) = scope(d, session, args)?;
            let ttl_ms = args["ttl_seconds"]
                .as_u64()
                .map(|t| t.saturating_mul(1000))
                .unwrap_or(d.cfg.lease_ttl.as_millis() as u64);
            let v = req(Request::LeaseAcquire {
                session: s,
                repo: repo.clone(),
                scope: scope.clone(),
                ttl_ms,
            })
            .await
            .map_err(hub_err)?;
            match serde_json::from_value::<LeaseResult>(v).map_err(|e| e.to_string())? {
                LeaseResult::Granted { lease } => {
                    {
                        let mut st = d.st.lock().unwrap();
                        let x = st.sess(session);
                        x.tokens.insert((repo.clone(), scope.clone()), lease.token);
                        x.explicit.insert((repo, scope.clone()));
                    }
                    Ok(format!(
                        "lease granted on {} (token {}), expires in {} s",
                        text::attr(&scope),
                        lease.token,
                        lease.expires.saturating_sub(now_ms()) / 1000
                    ))
                }
                LeaseResult::Held { lease } => Ok(format!(
                    "not granted: {} is held by session {} ({}@{}) on scope {}",
                    text::attr(&scope),
                    text::attr(&lease.session),
                    text::attr(&lease.user),
                    text::attr(&lease.machine),
                    text::attr(&lease.scope)
                )),
            }
        }
        "release" => {
            let (repo, scope) = scope(d, session, args)?;
            let key = (repo.clone(), scope.clone());
            let token =
                d.st.lock()
                    .unwrap()
                    .sess(session)
                    .tokens
                    .get(&key)
                    .copied()
                    .ok_or("this session does not hold that lease")?;
            req(Request::LeaseRelease {
                session: s,
                repo,
                scope,
                token,
            })
            .await
            .map_err(hub_err)?;
            {
                let mut st = d.st.lock().unwrap();
                let x = st.sess(session);
                x.tokens.remove(&key);
                x.explicit.remove(&key);
            }
            Ok("released".into())
        }
        "request_transfer" => {
            let (repo, scope) = scope(d, session, args)?;
            let reason = args["reason"].as_str().unwrap_or("").to_string();
            req(Request::LeaseRequestTransfer {
                session: s,
                repo,
                scope,
                reason,
            })
            .await
            .map_err(hub_err)?;
            Ok("request sent to the holder; the answer arrives as a notice".into())
        }
        "grant" => {
            let (repo, scope) = scope(d, session, args)?;
            let to = arg(args, "to")?.to_string();
            req(Request::LeaseGrant {
                session: s,
                repo: repo.clone(),
                scope: scope.clone(),
                to,
            })
            .await
            .map_err(hub_err)?;
            d.st.lock()
                .unwrap()
                .sess(session)
                .tokens
                .remove(&(repo, scope));
            Ok("granted".into())
        }
        "deny" => {
            let (repo, scope) = scope(d, session, args)?;
            let to = arg(args, "to")?.to_string();
            let reason = args["reason"].as_str().unwrap_or("").to_string();
            req(Request::LeaseDeny {
                session: s,
                repo,
                scope,
                to,
                reason,
            })
            .await
            .map_err(hub_err)?;
            Ok("denied".into())
        }
        "delegate" => {
            let to = arg(args, "to")?.to_string();
            let mut paths = Vec::new();
            let mut repo = String::new();
            for p in strings(args, "paths")? {
                let (r, sc) = resolve(d, session, &p)?;
                repo = r;
                paths.push(sc);
            }
            if paths.is_empty() {
                repo =
                    d.st.lock()
                        .unwrap()
                        .sessions
                        .get(session)
                        .and_then(|s| s.repo.as_ref().map(|r| r.id.clone()))
                        .ok_or("this session is not in a git repository")?;
            }
            let contract = Contract {
                task_id: arg(args, "task_id")?.to_string(),
                kind: arg(args, "kind")?.to_string(),
                spec: args["spec"].as_str().unwrap_or("").to_string(),
                paths,
                commands: strings(args, "commands")?,
                exit: args["exit"].as_str().unwrap_or("").to_string(),
                ttl_secs: args["ttl_seconds"].as_u64().unwrap_or(0),
                max_steps: args["max_steps"].as_u64().unwrap_or(0),
                result_fields: strings(args, "result_fields")?,
                reference: String::new(),
                text: arg(args, "text")?.to_string(),
            };
            let v = req(Request::Delegate {
                session: s,
                to,
                repo,
                contract,
            })
            .await
            .map_err(hub_err)?;
            Ok(format!(
                "delegation request sent (request {}); the answer arrives as a notice",
                v["seq"]
            ))
        }
        "result" => {
            let request = args["request"]
                .as_u64()
                .ok_or("request must be the request id")?;
            let status = arg(args, "status")?.to_string();
            let fields = match &args["fields"] {
                Value::Object(m) => m.clone(),
                Value::Null => Default::default(),
                _ => return Err("fields must be an object".into()),
            };
            req(Request::DelegateResult {
                session: s,
                request,
                status: status.clone(),
                summary: arg(args, "summary")?.to_string(),
                fields,
            })
            .await
            .map_err(hub_err)?;
            deleg::finished(d, session, request, &status);
            Ok("result posted".into())
        }
        "set_task" => {
            let task = text::plain(arg(args, "task")?, MAX_TASK);
            {
                let mut st = d.st.lock().unwrap();
                let x = st.sess(session);
                x.task = task;
                x.hello_gen = 0;
            }
            d.hello(session, deadline).await.map_err(hub_err)?;
            Ok("task set".into())
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wh-sock-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn creates_private_dir_and_socket() {
        let d = base("ok");
        let p = d.join("run/d.sock");
        let _b = bind(&p).unwrap();
        assert_eq!(
            std::fs::metadata(d.join("run")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn refuses_symlinked_runtime_dir() {
        let d = base("symdir");
        let real = d.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, d.join("run")).unwrap();
        assert!(bind(&d.join("run/d.sock")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn refuses_group_or_world_accessible_dir() {
        for mode in [0o750, 0o705, 0o770, 0o777] {
            let d = base(&format!("mode{mode:o}"));
            let run = d.join("run");
            std::fs::create_dir_all(&run).unwrap();
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(bind(&run.join("d.sock")).is_err(), "mode {mode:o}");
            std::fs::remove_dir_all(&d).unwrap();
        }
    }

    #[tokio::test]
    async fn refuses_symlink_at_socket_path() {
        let d = base("symsock");
        let run = d.join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(d.join("target"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("target"), run.join("d.sock")).unwrap();
        assert!(bind(&run.join("d.sock")).is_err());
        // The symlink target was not touched.
        assert_eq!(std::fs::read_to_string(d.join("target")).unwrap(), "x");
        std::fs::remove_dir_all(&d).unwrap();
    }

    // A peer with another uid cannot be produced in a test without a second account, so
    // the rule itself is checked: only our effective uid is accepted.
    #[test]
    fn only_our_uid_is_accepted() {
        let me = euid();
        assert!(peer_allowed(Some(me), me));
        assert!(!peer_allowed(Some(me + 1), me));
        assert!(!peer_allowed(None, me));
    }
}
