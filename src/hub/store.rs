//! The hub's durable state in SQLite: the ordered event log, leases with fencing tokens,
//! and per-machine delivery cursors. Times are passed in so tests control the clock.

use crate::proto::{DelegationInfo, Event, LeaseInfo};
use serde_json::Value;
use std::path::Path;

pub struct Store {
    conn: rusqlite::Connection,
}

/// Who is asking for a lease.
#[derive(Clone, Debug)]
pub struct Holder<'a> {
    pub session: &'a str,
    pub user: &'a str,
    pub machine: &'a str,
}

#[derive(Debug, PartialEq)]
pub enum Acquired {
    /// `fresh` is true when a new token was issued, false when an existing lease was extended.
    Granted { lease: LeaseInfo, fresh: bool },
    /// Another session holds an overlapping scope.
    Held(LeaseInfo),
}

#[derive(Debug, PartialEq)]
pub enum LeaseError {
    /// No live lease on that scope.
    NotHeld,
    /// The token is not the current one for that scope (fencing).
    StaleToken,
    /// The caller is not the holder.
    NotHolder,
    /// A different session holds an overlapping scope.
    Conflict(LeaseInfo),
    /// The grantor holds a broader lease overlapping the one it is handing over.
    GrantorHoldsBroader(LeaseInfo),
}

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    user TEXT NOT NULL,
    machine TEXT NOT NULL,
    session TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    repo TEXT NOT NULL,
    scope TEXT NOT NULL,
    session TEXT NOT NULL,
    user TEXT NOT NULL,
    machine TEXT NOT NULL,
    token INTEGER NOT NULL,
    since INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    PRIMARY KEY (repo, scope)
);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT OR IGNORE INTO counters (name, value) VALUES ('token', 0);
CREATE TABLE IF NOT EXISTS cursors (key TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS session_owners (session TEXT PRIMARY KEY, user TEXT NOT NULL, machine TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS delegations (
    seq INTEGER PRIMARY KEY,
    from_session TEXT NOT NULL, from_user TEXT NOT NULL, from_machine TEXT NOT NULL,
    to_session TEXT NOT NULL, to_user TEXT NOT NULL, to_machine TEXT NOT NULL,
    repo TEXT NOT NULL, task_id TEXT NOT NULL, kind TEXT NOT NULL,
    paths TEXT NOT NULL, result_fields TEXT NOT NULL,
    status TEXT NOT NULL, level TEXT NOT NULL, summary TEXT NOT NULL, ts INTEGER NOT NULL
);
";

/// A request nobody answered for this long is expired.
pub const DELEGATION_PENDING_MS: u64 = 10 * 60 * 1000;

/// A delegated task: what the hub reports plus what it needs to hand off leases and check
/// the result.
#[derive(Clone, Debug, Default)]
pub struct Delegation {
    pub info: DelegationInfo,
    pub paths: Vec<String>,
    pub result_fields: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum AckError {
    NoSuchRequest,
    NotRecipient,
    Expired,
    /// The hand-off would break mutual exclusion; the message starts with `conflict:`.
    Conflict(String),
}

#[derive(Debug)]
pub struct Acked {
    /// False when the request had already been answered; nothing changed.
    pub fresh: bool,
    pub info: DelegationInfo,
    pub paths: Vec<String>,
    pub released: Vec<LeaseInfo>,
    pub granted: Vec<LeaseInfo>,
}

/// Shortest and longest lease a client can ask for; requests outside are clamped.
pub const MIN_TTL_MS: u64 = 100;
pub const MAX_TTL_MS: u64 = 4 * 60 * 60 * 1000;

const MAX_TIME: u64 = i64::MAX as u64;

/// Clamp a clock reading so it and any expiry after it fit in SQLite's i64.
fn clamp_now(now: u64) -> u64 {
    now.min(MAX_TIME - 1)
}

fn expiry(now: u64, ttl_ms: u64) -> u64 {
    now.saturating_add(ttl_ms.clamp(MIN_TTL_MS, MAX_TTL_MS))
        .min(MAX_TIME)
}

const DELEG_COLS: &str = "seq, from_session, from_user, from_machine, to_session, to_user, to_machine, repo, task_id, kind, status, level, summary, ts";

fn deleg_info(r: &rusqlite::Row) -> rusqlite::Result<DelegationInfo> {
    Ok(DelegationInfo {
        seq: r.get::<_, i64>(0)? as u64,
        from_session: r.get(1)?,
        from_user: r.get(2)?,
        from_machine: r.get(3)?,
        to_session: r.get(4)?,
        to_user: r.get(5)?,
        to_machine: r.get(6)?,
        repo: r.get(7)?,
        task_id: r.get(8)?,
        kind: r.get(9)?,
        status: r.get(10)?,
        level: r.get(11)?,
        summary: r.get(12)?,
        ts: r.get::<_, i64>(13)? as u64,
    })
}

const LEASE_COLS: &str = "repo, scope, session, user, machine, token, since, expires";

fn lease_row(r: &rusqlite::Row) -> rusqlite::Result<LeaseInfo> {
    Ok(LeaseInfo {
        repo: r.get(0)?,
        scope: r.get(1)?,
        session: r.get(2)?,
        user: r.get(3)?,
        machine: r.get(4)?,
        token: r.get::<_, i64>(5)? as u64,
        since: r.get::<_, i64>(6)? as u64,
        expires: r.get::<_, i64>(7)? as u64,
    })
}

fn event_row(r: &rusqlite::Row) -> rusqlite::Result<Event> {
    let data: String = r.get(6)?;
    Ok(Event {
        seq: r.get::<_, i64>(0)? as u64,
        ts: r.get::<_, i64>(1)? as u64,
        kind: r.get(2)?,
        user: r.get(3)?,
        machine: r.get(4)?,
        session: r.get(5)?,
        data: serde_json::from_str(&data).unwrap_or(Value::Null),
    })
}

impl Store {
    /// Open or create the database. The log holds message bodies, so the file and its
    /// -wal and -shm companions are created owner-only (0600) before SQLite touches them,
    /// a missing parent directory is created 0700, and a parent others can write to (where
    /// the file could be swapped) is refused.
    pub fn open(path: &Path) -> Result<Store, String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        let shown = path.display();
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let dm = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if dm.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is writable by other users; put the hub database in a private directory",
                dir.display()
            ));
        }
        let private = |p: &Path| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 600 {}: {e}", p.display()))
        };
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("open {shown}: {e}"))?;
        private(path)?;
        let conn = rusqlite::Connection::open(path).map_err(|e| format!("open {shown}: {e}"))?;
        let s = Self::init(conn).map_err(|e| format!("open {shown}: {e}"))?;
        for ext in ["-wal", "-shm"] {
            let f = std::path::PathBuf::from(format!("{}{ext}", path.display()));
            if f.exists() {
                private(&f)?;
            }
        }
        Ok(s)
    }

    pub fn open_memory() -> rusqlite::Result<Store> {
        Self::init(rusqlite::Connection::open_in_memory()?)
    }

    fn init(conn: rusqlite::Connection) -> rusqlite::Result<Store> {
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    pub fn append(
        &self,
        ts: u64,
        kind: &str,
        user: &str,
        machine: &str,
        session: &str,
        data: Value,
    ) -> rusqlite::Result<Event> {
        self.conn.execute(
            "INSERT INTO events (ts, kind, user, machine, session, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![ts as i64, kind, user, machine, session, data.to_string()],
        )?;
        Ok(Event {
            seq: self.conn.last_insert_rowid() as u64,
            ts,
            kind: kind.into(),
            user: user.into(),
            machine: machine.into(),
            session: session.into(),
            data,
        })
    }

    pub fn head(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|v| v as u64)
    }

    pub fn events_after(&self, seq: u64, limit: usize) -> rusqlite::Result<Vec<Event>> {
        let mut st = self.conn.prepare_cached(
            "SELECT seq, ts, kind, user, machine, session, data FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )?;
        let rows = st.query_map(rusqlite::params![seq as i64, limit as i64], event_row)?;
        rows.collect()
    }

    pub fn recent(&self, limit: usize) -> rusqlite::Result<Vec<Event>> {
        let head = self.head()?;
        self.events_after(head.saturating_sub(limit as u64), limit)
    }

    pub fn cursor(&self, key: &str) -> rusqlite::Result<Option<u64>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row("SELECT seq FROM cursors WHERE key = ?1", [key], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
            .map(|v| v.map(|v| v as u64))
    }

    pub fn set_cursor(&mut self, key: &str, seq: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO cursors (key, seq) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET seq = MAX(seq, excluded.seq)",
            rusqlite::params![key, seq as i64],
        )?;
        Ok(())
    }

    /// Bind `session` to its first owner for good. True if `user@machine` is that owner.
    /// shortcut: bindings are never pruned; add an age-based purge if ids pile up.
    pub fn bind_session(
        &mut self,
        session: &str,
        user: &str,
        machine: &str,
    ) -> rusqlite::Result<bool> {
        self.conn.execute(
            "INSERT OR IGNORE INTO session_owners (session, user, machine) VALUES (?1, ?2, ?3)",
            [session, user, machine],
        )?;
        Ok(self
            .session_owner(session)?
            .is_some_and(|(u, m)| u == user && m == machine))
    }

    pub fn session_owner(&self, session: &str) -> rusqlite::Result<Option<(String, String)>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                "SELECT user, machine FROM session_owners WHERE session = ?1",
                [session],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    fn next_token(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row(
                "UPDATE counters SET value = value + 1 WHERE name = 'token' RETURNING value",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
    }

    /// The row for exactly `scope`, live or not.
    fn row(&self, repo: &str, scope: &str) -> rusqlite::Result<Option<LeaseInfo>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                &format!("SELECT {LEASE_COLS} FROM leases WHERE repo = ?1 AND scope = ?2"),
                [repo, scope],
                lease_row,
            )
            .optional()
    }

    fn put(&self, l: &LeaseInfo) -> rusqlite::Result<()> {
        self.conn.execute(
            &format!("INSERT OR REPLACE INTO leases ({LEASE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
            rusqlite::params![
                l.repo,
                l.scope,
                l.session,
                l.user,
                l.machine,
                l.token as i64,
                l.since as i64,
                l.expires as i64
            ],
        )?;
        Ok(())
    }

    fn delete(&self, repo: &str, scope: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM leases WHERE repo = ?1 AND scope = ?2",
            [repo, scope],
        )?;
        Ok(())
    }

    fn query_leases(
        &self,
        sql_where: &str,
        params: impl rusqlite::Params,
    ) -> rusqlite::Result<Vec<LeaseInfo>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {LEASE_COLS} FROM leases WHERE {sql_where} ORDER BY since, scope"
        ))?;
        let rows = st.query_map(params, lease_row)?;
        rows.collect()
    }

    /// Grant, extend, or report the holder. Every grant gets a token larger than any issued before.
    pub fn acquire(
        &mut self,
        now: u64,
        who: &Holder,
        repo: &str,
        scope: &str,
        ttl_ms: u64,
    ) -> rusqlite::Result<Acquired> {
        let now = clamp_now(now);
        let live = self.query_leases(
            "repo = ?1 AND expires > ?2",
            rusqlite::params![repo, now as i64],
        )?;
        if let Some(other) = live
            .iter()
            .find(|l| l.session != who.session && crate::glob::overlaps(&l.scope, scope))
        {
            return Ok(Acquired::Held(other.clone()));
        }
        if let Some(mut own) = live.into_iter().find(|l| l.scope == scope) {
            own.expires = expiry(now, ttl_ms);
            self.put(&own)?;
            return Ok(Acquired::Granted {
                lease: own,
                fresh: false,
            });
        }
        let lease = LeaseInfo {
            repo: repo.into(),
            scope: scope.into(),
            session: who.session.into(),
            user: who.user.into(),
            machine: who.machine.into(),
            token: self.next_token()?,
            since: now,
            expires: expiry(now, ttl_ms),
        };
        self.put(&lease)?;
        Ok(Acquired::Granted { lease, fresh: true })
    }

    /// Check `token` against the current lease on `scope`: the fencing rule.
    fn fenced(
        &self,
        now: u64,
        session: &str,
        repo: &str,
        scope: &str,
        token: u64,
    ) -> rusqlite::Result<Result<LeaseInfo, LeaseError>> {
        Ok(match self.row(repo, scope)? {
            None => Err(LeaseError::NotHeld),
            Some(l) if l.token != token => Err(LeaseError::StaleToken),
            Some(l) if l.expires <= now => Err(LeaseError::NotHeld),
            Some(l) if l.session != session => Err(LeaseError::NotHolder),
            Some(l) => Ok(l),
        })
    }

    /// Extend a lease the caller holds with `token`.
    pub fn renew(
        &mut self,
        now: u64,
        session: &str,
        repo: &str,
        scope: &str,
        token: u64,
        ttl_ms: u64,
    ) -> rusqlite::Result<Result<LeaseInfo, LeaseError>> {
        let now = clamp_now(now);
        let mut l = match self.fenced(now, session, repo, scope, token)? {
            Ok(l) => l,
            Err(e) => return Ok(Err(e)),
        };
        l.expires = expiry(now, ttl_ms);
        self.put(&l)?;
        Ok(Ok(l))
    }

    pub fn release(
        &mut self,
        now: u64,
        session: &str,
        repo: &str,
        scope: &str,
        token: u64,
    ) -> rusqlite::Result<Result<LeaseInfo, LeaseError>> {
        let now = clamp_now(now);
        let l = match self.fenced(now, session, repo, scope, token)? {
            Ok(l) => l,
            Err(e) => return Ok(Err(e)),
        };
        self.delete(repo, scope)?;
        Ok(Ok(l))
    }

    /// Hand the caller's lease on `scope` to `to`, with a new token.
    pub fn transfer(
        &mut self,
        now: u64,
        holder_session: &str,
        repo: &str,
        scope: &str,
        to: &Holder,
        ttl_ms: u64,
    ) -> rusqlite::Result<Result<(LeaseInfo, Vec<LeaseInfo>), LeaseError>> {
        let now = clamp_now(now);
        let tx = self.conn.unchecked_transaction()?;
        let current = match self.lease(now, repo, scope)? {
            None => return Ok(Err(LeaseError::NotHeld)),
            Some(l) if l.session != holder_session => return Ok(Err(LeaseError::NotHolder)),
            Some(l) => l,
        };
        // The recipient must not end up overlapping a third session's lease.
        let live = self.query_leases(
            "repo = ?1 AND expires > ?2",
            rusqlite::params![repo, now as i64],
        )?;
        let overlapping =
            |l: &&LeaseInfo| l.scope != current.scope && crate::glob::overlaps(&l.scope, scope);
        if let Some(other) = live
            .iter()
            .filter(overlapping)
            .find(|l| l.session != to.session && l.session != holder_session)
        {
            return Ok(Err(LeaseError::Conflict(other.clone())));
        }
        // The grantor's leases inside the scope go with it; a broader one it also holds would
        // be silently lost, so the transfer is refused until the grantor narrows or releases it.
        let own: Vec<&LeaseInfo> = live
            .iter()
            .filter(overlapping)
            .filter(|l| l.session == holder_session)
            .collect();
        if let Some(broader) = own.iter().find(|l| !crate::glob::covers(scope, &l.scope)) {
            return Ok(Err(LeaseError::GrantorHoldsBroader((*broader).clone())));
        }
        let mut released = Vec::new();
        for l in own {
            self.delete(&l.repo, &l.scope)?;
            released.push(l.clone());
        }
        let lease = LeaseInfo {
            repo: repo.into(),
            scope: scope.into(),
            session: to.session.into(),
            user: to.user.into(),
            machine: to.machine.into(),
            token: self.next_token()?,
            since: now,
            expires: expiry(now, ttl_ms),
        };
        self.put(&lease)?;
        tx.commit()?;
        Ok(Ok((lease, released)))
    }

    /// Append the request event and store its row in one step, so the target's ack can
    /// never arrive before the row exists. The request id is the event's seq.
    pub fn delegate(
        &mut self,
        ts: u64,
        user: &str,
        machine: &str,
        session: &str,
        data: Value,
        mut d: Delegation,
    ) -> rusqlite::Result<(Event, Delegation)> {
        let tx = self.conn.unchecked_transaction()?;
        let e = self.append(ts, "delegation.request", user, machine, session, data)?;
        d.info.seq = e.seq;
        d.info.ts = ts;
        let i = &d.info;
        self.conn.execute(
            &format!("INSERT INTO delegations ({DELEG_COLS}, paths, result_fields) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"),
            rusqlite::params![
                i.seq as i64, i.from_session, i.from_user, i.from_machine, i.to_session, i.to_user,
                i.to_machine, i.repo, i.task_id, i.kind, i.status, i.level, i.summary, i.ts as i64,
                serde_json::to_string(&d.paths).unwrap_or_default(),
                serde_json::to_string(&d.result_fields).unwrap_or_default()
            ],
        )?;
        tx.commit()?;
        Ok((e, d))
    }

    pub fn delegation(&self, seq: u64) -> rusqlite::Result<Option<Delegation>> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row(
                &format!(
                    "SELECT {DELEG_COLS}, paths, result_fields FROM delegations WHERE seq = ?1"
                ),
                [seq as i64],
                |r| {
                    let list = |i| -> rusqlite::Result<Vec<String>> {
                        Ok(serde_json::from_str(&r.get::<_, String>(i)?).unwrap_or_default())
                    };
                    Ok(Delegation {
                        info: deleg_info(r)?,
                        paths: list(14)?,
                        result_fields: list(15)?,
                    })
                },
            )
            .optional()
    }

    /// The newest `limit` requests sent from or to `user@machine`, newest first.
    pub fn delegations_for(
        &self,
        user: &str,
        machine: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<DelegationInfo>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {DELEG_COLS} FROM delegations WHERE (from_user = ?1 AND from_machine = ?2) OR (to_user = ?1 AND to_machine = ?2) ORDER BY seq DESC LIMIT ?3"
        ))?;
        let rows = st.query_map(rusqlite::params![user, machine, limit as i64], deleg_info)?;
        rows.collect()
    }

    /// Mark requests still pending after `DELEGATION_PENDING_MS` as expired.
    pub fn expire_delegations(&mut self, now: u64) -> rusqlite::Result<usize> {
        let cutoff = clamp_now(now).saturating_sub(DELEGATION_PENDING_MS);
        self.conn.execute(
            "UPDATE delegations SET status = 'expired' WHERE status = 'pending' AND ts < ?1",
            [cutoff as i64],
        )
    }

    /// The target's answer to a request. An acceptance releases the sender's own leases
    /// that the contract paths cover and grants the target a lease on each path, in one
    /// transaction: any overlap with a third session's lease, or a sender lease broader
    /// than the path, changes nothing. An answer to a request no longer pending returns
    /// the stored outcome with `fresh: false`.
    pub fn ack_delegation(
        &mut self,
        now: u64,
        session: &str,
        request: u64,
        accept: bool,
        level: &str,
        ttl_ms: u64,
    ) -> rusqlite::Result<Result<Acked, AckError>> {
        let now = clamp_now(now);
        let tx = self.conn.unchecked_transaction()?;
        let Some(d) = self.delegation(request)? else {
            return Ok(Err(AckError::NoSuchRequest));
        };
        if d.info.to_session != session {
            return Ok(Err(AckError::NotRecipient));
        }
        let mut acked = Acked {
            fresh: false,
            info: d.info.clone(),
            paths: d.paths.clone(),
            released: vec![],
            granted: vec![],
        };
        if d.info.status != "pending" {
            return Ok(Ok(acked));
        }
        if now.saturating_sub(d.info.ts) > DELEGATION_PENDING_MS {
            self.conn.execute(
                "UPDATE delegations SET status = 'expired' WHERE seq = ?1",
                [request as i64],
            )?;
            tx.commit()?;
            return Ok(Err(AckError::Expired));
        }
        let status = if accept {
            let repo = &d.info.repo;
            let live = self.query_leases(
                "repo = ?1 AND expires > ?2",
                rusqlite::params![repo, now as i64],
            )?;
            let mut released: Vec<LeaseInfo> = Vec::new();
            for p in &d.paths {
                for l in live.iter().filter(|l| crate::glob::overlaps(&l.scope, p)) {
                    if l.session == session {
                        continue;
                    }
                    if l.session == d.info.from_session && crate::glob::covers(p, &l.scope) {
                        if !released.iter().any(|r| r.scope == l.scope) {
                            released.push(l.clone());
                        }
                        continue;
                    }
                    let why = if l.session == d.info.from_session {
                        format!("the sender's lease on {} is broader than {p}", l.scope)
                    } else {
                        format!("session {} holds overlapping scope {}", l.session, l.scope)
                    };
                    return Ok(Err(AckError::Conflict(format!("conflict: {why}"))));
                }
            }
            for l in &released {
                self.delete(&l.repo, &l.scope)?;
            }
            for p in &d.paths {
                let own = live
                    .iter()
                    .find(|l| l.session == session && &l.scope == p)
                    .cloned();
                let lease = match own {
                    Some(mut l) => {
                        l.expires = expiry(now, ttl_ms);
                        l
                    }
                    None => LeaseInfo {
                        repo: repo.clone(),
                        scope: p.clone(),
                        session: session.into(),
                        user: d.info.to_user.clone(),
                        machine: d.info.to_machine.clone(),
                        token: self.next_token()?,
                        since: now,
                        expires: expiry(now, ttl_ms),
                    },
                };
                self.put(&lease)?;
                acked.granted.push(lease);
            }
            acked.released = released;
            "accepted"
        } else if level == "off" {
            "declined"
        } else {
            "informed"
        };
        self.conn.execute(
            "UPDATE delegations SET status = ?2, level = ?3 WHERE seq = ?1",
            rusqlite::params![request as i64, status, level],
        )?;
        tx.commit()?;
        acked.fresh = true;
        acked.info.status = status.into();
        acked.info.level = level.into();
        Ok(Ok(acked))
    }

    /// Record the outcome of an accepted or informed request and release the target's
    /// leases that its contract paths cover. The error is a message for the caller.
    pub fn finish_delegation(
        &mut self,
        session: &str,
        request: u64,
        status: &str,
        summary: &str,
        fields: &serde_json::Map<String, Value>,
    ) -> rusqlite::Result<Result<(Delegation, Vec<LeaseInfo>), String>> {
        let tx = self.conn.unchecked_transaction()?;
        let d = match self.delegation(request)? {
            Some(d) if d.info.to_session == session => d,
            Some(_) => return Ok(Err("not the recipient".into())),
            None => return Ok(Err("no such request".into())),
        };
        if d.info.status != "accepted" && d.info.status != "informed" {
            return Ok(Err("no open request".into()));
        }
        if !["done", "failed", "partial", "revoked"].contains(&status) {
            return Ok(Err("invalid status".into()));
        }
        if status == "done" {
            if let Some(m) = d.result_fields.iter().find(|f| !fields.contains_key(*f)) {
                return Ok(Err(format!("missing result field {m}")));
            }
        }
        let mut info = d.info.clone();
        info.status = status.into();
        info.summary = summary.into();
        self.conn.execute(
            "UPDATE delegations SET status = ?2, summary = ?3 WHERE seq = ?1",
            rusqlite::params![request as i64, status, summary],
        )?;
        let mine = self.query_leases("session = ?1 AND repo = ?2", [session, &d.info.repo])?;
        let mut released = Vec::new();
        for l in mine {
            if d.paths.iter().any(|p| crate::glob::covers(p, &l.scope)) {
                self.delete(&l.repo, &l.scope)?;
                released.push(l);
            }
        }
        tx.commit()?;
        Ok(Ok((Delegation { info, ..d }, released)))
    }

    /// The live lease on exactly `scope`, if any.
    pub fn lease(&self, now: u64, repo: &str, scope: &str) -> rusqlite::Result<Option<LeaseInfo>> {
        let now = clamp_now(now);
        Ok(self.row(repo, scope)?.filter(|l| l.expires > now))
    }

    /// Remove leases past their expiry and return them.
    pub fn expire(&mut self, now: u64) -> rusqlite::Result<Vec<LeaseInfo>> {
        let now = clamp_now(now);
        let gone = self.query_leases("expires <= ?1", [now as i64])?;
        self.conn
            .execute("DELETE FROM leases WHERE expires <= ?1", [now as i64])?;
        Ok(gone)
    }

    /// Remove every lease held by `session` and return them.
    pub fn release_session(&mut self, session: &str) -> rusqlite::Result<Vec<LeaseInfo>> {
        let gone = self.query_leases("session = ?1", [session])?;
        self.conn
            .execute("DELETE FROM leases WHERE session = ?1", [session])?;
        Ok(gone)
    }

    pub fn leases(&self, now: u64) -> rusqlite::Result<Vec<LeaseInfo>> {
        let now = clamp_now(now);
        self.query_leases("expires > ?1", [now as i64])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn h(s: &'static str) -> Holder<'static> {
        Holder {
            session: s,
            user: "u",
            machine: "m",
        }
    }

    fn granted(a: Acquired) -> LeaseInfo {
        match a {
            Acquired::Granted { lease, .. } => lease,
            other => panic!("expected grant, got {other:?}"),
        }
    }

    #[test]
    fn log_is_ordered_and_resumable() {
        let mut s = Store::open_memory().unwrap();
        for i in 0..5 {
            let e = s.append(i, "k", "u", "m", "s", json!({ "i": i })).unwrap();
            assert_eq!(e.seq, i + 1);
        }
        assert_eq!(s.head().unwrap(), 5);
        let after: Vec<u64> = s
            .events_after(2, 100)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(after, vec![3, 4, 5]);
        assert_eq!(s.events_after(0, 2).unwrap().len(), 2);
        let recent: Vec<u64> = s.recent(2).unwrap().iter().map(|e| e.seq).collect();
        assert_eq!(recent, vec![4, 5]);
        assert_eq!(s.cursor("u@m").unwrap(), None);
        s.set_cursor("u@m", 4).unwrap();
        assert_eq!(s.cursor("u@m").unwrap(), Some(4));
    }

    #[test]
    fn tokens_increase_on_every_grant() {
        let mut s = Store::open_memory().unwrap();
        let a = granted(s.acquire(0, &h("A"), "r", "x", 1000).unwrap());
        let b = granted(s.acquire(0, &h("B"), "r", "y", 1000).unwrap());
        assert!(b.token > a.token);
        // Re-acquiring your own lease extends it and keeps the token.
        match s.acquire(500, &h("A"), "r", "x", 1000).unwrap() {
            Acquired::Granted { lease, fresh } => {
                assert!(!fresh);
                assert_eq!(lease.token, a.token);
                assert_eq!(lease.expires, 1500);
            }
            o => panic!("{o:?}"),
        }
        s.release(600, "A", "r", "x", a.token).unwrap().unwrap();
        let a2 = granted(s.acquire(700, &h("A"), "r", "x", 1000).unwrap());
        assert!(a2.token > b.token);
    }

    #[test]
    fn transfer_refuses_to_break_mutual_exclusion() {
        let mut s = Store::open_memory().unwrap();
        // Reach a state where A's glob and B's path coexist (as after a crash or older hub).
        s.put(&LeaseInfo {
            repo: "r".into(),
            scope: "src/**".into(),
            session: "A".into(),
            user: "u".into(),
            machine: "m".into(),
            token: 1,
            since: 0,
            expires: 10_000,
        })
        .unwrap();
        s.put(&LeaseInfo {
            repo: "r".into(),
            scope: "src/a.rs".into(),
            session: "B".into(),
            user: "u".into(),
            machine: "m".into(),
            token: 2,
            since: 0,
            expires: 10_000,
        })
        .unwrap();
        match s.transfer(10, "A", "r", "src/**", &h("C"), 1000).unwrap() {
            Err(LeaseError::Conflict(l)) => assert_eq!(l.session, "B"),
            o => panic!("{o:?}"),
        }
        assert_eq!(s.lease(10, "r", "src/**").unwrap().unwrap().session, "A");
        // Handing it to the session that holds the overlapping lease is fine.
        let (t, released) = s
            .transfer(10, "A", "r", "src/**", &h("B"), 1000)
            .unwrap()
            .unwrap();
        assert_eq!(t.session, "B");
        // B's own lease is not the grantor's: it stays.
        assert!(released.is_empty());
        assert_eq!(s.lease(10, "r", "src/a.rs").unwrap().unwrap().session, "B");
    }

    #[test]
    fn grantors_own_sub_lease_does_not_block_its_transfer() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("A"), "r", "src/**", 1000).unwrap());
        granted(s.acquire(0, &h("A"), "r", "src/a.rs", 1000).unwrap());
        let (t, released) = s
            .transfer(10, "A", "r", "src/**", &h("B"), 1000)
            .unwrap()
            .unwrap();
        assert_eq!(t.session, "B");
        // The grantor's sub-lease inside the scope went with it, and is reported.
        assert_eq!(s.lease(10, "r", "src/a.rs").unwrap(), None);
        assert_eq!(
            released
                .iter()
                .map(|l| l.scope.as_str())
                .collect::<Vec<_>>(),
            ["src/a.rs"]
        );
    }

    #[test]
    fn transfer_never_silently_drops_a_broader_grantor_lease() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("A"), "r", "src/**", 1000).unwrap());
        granted(s.acquire(0, &h("A"), "r", "src/hub/*", 1000).unwrap());
        match s
            .transfer(10, "A", "r", "src/hub/*", &h("B"), 1000)
            .unwrap()
        {
            Err(LeaseError::GrantorHoldsBroader(l)) => assert_eq!(l.scope, "src/**"),
            o => panic!("{o:?}"),
        }
        // Nothing changed.
        assert_eq!(s.lease(10, "r", "src/**").unwrap().unwrap().session, "A");
        assert_eq!(s.lease(10, "r", "src/hub/*").unwrap().unwrap().session, "A");
    }

    #[test]
    fn transfer_releases_covered_sub_leases() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("A"), "r", "src/hub/*", 1000).unwrap());
        granted(s.acquire(0, &h("A"), "r", "src/hub/a.rs", 1000).unwrap());
        let (t, released) = s
            .transfer(10, "A", "r", "src/hub/*", &h("B"), 1000)
            .unwrap()
            .unwrap();
        assert_eq!(t.session, "B");
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].scope, "src/hub/a.rs");
        assert_eq!(s.lease(10, "r", "src/hub/a.rs").unwrap(), None);
    }

    fn pending(s: &mut Store, paths: &[&str]) -> u64 {
        let d = Delegation {
            info: DelegationInfo {
                from_session: "A".into(),
                from_user: "u".into(),
                from_machine: "m".into(),
                to_session: "B".into(),
                to_user: "u".into(),
                to_machine: "m".into(),
                repo: "r".into(),
                task_id: "T".into(),
                kind: "tests".into(),
                status: "pending".into(),
                ..Default::default()
            },
            paths: paths.iter().map(|p| p.to_string()).collect(),
            result_fields: vec!["sha".into()],
        };
        s.delegate(100, "u", "m", "A", json!({}), d).unwrap().0.seq
    }

    #[test]
    fn accepting_hands_leases_off_atomically() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("A"), "r", "src/a.rs", 100_000).unwrap());
        let req = pending(&mut s, &["src/**"]);
        let a = s
            .ack_delegation(1000, "B", req, true, "scoped-bypass", 5000)
            .unwrap()
            .unwrap();
        assert!(a.fresh);
        assert_eq!(a.released.len(), 1);
        assert_eq!(a.granted.len(), 1);
        assert_eq!(s.lease(1000, "r", "src/a.rs").unwrap(), None);
        assert_eq!(s.lease(1000, "r", "src/**").unwrap().unwrap().session, "B");
        // A second ack returns the stored outcome and changes nothing.
        let again = s
            .ack_delegation(1001, "B", req, false, "inform", 0)
            .unwrap()
            .unwrap();
        assert!(!again.fresh);
        assert_eq!(again.info.status, "accepted");
        assert_eq!(
            s.ack_delegation(1001, "A", req, true, "scoped-bypass", 0)
                .unwrap()
                .unwrap_err(),
            AckError::NotRecipient
        );
        // The result needs every required field and gives the leases back.
        let none = serde_json::Map::new();
        assert!(s
            .finish_delegation("B", req, "done", "ok", &none)
            .unwrap()
            .unwrap_err()
            .contains("missing result field sha"));
        let mut f = serde_json::Map::new();
        f.insert("sha".into(), json!("abc"));
        let (d, released) = s
            .finish_delegation("B", req, "done", "ok", &f)
            .unwrap()
            .unwrap();
        assert_eq!(d.info.status, "done");
        assert_eq!(released.len(), 1);
        assert_eq!(s.lease(1002, "r", "src/**").unwrap(), None);
        assert!(s
            .finish_delegation("B", req, "done", "ok", &f)
            .unwrap()
            .unwrap_err()
            .contains("no open request"));
    }

    #[test]
    fn a_conflicting_hand_off_changes_nothing() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("C"), "r", "src/b.rs", 100_000).unwrap());
        // A third session overlaps the scope.
        let req = pending(&mut s, &["src/**"]);
        let e = s
            .ack_delegation(10, "B", req, true, "scoped-instruction", 5000)
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(e, AckError::Conflict(ref m) if m.starts_with("conflict:")),
            "{e:?}"
        );
        // The sender's lease is broader than the path: also refused, nothing released.
        s.release_session("C").unwrap();
        granted(s.acquire(0, &h("A"), "r", "src/", 100_000).unwrap());
        let req2 = pending(&mut s, &["src/a.rs"]);
        let e = s
            .ack_delegation(10, "B", req2, true, "scoped-instruction", 5000)
            .unwrap()
            .unwrap_err();
        assert!(matches!(e, AckError::Conflict(_)), "{e:?}");
        assert_eq!(s.lease(10, "r", "src/").unwrap().unwrap().session, "A");
        assert_eq!(s.delegation(req2).unwrap().unwrap().info.status, "pending");
        // Unanswered for too long: expired.
        assert_eq!(
            s.ack_delegation(100 + DELEGATION_PENDING_MS + 1, "B", req2, false, "off", 0)
                .unwrap()
                .unwrap_err(),
            AckError::Expired
        );
        assert_eq!(s.delegation(req2).unwrap().unwrap().info.status, "expired");
    }

    #[test]
    fn ttl_is_clamped_and_cannot_overflow() {
        let mut s = Store::open_memory().unwrap();
        let now = 1_000_000;
        let a = granted(s.acquire(now, &h("A"), "r", "f", u64::MAX).unwrap());
        assert_eq!(a.expires, now + MAX_TTL_MS);
        let b = granted(s.acquire(now, &h("B"), "r", "g", 0).unwrap());
        assert_eq!(b.expires, now + MIN_TTL_MS);
        let c = granted(s.acquire(now, &h("C"), "r", "h", (-1i64) as u64).unwrap());
        assert_eq!(c.expires, now + MAX_TTL_MS);
        let r = s
            .renew(now, "A", "r", "f", a.token, u64::MAX - 5)
            .unwrap()
            .unwrap();
        assert_eq!(r.expires, now + MAX_TTL_MS);
        let (t, _) = s
            .transfer(now, "B", "r", "g", &h("D"), u64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(t.expires, now + MAX_TTL_MS);
        // A clock near the end of time saturates instead of wrapping or overflowing i64.
        let late = granted(s.acquire(u64::MAX - 1, &h("E"), "r", "z", 1000).unwrap());
        assert_eq!(late.expires, i64::MAX as u64);
        assert_eq!(
            s.lease(u64::MAX - 1, "r", "z").unwrap().unwrap().expires,
            i64::MAX as u64
        );
    }

    #[test]
    fn conflicting_acquire_reports_holder() {
        let mut s = Store::open_memory().unwrap();
        let a = granted(s.acquire(0, &h("A"), "r", "src/**", 1000).unwrap());
        match s.acquire(10, &h("B"), "r", "src/a.rs", 1000).unwrap() {
            Acquired::Held(l) => assert_eq!(l, a),
            o => panic!("{o:?}"),
        }
        // Different repo does not conflict.
        granted(s.acquire(10, &h("B"), "other", "src/a.rs", 1000).unwrap());
    }

    #[test]
    fn fencing_rejects_stale_holder() {
        let mut s = Store::open_memory().unwrap();
        let a = granted(s.acquire(0, &h("A"), "r", "f", 100).unwrap());
        assert_eq!(s.expire(200).unwrap().len(), 1);
        let b = granted(s.acquire(200, &h("B"), "r", "f", 1000).unwrap());
        assert!(b.token > a.token);
        // A comes back with its old token: every operation is refused and B is untouched.
        assert_eq!(
            s.renew(250, "A", "r", "f", a.token, 1000).unwrap(),
            Err(LeaseError::StaleToken)
        );
        assert_eq!(
            s.release(250, "A", "r", "f", a.token).unwrap(),
            Err(LeaseError::StaleToken)
        );
        assert_eq!(s.lease(250, "r", "f").unwrap(), Some(b.clone()));
        // Even with the right token, only the holder may act.
        assert_eq!(
            s.release(250, "A", "r", "f", b.token).unwrap(),
            Err(LeaseError::NotHolder)
        );
        assert_eq!(
            s.renew(250, "B", "r", "nope", b.token, 1000).unwrap(),
            Err(LeaseError::NotHeld)
        );
    }

    #[test]
    fn expired_lease_is_not_held_even_before_sweep() {
        let mut s = Store::open_memory().unwrap();
        let a = granted(s.acquire(0, &h("A"), "r", "f", 100).unwrap());
        assert_eq!(s.lease(150, "r", "f").unwrap(), None);
        let b = granted(s.acquire(150, &h("B"), "r", "f", 100).unwrap());
        assert!(b.token > a.token);
        assert_eq!(
            s.renew(160, "A", "r", "f", a.token, 100).unwrap(),
            Err(LeaseError::StaleToken)
        );
    }

    #[test]
    fn transfer_issues_new_token_to_recipient() {
        let mut s = Store::open_memory().unwrap();
        let a = granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap());
        assert_eq!(
            s.transfer(10, "B", "r", "f", &h("C"), 1000).unwrap(),
            Err(LeaseError::NotHolder)
        );
        let (b, _) = s
            .transfer(10, "A", "r", "f", &h("B"), 1000)
            .unwrap()
            .unwrap();
        assert_eq!(b.session, "B");
        assert!(b.token > a.token);
        assert_eq!(
            s.renew(20, "A", "r", "f", a.token, 1000).unwrap(),
            Err(LeaseError::StaleToken)
        );
    }

    #[test]
    fn release_session_drops_all_its_leases() {
        let mut s = Store::open_memory().unwrap();
        granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap());
        granted(s.acquire(0, &h("A"), "r", "g", 1000).unwrap());
        granted(s.acquire(0, &h("B"), "r", "h", 1000).unwrap());
        assert_eq!(s.release_session("A").unwrap().len(), 2);
        assert_eq!(s.leases(0).unwrap().len(), 1);
    }

    #[test]
    fn database_files_are_private_under_a_default_umask() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("wh-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        // SAFETY: umask only sets the process file-creation mask.
        let old = unsafe { libc::umask(0o022) };
        let p = d.join("db/hub.sqlite");
        let s = Store::open(&p).unwrap();
        s.append(1, "k", "u", "m", "s", json!({})).unwrap();
        unsafe { libc::umask(old) };
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        for ext in ["-wal", "-shm"] {
            let f = std::path::PathBuf::from(format!("{}{ext}", p.display()));
            assert_eq!(mode(&f), 0o600, "{ext}");
        }
        assert_eq!(mode(&d.join("db")), 0o700);
        drop(s);
        // A directory others can write to is refused.
        let open = d.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Store::open(&open.join("hub.sqlite")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn state_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("wh-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("hub.sqlite");
        let t1 = {
            let mut s = Store::open(&p).unwrap();
            s.append(1, "k", "u", "m", "s", json!({})).unwrap();
            granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap()).token
        };
        let mut s = Store::open(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(s.head().unwrap(), 1);
        s.release_session("A").unwrap();
        let t2 = granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap()).token;
        assert!(t2 > t1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
