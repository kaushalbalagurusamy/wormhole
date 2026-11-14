//! The hub's durable state in SQLite: the ordered event log, leases with fencing tokens,
//! and per-machine delivery cursors. Times are passed in so tests control the clock.

use crate::proto::{Event, LeaseInfo};
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
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let _ = path;
        todo!()
    }

    pub fn open_memory() -> rusqlite::Result<Store> {
        todo!()
    }

    pub fn append(
        &mut self,
        ts: u64,
        kind: &str,
        user: &str,
        machine: &str,
        session: &str,
        data: Value,
    ) -> rusqlite::Result<Event> {
        let _ = (ts, kind, user, machine, session, data, &self.conn);
        todo!()
    }

    pub fn head(&self) -> rusqlite::Result<u64> {
        todo!()
    }

    pub fn events_after(&self, seq: u64, limit: usize) -> rusqlite::Result<Vec<Event>> {
        let _ = (seq, limit);
        todo!()
    }

    pub fn recent(&self, limit: usize) -> rusqlite::Result<Vec<Event>> {
        let _ = limit;
        todo!()
    }

    pub fn cursor(&self, key: &str) -> rusqlite::Result<Option<u64>> {
        let _ = key;
        todo!()
    }

    pub fn set_cursor(&mut self, key: &str, seq: u64) -> rusqlite::Result<()> {
        let _ = (key, seq);
        todo!()
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
        let _ = (now, who, repo, scope, ttl_ms);
        todo!()
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
        let _ = (now, session, repo, scope, token, ttl_ms);
        todo!()
    }

    pub fn release(
        &mut self,
        now: u64,
        session: &str,
        repo: &str,
        scope: &str,
        token: u64,
    ) -> rusqlite::Result<Result<LeaseInfo, LeaseError>> {
        let _ = (now, session, repo, scope, token);
        todo!()
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
    ) -> rusqlite::Result<Result<LeaseInfo, LeaseError>> {
        let _ = (now, holder_session, repo, scope, to, ttl_ms);
        todo!()
    }

    /// The live lease on exactly `scope`, if any.
    pub fn lease(&self, now: u64, repo: &str, scope: &str) -> rusqlite::Result<Option<LeaseInfo>> {
        let _ = (now, repo, scope);
        todo!()
    }

    /// Remove leases past their expiry and return them.
    pub fn expire(&mut self, now: u64) -> rusqlite::Result<Vec<LeaseInfo>> {
        let _ = now;
        todo!()
    }

    /// Remove every lease held by `session` and return them.
    pub fn release_session(&mut self, session: &str) -> rusqlite::Result<Vec<LeaseInfo>> {
        let _ = session;
        todo!()
    }

    pub fn leases(&self, now: u64) -> rusqlite::Result<Vec<LeaseInfo>> {
        let _ = now;
        todo!()
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
        let after: Vec<u64> = s.events_after(2, 100).unwrap().iter().map(|e| e.seq).collect();
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
        let b = s.transfer(10, "A", "r", "f", &h("B"), 1000).unwrap().unwrap();
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
    fn state_survives_reopen() {
        let p = std::env::temp_dir().join(format!("wh-store-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let t1 = {
            let mut s = Store::open(&p).unwrap();
            s.append(1, "k", "u", "m", "s", json!({})).unwrap();
            granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap()).token
        };
        let mut s = Store::open(&p).unwrap();
        assert_eq!(s.head().unwrap(), 1);
        s.release_session("A").unwrap();
        let t2 = granted(s.acquire(0, &h("A"), "r", "f", 1000).unwrap()).token;
        assert!(t2 > t1);
        std::fs::remove_file(&p).unwrap();
    }
}
