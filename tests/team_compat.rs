//! Wire compatibility of the team-log and update additions with the frozen `main` protocol
//! (tests/fixtures/proto_v0.rs), and fake hubs that must never see a frame they cannot parse.

mod common;

#[allow(dead_code)]
#[path = "fixtures/proto_v0.rs"]
mod v0;

use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use wormhole::proto::{
    self, Contract, DaemonInfo, Down, LogEntry, LogQuery, Request, Snapshot, Up,
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn the_capability_names_are_pinned() {
    assert_eq!(proto::CAP_TEAM_LOG, "team-log");
    assert_eq!(proto::CAP_UPDATE, "update");
    assert_eq!(proto::CAP_DELEGATION, "delegation");
}

#[test]
fn a_new_welcome_parses_as_the_old_type_and_an_old_welcome_as_the_new_one() {
    let caps = vec![
        proto::CAP_DELEGATION.to_string(),
        proto::CAP_TEAM_LOG.to_string(),
        proto::CAP_UPDATE.to_string(),
    ];
    for target in [None, Some(SHA.to_string())] {
        let s = serde_json::to_string(&Down::Welcome {
            user: "alice".into(),
            machine: "machine-a".into(),
            head: 4,
            caps: caps.clone(),
            target: target.clone(),
        })
        .unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["op"], "welcome");
        assert_eq!(v["caps"], json!(caps));
        match &target {
            Some(t) => assert_eq!(v["target"], *t),
            None => assert!(
                v.get("target").is_none(),
                "an absent target is not serialised: {s}"
            ),
        }
        match serde_json::from_str::<v0::Down>(&s).unwrap() {
            v0::Down::Welcome {
                user,
                machine,
                head,
            } => assert_eq!(
                (user.as_str(), machine.as_str(), head),
                ("alice", "machine-a", 4)
            ),
            _ => panic!("not a welcome"),
        }
        match serde_json::from_str::<Down>(&s).unwrap() {
            Down::Welcome {
                target: t, caps: c, ..
            } => assert_eq!((t, c), (target, caps.clone())),
            other => panic!("{other:?}"),
        }
    }
    // What a hub from before the slice sends.
    let old = r#"{"op":"welcome","user":"alice","machine":"machine-a","head":9}"#;
    match serde_json::from_str::<Down>(old).unwrap() {
        Down::Welcome {
            caps, target, head, ..
        } => {
            assert!(caps.is_empty() && target.is_none());
            assert_eq!(head, 9);
        }
        other => panic!("{other:?}"),
    }
    // And one from the delegation slice (caps, no target).
    let mid =
        r#"{"op":"welcome","user":"alice","machine":"machine-a","head":9,"caps":["delegation"]}"#;
    match serde_json::from_str::<Down>(mid).unwrap() {
        Down::Welcome { caps, target, .. } => {
            assert_eq!(caps, ["delegation"]);
            assert!(target.is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn target_frames_parse_with_and_without_a_commit_and_old_daemons_cannot_parse_them() {
    for (raw, want) in [
        (
            format!(r#"{{"op":"target","commit":"{SHA}"}}"#),
            Some(SHA.to_string()),
        ),
        (r#"{"op":"target","commit":null}"#.to_string(), None),
        (r#"{"op":"target"}"#.to_string(), None),
    ] {
        match serde_json::from_str::<Down>(&raw).unwrap() {
            Down::Target { commit } => assert_eq!(commit, want, "{raw}"),
            other => panic!("{raw}: {other:?}"),
        }
        // This is why the hub sends it only to connections that advertised `update`: an old
        // daemon's parser refuses it (and ignores the frame).
        assert!(serde_json::from_str::<v0::Down>(&raw).is_err(), "{raw}");
    }
    let s = serde_json::to_string(&Down::Target {
        commit: Some(SHA.into()),
    })
    .unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(
        (v["op"].as_str(), v["commit"].as_str()),
        (Some("target"), Some(SHA))
    );
}

#[test]
fn a_snapshot_with_daemons_parses_as_old_and_an_empty_list_is_not_serialised() {
    let d = DaemonInfo {
        user: "alice".into(),
        machine: "machine-a".into(),
        commit: SHA.into(),
        target: String::new(),
        status: "current".into(),
        ts: 5,
        ..Default::default()
    };
    let s = serde_json::to_string(&Snapshot {
        daemons: vec![d.clone()],
        ..Default::default()
    })
    .unwrap();
    assert!(s.contains("daemons") && s.contains("machine-a"), "{s}");
    let old: v0::Snapshot = serde_json::from_str(&s).unwrap();
    assert!(old.sessions.is_empty() && old.leases.is_empty());
    let new: Snapshot = serde_json::from_str(&s).unwrap();
    assert_eq!(new.daemons, vec![d]);

    let s = serde_json::to_string(&Snapshot::default()).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert!(v.get("daemons").is_none(), "{s}");
    assert!(v.get("delegations").is_none(), "{s}");
    // A snapshot from a hub that knows no daemons.
    let s: Snapshot = serde_json::from_str(r#"{"sessions":[],"leases":[]}"#).unwrap();
    assert!(s.daemons.is_empty());
}

#[test]
fn contract_ref_goes_on_the_wire_as_ref_and_only_when_set() {
    let c = Contract {
        task_id: "T-1".into(),
        kind: "review".into(),
        text: "x".into(),
        reference: "https://example.com/org/repo/pull/7".into(),
        ..Default::default()
    };
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["ref"], "https://example.com/org/repo/pull/7");
    assert!(v.get("reference").is_none(), "{v}");
    assert_eq!(serde_json::from_value::<Contract>(v.clone()).unwrap(), c);
    // Inside a delegate request too.
    let r = serde_json::to_value(&Request::Delegate {
        session: "s".into(),
        to: "t".into(),
        repo: "r".into(),
        contract: c.clone(),
    })
    .unwrap();
    assert_eq!(r["contract"]["ref"], v["ref"]);

    let empty = Contract {
        reference: String::new(),
        ..c.clone()
    };
    let v = serde_json::to_value(&empty).unwrap();
    assert!(v.as_object().unwrap().get("ref").is_none(), "{v}");
    assert!(!serde_json::to_string(&empty).unwrap().contains("ref"));
    // A contract from before the slice has no ref.
    let old = r#"{"task_id":"T-1","kind":"fix","text":"x"}"#;
    assert_eq!(serde_json::from_str::<Contract>(old).unwrap().reference, "");
    let old = r#"{"task_id":"T-1","kind":"fix","text":"x","ref":""}"#;
    assert_eq!(serde_json::from_str::<Contract>(old).unwrap().reference, "");
}

#[test]
fn log_and_daemon_status_requests_have_their_pinned_shape_and_old_hubs_cannot_parse_them() {
    let q = LogQuery {
        since: Some(5),
        session: Some("s".into()),
        user: Some("alice".into()),
        kind: Some("msg".into()),
        task_id: Some("T-1".into()),
        limit: 7,
    };
    let v = serde_json::to_value(&Request::Log {
        session: "sess".into(),
        query: q.clone(),
    })
    .unwrap();
    assert_eq!(v["type"], "log");
    assert_eq!(v["session"], "sess");
    assert_eq!(
        v["query"],
        json!({"since": 5, "session": "s", "user": "alice", "kind": "msg", "task_id": "T-1",
               "limit": 7})
    );
    // A query may omit any field; a bare request has the default query.
    for raw in [
        r#"{"type":"log","session":"sess"}"#,
        r#"{"type":"log","session":"sess","query":{}}"#,
    ] {
        match serde_json::from_str::<Request>(raw).unwrap() {
            Request::Log { session, query } => {
                assert_eq!(session, "sess");
                assert_eq!(query, LogQuery::default());
                assert_eq!(query.limit, 0);
            }
            other => panic!("{other:?}"),
        }
    }
    match serde_json::from_str::<Request>(
        r#"{"type":"log","session":"s","query":{"limit":7,"since":3}}"#,
    )
    .unwrap()
    {
        Request::Log { query, .. } => {
            assert_eq!((query.limit, query.since, query.kind), (7, Some(3), None))
        }
        other => panic!("{other:?}"),
    }

    let st = Request::DaemonStatus {
        commit: SHA.into(),
        target: String::new(),
        status: "current".into(),
        downgrade: false,
    };
    let sv = serde_json::to_value(&st).unwrap();
    for (k, want) in [
        ("type", json!("daemon_status")),
        ("commit", json!(SHA)),
        ("target", json!("")),
        ("status", json!("current")),
    ] {
        assert_eq!(sv[k], want, "{k}: {sv}");
    }
    // A report from before the amendment has no downgrade flag.
    let old = r#"{"type":"daemon_status","commit":"a","target":"","status":"current"}"#;
    match serde_json::from_str::<Request>(old).unwrap() {
        Request::DaemonStatus { downgrade, .. } => assert!(!downgrade),
        other => panic!("{other:?}"),
    }
    match serde_json::from_value::<Request>(sv.clone()).unwrap() {
        Request::DaemonStatus { commit, status, .. } => {
            assert_eq!((commit.as_str(), status.as_str()), (SHA, "current"))
        }
        other => panic!("{other:?}"),
    }
    for r in [v, sv] {
        assert!(
            serde_json::from_value::<v0::Request>(r.clone()).is_err(),
            "{r}"
        );
        let framed = json!({"op": "req", "id": 1, "req": r});
        assert!(serde_json::from_value::<v0::Up>(framed).is_err());
    }

    // The entry and info types round-trip.
    let e = LogEntry {
        seq: 3,
        ts: 4,
        kind: "msg".into(),
        repo: "example.com/team/proj".into(),
        from_session: "a".into(),
        from_user: "alice".into(),
        from_machine: "machine-a".into(),
        to: "all".into(),
        to_user: String::new(),
        task_id: String::new(),
        text: "hello".into(),
        data: json!({"body": "hello"}),
    };
    let back: LogEntry = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(back, e);
}

#[test]
fn a_resume_with_the_new_capabilities_still_parses_as_the_old_resume() {
    let s = serde_json::to_string(&Up::Resume {
        from: Some(3),
        caps: vec![
            proto::CAP_DELEGATION.into(),
            proto::CAP_TEAM_LOG.into(),
            proto::CAP_UPDATE.into(),
        ],
    })
    .unwrap();
    assert!(s.contains("team-log") && s.contains("update"), "{s}");
    match serde_json::from_str::<v0::Up>(&s).unwrap() {
        v0::Up::Resume { from } => assert_eq!(from, Some(3)),
        _ => panic!("not a resume"),
    }
}

/// A hub that answers `Resume` with `welcome` and every request with an empty success, except
/// `snapshot` and `log`. Records every text frame it receives.
async fn fake_hub(welcome: Value) -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let rec = frames.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (rec, welcome) = (rec.clone(), welcome.clone());
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(s).await else {
                    return;
                };
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(m)) = rx.next().await {
                    let Message::Text(t) = m else { continue };
                    let t = t.to_string();
                    rec.lock().unwrap().push(t.clone());
                    let v: Value = serde_json::from_str(&t).unwrap_or_default();
                    let out = match v["op"].as_str() {
                        Some("resume") => welcome.clone(),
                        Some("req") => {
                            let data = match v["req"]["type"].as_str() {
                                Some("snapshot") => json!({"sessions": [], "leases": []}),
                                Some("log") => json!({"entries": [], "more": false}),
                                _ => json!({}),
                            };
                            json!({"op":"resp","id":v["id"],"ok":true,"data":data})
                        }
                        _ => continue,
                    };
                    if tx
                        .send(Message::Text(out.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (addr, frames)
}

fn welcome(caps: &[&str], target: Option<&str>) -> Value {
    let mut w = json!({"op": "welcome", "user": "alice", "machine": "machine-a", "head": 0});
    if !caps.is_empty() {
        w["caps"] = json!(caps);
    }
    if let Some(t) = target {
        w["target"] = json!(t);
    }
    w
}

/// Requests of type `t` the fake hub received.
fn reqs(frames: &Arc<Mutex<Vec<String>>>, t: &str) -> Vec<Value> {
    frames
        .lock()
        .unwrap()
        .iter()
        .filter_map(|f| serde_json::from_str::<Value>(f).ok())
        .filter(|v| v["op"] == "req" && v["req"]["type"] == t)
        .map(|v| v["req"].clone())
        .collect()
}

#[tokio::test]
async fn a_daemon_never_sends_log_or_daemon_status_unless_the_hub_advertised_the_capability() {
    for (caps, log_ok, status_ok) in [
        (vec![], false, false),
        (vec!["delegation"], false, false),
        (vec!["team-log"], true, false),
        (vec!["update"], false, true),
        (vec!["delegation", "team-log", "update"], true, true),
    ] {
        let (addr, frames) = fake_hub(welcome(&caps, Some(SHA))).await;
        let dir = tmpdir();
        let mut cfg = daemon_config(
            &dir,
            format!("ws://{addr}/ws"),
            "alice@machine-a",
            &Opts::default(),
        );
        // An updater that has nowhere to go: the status would be `current` or `waiting` at most.
        cfg.auto_update = Some(wormhole::update::UpdateConfig::new(
            dir.join("no-src"),
            dir.join("bin"),
        ));
        let d = wormhole::daemon::start(cfg).await.unwrap();
        wait_connected(&d).await;
        let repo = make_repo(&dir.join("a/proj"));
        hook(&d, session_start(SA, &repo)).await;
        let r = tool(&d, SA, "log", json!({})).await;
        if log_ok {
            assert_eq!(r.unwrap().trim(), "No team log entries match.", "{caps:?}");
        } else {
            let e = r.unwrap_err();
            assert!(e.contains("does not support the team log"), "{caps:?}: {e}");
        }
        tokio::time::sleep(Duration::from_millis(600)).await;

        assert_eq!(reqs(&frames, "log").len(), usize::from(log_ok), "{caps:?}");
        let status = reqs(&frames, "daemon_status");
        if status_ok {
            assert!(
                !status.is_empty(),
                "{caps:?}: no daemon_status after Welcome"
            );
            let first = &status[0];
            assert_eq!(first["commit"], wormhole::COMMIT, "{first}");
            assert!(
                first["status"].as_str().is_some_and(|s| !s.is_empty()),
                "{first}"
            );
            // A status never carries a local path.
            for s in &status {
                let text = s.to_string();
                assert!(!text.contains(dir.to_str().unwrap()), "{text}");
            }
        } else {
            assert!(status.is_empty(), "{caps:?}: {status:?}");
        }
        // The daemon always lists what it can do, and `delegation` only with a policy.
        let first: Value =
            serde_json::from_str(frames.lock().unwrap().first().expect("no resume")).unwrap();
        assert_eq!(first["op"], "resume");
        let have: Vec<&str> = first["caps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert!(
            have.contains(&"team-log") && have.contains(&"update"),
            "{have:?}"
        );
        assert!(!have.contains(&"delegation"), "{have:?}");
        d.shutdown().await;
    }
}

#[tokio::test]
async fn a_daemon_without_an_updater_reports_disabled_with_the_hubs_target() {
    let (addr, frames) = fake_hub(welcome(&["team-log", "update"], Some(SHA))).await;
    let dir = tmpdir();
    let d = wormhole::daemon::start(daemon_config(
        &dir,
        format!("ws://{addr}/ws"),
        "alice@machine-a",
        &Opts::default(),
    ))
    .await
    .unwrap();
    wait_connected(&d).await;
    let s = eventually(5, || async {
        reqs(&frames, "daemon_status").into_iter().last()
    })
    .await;
    assert_eq!(s["commit"], wormhole::COMMIT);
    assert_eq!(s["target"], SHA);
    assert!(s["status"].as_str().unwrap().starts_with("disabled"), "{s}");
}
