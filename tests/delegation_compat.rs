//! Wire compatibility between the delegation protocol and the frozen `main` protocol
//! (tests/fixtures/proto_v0.rs), plus a fake old hub that must never see a delegation frame.

mod common;

#[allow(dead_code)]
#[path = "fixtures/proto_v0.rs"]
mod v0;

use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use wormhole::proto::{self, Contract, DelegationInfo, Down, Request, Snapshot, Up};

const SA: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SB: &str = "bbbbbbbb-0000-4000-8000-000000000002";

#[test]
fn old_frames_parse_as_new_types_with_empty_additions() {
    let up: Up = serde_json::from_str(r#"{"op":"resume","from":5}"#).unwrap();
    match up {
        Up::Resume { from, caps } => {
            assert_eq!(from, Some(5));
            assert!(caps.is_empty());
        }
        other => panic!("{other:?}"),
    }
    let down: Down =
        serde_json::from_str(r#"{"op":"welcome","user":"alice","machine":"machine-a","head":9}"#)
            .unwrap();
    match down {
        Down::Welcome {
            user,
            machine,
            head,
            caps,
        } => {
            assert_eq!(
                (user.as_str(), machine.as_str(), head),
                ("alice", "machine-a", 9)
            );
            assert!(caps.is_empty());
        }
        other => panic!("{other:?}"),
    }
    let snap: Snapshot = serde_json::from_str(r#"{"sessions":[],"leases":[]}"#).unwrap();
    assert!(snap.delegations.is_empty());
}

#[test]
fn new_frames_with_caps_and_delegations_parse_as_old_types() {
    let up = serde_json::to_string(&Up::Resume {
        from: Some(3),
        caps: vec![proto::CAP_DELEGATION.to_string()],
    })
    .unwrap();
    assert!(up.contains("delegation"), "{up}");
    match serde_json::from_str::<v0::Up>(&up).unwrap() {
        v0::Up::Resume { from } => assert_eq!(from, Some(3)),
        _ => panic!("not a resume"),
    }

    let down = serde_json::to_string(&Down::Welcome {
        user: "alice".into(),
        machine: "machine-a".into(),
        head: 4,
        caps: vec![proto::CAP_DELEGATION.to_string()],
    })
    .unwrap();
    assert!(down.contains("delegation"), "{down}");
    match serde_json::from_str::<v0::Down>(&down).unwrap() {
        v0::Down::Welcome { head, .. } => assert_eq!(head, 4),
        _ => panic!("not a welcome"),
    }

    let snap = serde_json::to_string(&Snapshot {
        delegations: vec![DelegationInfo {
            seq: 7,
            task_id: "T-1".into(),
            status: "accepted".into(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .unwrap();
    assert!(snap.contains("T-1"), "{snap}");
    let old: v0::Snapshot = serde_json::from_str(&snap).unwrap();
    assert!(old.sessions.is_empty() && old.leases.is_empty());
}

#[test]
fn new_request_variants_do_not_parse_as_old_requests() {
    // This is why a daemon must not send them to a hub that did not advertise the capability:
    // an old hub cannot parse the frame and drops the connection.
    let reqs = [
        Request::Delegate {
            session: SA.into(),
            to: SB.into(),
            repo: "example.com/team/proj".into(),
            contract: Contract {
                task_id: "T-1".into(),
                kind: "tests".into(),
                text: "x".into(),
                ..Default::default()
            },
        },
        Request::DelegateAck {
            session: SB.into(),
            request: 1,
            accept: true,
            level: "scoped-instruction".into(),
            reason: String::new(),
            ttl_ms: 1000,
        },
        Request::DelegateResult {
            session: SB.into(),
            request: 1,
            status: "done".into(),
            summary: "s".into(),
            fields: Default::default(),
        },
    ];
    for r in reqs {
        let v = serde_json::to_value(&r).unwrap();
        assert!(
            serde_json::from_value::<v0::Request>(v.clone()).is_err(),
            "old Request parsed {v}"
        );
        let framed = json!({"op": "req", "id": 1, "req": v});
        assert!(serde_json::from_value::<v0::Up>(framed).is_err());
    }
}

/// A hub from before delegation: a v0 Welcome without caps, every request answered ok with
/// empty data. Records every text frame it receives.
async fn fake_old_hub() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let rec = frames.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let rec = rec.clone();
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
                        Some("resume") => {
                            json!({"op":"welcome","user":"alice","machine":"machine-a","head":0})
                        }
                        Some("req") => {
                            let data = if v["req"]["type"] == "snapshot" {
                                json!({"sessions": [], "leases": []})
                            } else {
                                json!({})
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

#[tokio::test]
async fn daemon_never_sends_delegation_frames_to_an_old_hub() {
    let (addr, frames) = fake_old_hub().await;
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
    let repo = make_repo(&dir.join("a/proj"));
    hook(&d, session_start(SA, &repo)).await;
    let e = tool(
        &d,
        SA,
        "delegate",
        json!({"to_session": SB, "to": SB, "task_id": "T-1", "kind": "tests", "text": "x",
               "paths": ["src/a.rs"]}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("does not support delegation"), "{e}");
    let seen = frames.lock().unwrap().join("\n").to_lowercase();
    assert!(seen.contains("resume") && seen.contains("hello"), "{seen}");
    assert!(!seen.contains("delegate"), "{seen}");
}

#[tokio::test]
async fn daemon_without_a_policy_refuses_delegated_tasks_through_a_real_hub() {
    let n = net(Opts::default()).await;
    hook(&n.a, session_start(SA, &n.repo_a)).await;
    hook(&n.b, session_start(SB, &n.repo_b)).await;
    let e = tool(
        &n.a,
        SA,
        "delegate",
        json!({"to_session": SB, "to": SB, "task_id": "T-1", "kind": "tests", "text": "x",
               "paths": ["src/a.rs"]}),
    )
    .await
    .unwrap_err();
    assert!(e.contains("does not accept delegated tasks"), "{e}");
}
