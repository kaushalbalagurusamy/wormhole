//! TLS on the daemon-to-hub link, and refusal of plaintext off the tailnet.

mod common;

use common::*;
use serde_json::json;
use std::time::Duration;
use wormhole::daemon;
use wormhole::hub::{self, identity::IdentityConfig, HubConfig, HubHandle};

const SA: &str = "aaaaaaaa-0000-4000-8000-0000000000a1";
const SB: &str = "bbbbbbbb-0000-4000-8000-0000000000b2";

async fn tls_hub(dir: &std::path::Path, files: wormhole::tls::TlsFiles) -> HubHandle {
    hub::start(HubConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        db: dir.join("hub.sqlite"),
        identity: IdentityConfig::Static,
        hostnames: vec![],
        allow_users: vec![],
        tls: Some(files),
        log_max_entries: wormhole::hub::DEFAULT_LOG_MAX_ENTRIES,
        log_max_age_secs: wormhole::hub::DEFAULT_LOG_MAX_AGE_SECS,
        target_file: None,
    })
    .await
    .unwrap()
}

fn tls_daemon_config(
    dir: &std::path::Path,
    hub: &HubHandle,
    who: &str,
    roots: Vec<std::path::PathBuf>,
) -> daemon::DaemonConfig {
    let mut c = daemon_config(
        dir,
        format!("wss://localhost:{}/ws", hub.addr.port()),
        who,
        &Opts::default(),
    );
    c.extra_roots = roots;
    c
}

async fn never_connects(d: &daemon::DaemonHandle) {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        d.connects(),
        0,
        "daemon connected to a hub it should not trust"
    );
}

#[tokio::test]
async fn wss_round_trip_with_a_verified_certificate() {
    let dir = tmpdir();
    let ca = ca();
    let roots = vec![write_ca(&ca, &dir.join("ca.pem"))];
    let hub = tls_hub(&dir, leaf(&ca, &["localhost"], false, &dir.join("cert"))).await;
    let a = daemon::start(tls_daemon_config(
        &dir,
        &hub,
        "alice@machine-a",
        roots.clone(),
    ))
    .await
    .unwrap();
    let b = daemon::start(tls_daemon_config(&dir, &hub, "bob@machine-b", roots))
        .await
        .unwrap();
    wait_connected(&a).await;
    wait_connected(&b).await;
    let (ra, rb) = (
        make_repo(&dir.join("a/proj")),
        make_repo(&dir.join("b/proj")),
    );
    hook(&a, session_start(SA, &ra)).await;
    hook(&b, session_start(SB, &rb)).await;
    tool(
        &a,
        SA,
        "send",
        json!({"to": format!("session:{SB}"), "body": "over-tls"}),
    )
    .await
    .unwrap();
    eventually(5, || async {
        ctx(&hook(&b, post_bash(SB, &rb)).await)
            .contains("over-tls")
            .then_some(())
    })
    .await;
    // The hub no longer speaks plaintext on its port.
    let plain = format!("ws://127.0.0.1:{}/ws", hub.addr.port());
    let p = daemon::start(daemon_config(
        &dir.join("p"),
        plain,
        "carol@machine-c",
        &Opts::default(),
    ))
    .await
    .unwrap();
    never_connects(&p).await;
}

#[tokio::test]
async fn untrusted_expired_and_misnamed_certificates_are_rejected() {
    let dir = tmpdir();
    let ca = ca();
    let roots = vec![write_ca(&ca, &dir.join("ca.pem"))];
    // Signed by a CA the daemon does not trust (system roots only).
    let other = common::ca();
    let hub1 = tls_hub(
        &dir.join("h1"),
        leaf(&other, &["localhost"], false, &dir.join("c1")),
    )
    .await;
    let d1 = daemon::start(tls_daemon_config(
        &dir.join("d1"),
        &hub1,
        "alice@m1",
        roots.clone(),
    ))
    .await
    .unwrap();
    // Expired, from the trusted CA.
    let hub2 = tls_hub(
        &dir.join("h2"),
        leaf(&ca, &["localhost"], true, &dir.join("c2")),
    )
    .await;
    let d2 = daemon::start(tls_daemon_config(
        &dir.join("d2"),
        &hub2,
        "alice@m2",
        roots.clone(),
    ))
    .await
    .unwrap();
    // Valid, trusted, but for another name.
    let hub3 = tls_hub(
        &dir.join("h3"),
        leaf(&ca, &["hub.example-tailnet.ts.net"], false, &dir.join("c3")),
    )
    .await;
    let d3 = daemon::start(tls_daemon_config(&dir.join("d3"), &hub3, "alice@m3", roots))
        .await
        .unwrap();
    for d in [&d1, &d2, &d3] {
        never_connects(d).await;
    }
}

#[tokio::test]
async fn certificate_is_reloaded_without_a_restart() {
    let dir = tmpdir();
    let ca = ca();
    let roots = vec![write_ca(&ca, &dir.join("ca.pem"))];
    let other = common::ca();
    let files = leaf(&other, &["localhost"], false, &dir.join("cert"));
    let hub = tls_hub(&dir, files).await;
    let mut cfg = tls_daemon_config(&dir, &hub, "alice@machine-a", roots);
    cfg.reconnect_min = Duration::from_millis(100);
    let d = daemon::start(cfg).await.unwrap();
    never_connects(&d).await;
    // A renewed certificate (as from `tailscale cert`) replaces the files; reload picks it up.
    leaf(&ca, &["localhost"], false, &dir.join("cert"));
    hub.reload_tls().unwrap();
    eventually(15, || async { (d.connects() > 0).then_some(()) }).await;
}

#[tokio::test]
async fn plaintext_off_the_tailnet_is_refused() {
    let dir = tmpdir();
    // The daemon refuses ws:// to a LAN address or a public name.
    for url in ["ws://192.168.1.20:7420/ws", "ws://hub.example.com:7420/ws"] {
        let e = daemon::start(daemon_config(
            &dir.join("d"),
            url.into(),
            "alice@m",
            &Opts::default(),
        ))
        .await;
        assert!(
            e.as_ref().err().is_some_and(|e| e.contains("plaintext")),
            "{url}: {:?}",
            e.err()
        );
    }
    // The hub refuses to serve plaintext on all interfaces or a LAN address.
    for listen in ["0.0.0.0:0", "192.168.1.5:7420"] {
        let e = hub::start(HubConfig {
            listen: listen.parse().unwrap(),
            db: dir.join("hub.sqlite"),
            identity: IdentityConfig::Tailscale {
                bin: "tailscale".into(),
            },
            hostnames: vec![],
            allow_users: vec![],
            tls: None,
            log_max_entries: wormhole::hub::DEFAULT_LOG_MAX_ENTRIES,
            log_max_age_secs: wormhole::hub::DEFAULT_LOG_MAX_AGE_SECS,
            target_file: None,
        })
        .await;
        assert!(
            e.as_ref().err().is_some_and(|e| e.contains("plaintext")),
            "{listen}: {:?}",
            e.err()
        );
    }
}
