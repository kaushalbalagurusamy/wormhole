//! Read-only activity page: presence, leases and recent events, with live updates over
//! server-sent events. Every route requires the same identity as the WebSocket. Message
//! bodies are never shown; only who wrote to whom.

use super::{who, Hub};
use crate::proto::Event;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub(super) fn routes() -> axum::Router<Arc<Hub>> {
    axum::Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/state", get(state))
        .route("/api/events", get(events))
}

/// What the page may show of an event: no message bodies, no fencing tokens.
fn redact(e: &Event) -> Value {
    let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
    if let Some(d) = v["data"].as_object_mut() {
        d.remove("token");
    }
    if e.kind == "msg" {
        v["data"] = json!({
            "to": e.data["to"],
            "reply_to": e.data["reply_to"],
            "bytes": e.data["body"].as_str().map(str::len).unwrap_or(0),
        });
    }
    v
}

fn secure(mut r: Response, content_type: &'static str) -> Response {
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Refuse cross-site reads: a foreign Origin, or a browser saying the request is cross-site.
fn same_site(headers: &HeaderMap) -> bool {
    let get = |h| headers.get(h).and_then(|v: &HeaderValue| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        if site != "same-origin" && site != "none" {
            return false;
        }
    }
    match get("origin") {
        None => true,
        Some(o) => get("host").is_some_and(|h| o == format!("http://{h}") || o == format!("https://{h}")),
    }
}

macro_rules! identify {
    ($hub:expr, $addr:expr, $headers:expr) => {
        if !same_site(&$headers) {
            return StatusCode::FORBIDDEN.into_response();
        }
        if let Err(s) = who(&$hub, $addr, &$headers).await {
            return s.into_response();
        }
    };
}

async fn index(State(hub): State<Arc<Hub>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    identify!(hub, addr, headers);
    secure(INDEX.into_response(), "text/html; charset=utf-8")
}

async fn app_js(State(hub): State<Arc<Hub>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    identify!(hub, addr, headers);
    secure(APP_JS.into_response(), "text/javascript; charset=utf-8")
}

async fn state(State(hub): State<Arc<Hub>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    identify!(hub, addr, headers);
    let (snap, recent) = match (hub.snapshot(), hub.recent(200)) {
        (Ok(s), Ok(r)) => (s, r),
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let body = json!({
        "sessions": snap.sessions,
        "leases": snap.leases.iter().map(|l| {
            let mut v = serde_json::to_value(l).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() { o.remove("token"); }
            v
        }).collect::<Vec<_>>(),
        "events": recent.iter().map(redact).collect::<Vec<_>>(),
    });
    secure(body.to_string().into_response(), "application/json")
}

async fn events(State(hub): State<Arc<Hub>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    identify!(hub, addr, headers);
    let rx = hub.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(e) => {
                    let ev = SseEvent::default().data(redact(&e).to_string());
                    return Some((Ok::<_, Infallible>(ev), rx));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

const INDEX: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wormhole activity</title>
<style>
body { font: 14px/1.4 system-ui, sans-serif; margin: 16px; color: #1b1b1b; background: #fff; }
@media (prefers-color-scheme: dark) { body { color: #e6e6e6; background: #161616; } }
h1 { font-size: 18px; } h2 { font-size: 15px; margin-top: 24px; }
table { border-collapse: collapse; width: 100%; } td, th { text-align: left; padding: 2px 8px 2px 0; vertical-align: top; }
code { font: 12px ui-monospace, monospace; } #status { opacity: .7; }
</style>
</head>
<body>
<h1>wormhole activity</h1>
<p id="status">loading</p>
<h2>Sessions</h2><table id="sessions"></table>
<h2>Leases</h2><table id="leases"></table>
<h2>Recent events</h2><table id="events"></table>
<script src="app.js"></script>
</body>
</html>
"#;

// Builds the page with textContent only; nothing from the hub is parsed as HTML.
const APP_JS: &str = r#""use strict";
const $ = (id) => document.getElementById(id);
const t = (ms) => new Date(ms).toLocaleTimeString();
function row(table, cells, head) {
  const tr = document.createElement("tr");
  for (const c of cells) {
    const td = document.createElement(head ? "th" : "td");
    td.textContent = String(c);
    tr.appendChild(td);
  }
  if (head) table.appendChild(tr); else table.insertBefore(tr, table.rows[1] || null);
}
function describe(e) {
  const d = e.data || {};
  switch (e.kind) {
    case "activity": return d.kind + " " + (d.paths || []).join(", ") + (d.summary ? " (" + d.summary + ")" : "");
    case "msg": return "message to " + (d.to && d.to.kind) + (d.to && d.to.id ? " " + d.to.id : "") + " (" + d.bytes + " bytes)";
    case "hello": return "joined " + d.repo + " on " + d.branch + (d.task ? ": " + d.task : "");
    case "bye": return "left (" + d.reason + ")";
    default: return [d.repo, d.scope, d.reason].filter(Boolean).join(" ");
  }
}
let events = $("events");
function addEvent(e) {
  row(events, [e.seq, t(e.ts), e.user + "@" + e.machine, (e.session || "").slice(0, 8), e.kind, describe(e)]);
  while (events.rows.length > 300) events.deleteRow(events.rows.length - 1);
}
async function load() {
  const s = await (await fetch("api/state")).json();
  for (const id of ["sessions", "leases", "events"]) $(id).textContent = "";
  row($("sessions"), ["session", "who", "repo", "branch", "task", "last seen"], true);
  for (const x of s.sessions) row($("sessions"), [x.session.slice(0, 8), x.user + "@" + x.machine, x.repo, x.branch, x.task, t(x.last_seen)]);
  row($("leases"), ["scope", "repo", "holder", "since", "expires"], true);
  for (const l of s.leases) row($("leases"), [l.scope, l.repo, l.user + "@" + l.machine + " " + l.session.slice(0, 8), t(l.since), t(l.expires)]);
  row(events, ["seq", "time", "who", "session", "kind", "detail"], true);
  for (const e of s.events) addEvent(e);
  $("status").textContent = "live";
}
let reload = null;
const es = new EventSource("api/events");
es.onmessage = (m) => {
  addEvent(JSON.parse(m.data));
  clearTimeout(reload);
  reload = setTimeout(load, 300);
};
es.onerror = () => { $("status").textContent = "disconnected; retrying"; };
load();
"#;
