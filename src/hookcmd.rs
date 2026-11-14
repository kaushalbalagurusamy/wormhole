//! `wormhole hook`: a command hook (needed for SessionStart, which does not accept HTTP
//! hooks). Reads the hook input on stdin, asks the daemon over the Unix socket, prints the
//! JSON output. Fails open: on any error or after the deadline it prints a stale-state note.

use crate::local::LocalClient;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

/// Hook output for `input`, from the daemon at `socket`, within `deadline`.
pub async fn run(socket: &Path, input: Value, deadline: Duration) -> Value {
    let event = input["hook_event_name"]
        .as_str()
        .unwrap_or("SessionStart")
        .to_string();
    let r = tokio::time::timeout(deadline, async {
        let mut c = LocalClient::connect(socket)
            .await
            .map_err(|e| e.to_string())?;
        c.call("hook", json!({ "input": input })).await
    })
    .await;
    match r {
        Ok(Ok(v)) if v.is_object() => v,
        _ => json!({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": crate::daemon::STALE_DAEMON,
        }}),
    }
}
