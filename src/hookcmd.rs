//! `wormhole hook`: a command hook (needed for SessionStart, which does not accept HTTP
//! hooks). Reads the hook input on stdin, asks the daemon over the Unix socket, prints the
//! JSON output. Fails open: on any error or after the deadline it prints a stale-state note.

use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// Hook output for `input`, from the daemon at `socket`, within `deadline`.
pub async fn run(socket: &Path, input: Value, deadline: Duration) -> Value {
    let _ = (socket, input, deadline);
    todo!()
}
