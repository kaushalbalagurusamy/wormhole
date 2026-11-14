//! The daemon's Unix socket protocol: newline-delimited JSON. Requests carry an `id` and
//! get one response; an attached session also receives `{"push": notice}` lines.

use serde_json::Value;
use std::path::Path;
use std::time::Duration;

pub struct LocalClient {}

impl LocalClient {
    pub async fn connect(path: &Path) -> std::io::Result<LocalClient> {
        let _ = path;
        todo!()
    }

    /// Send `{"op": op, ...args}` and wait for the response's `data`, or its `error`.
    pub async fn call(&mut self, op: &str, args: Value) -> Result<Value, String> {
        let _ = (op, args);
        todo!()
    }

    /// Next pushed notice, or `None` after `wait`.
    pub async fn next_push(&mut self, wait: Duration) -> Option<Value> {
        let _ = wait;
        todo!()
    }
}
