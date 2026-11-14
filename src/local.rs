//! The daemon's Unix socket protocol: newline-delimited JSON. Requests carry an `id` and
//! get one response; an attached session also receives notices as lines without an `id`:
//! `{"seq", "text", "meta"}`.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

pub struct LocalClient {
    r: BufReader<OwnedReadHalf>,
    w: OwnedWriteHalf,
    next: u64,
    pushes: VecDeque<Value>,
}

impl LocalClient {
    pub async fn connect(path: &Path) -> std::io::Result<LocalClient> {
        let (r, w) = UnixStream::connect(path).await?.into_split();
        Ok(LocalClient {
            r: BufReader::new(r),
            w,
            next: 1,
            pushes: VecDeque::new(),
        })
    }

    async fn line(&mut self) -> Option<Value> {
        let mut s = String::new();
        match self.r.read_line(&mut s).await {
            Ok(0) | Err(_) => None,
            Ok(_) => serde_json::from_str(&s).ok(),
        }
    }

    /// Send `{"op": op, ...args}` and wait for the response's `data`, or its `error`.
    pub async fn call(&mut self, op: &str, args: Value) -> Result<Value, String> {
        let id = self.next;
        self.next += 1;
        let mut req = json!({"id": id, "op": op});
        if let (Some(r), Value::Object(a)) = (req.as_object_mut(), args) {
            r.extend(a);
        }
        let mut line = req.to_string();
        line.push('\n');
        self.w
            .write_all(line.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        loop {
            let v = self.line().await.ok_or("daemon closed the connection")?;
            if v.get("id") == Some(&json!(id)) {
                return if v["ok"] == json!(true) {
                    Ok(v["data"].clone())
                } else {
                    Err(v["error"].as_str().unwrap_or("error").to_string())
                };
            }
            if v.get("id").is_none() {
                self.pushes.push_back(v);
            }
        }
    }

    /// Next pushed notice, or `None` after `wait`.
    pub async fn next_push(&mut self, wait: Duration) -> Option<Value> {
        if let Some(v) = self.pushes.pop_front() {
            return Some(v);
        }
        tokio::time::timeout(wait, async {
            loop {
                let v = self.line().await?;
                if v.get("id").is_none() {
                    return Some(v);
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
}
