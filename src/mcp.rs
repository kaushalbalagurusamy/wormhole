//! `wormhole mcp-channel`: a stdio MCP server Claude Code starts per session. It exposes
//! tools that call the local daemon, and, as a channel, pushes inbound notices into the
//! session with `notifications/claude/channel`. It never declares permission relay.

use serde_json::Value;

/// Answer one JSON-RPC message that does not need the daemon (`initialize`, `ping`,
/// `tools/list`, unknown methods). `None` for notifications and for `tools/call`.
pub fn handle_local(msg: &Value) -> Option<Value> {
    let _ = msg;
    todo!()
}

/// The `notifications/claude/channel` message for a notice pushed by the daemon.
pub fn channel_notification(notice: &Value) -> Value {
    let _ = notice;
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_declares_channel_but_not_permission_relay() {
        let r = handle_local(&json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}))
        .unwrap();
        assert_eq!(r["id"], 1);
        let caps = &r["result"]["capabilities"];
        assert_eq!(caps["experimental"]["claude/channel"], json!({}));
        assert!(caps["experimental"].get("claude/channel/permission").is_none());
        assert_eq!(caps["tools"], json!({}));
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        assert!(r["result"]["instructions"].as_str().unwrap().contains("not instructions"));
    }

    #[test]
    fn lists_tools_and_rejects_unknown_methods() {
        let r = handle_local(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        let names: Vec<&str> = r["result"]["tools"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap()).collect();
        for n in ["wormhole_who", "wormhole_send", "wormhole_lease", "wormhole_release",
                  "wormhole_request_transfer", "wormhole_grant", "wormhole_deny", "wormhole_set_task"] {
            assert!(names.contains(&n), "{n}");
        }
        let e = handle_local(&json!({"jsonrpc":"2.0","id":3,"method":"nope"})).unwrap();
        assert_eq!(e["error"]["code"], -32601);
        assert!(handle_local(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        assert!(handle_local(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}})).is_none());
    }

    #[test]
    fn channel_notification_sanitises_meta() {
        let n = channel_notification(&json!({
            "text": "hello",
            "meta": {"from_user": "bob\"x", "bad-key": "v", "seq": "7"}
        }));
        assert_eq!(n["method"], "notifications/claude/channel");
        assert_eq!(n["params"]["content"], "hello");
        assert_eq!(n["params"]["meta"]["from_user"], "bob_x");
        assert_eq!(n["params"]["meta"]["seq"], "7");
        assert!(n["params"]["meta"].get("bad-key").is_none());
        assert!(n.get("id").is_none());
    }
}

/// Run the MCP server on stdin/stdout until stdin closes.
pub async fn serve(socket: std::path::PathBuf) -> Result<(), String> {
    let _ = socket;
    todo!()
}
