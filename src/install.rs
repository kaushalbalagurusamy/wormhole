//! `wormhole install`: print, never write, the Claude Code settings for a project.

use serde_json::{json, Value};
use std::path::Path;

/// The text `wormhole install` prints.
pub fn render(project: &Path, exe: &Path, http_port: u16, socket: &Path, token: &str) -> String {
    let url = format!("http://127.0.0.1:{http_port}/hook");
    let http = json!([{"type": "http", "url": url, "timeout": 5,
        "headers": {"Authorization": format!("Bearer {token}")}}]);
    let sock = socket.display().to_string();
    let settings = json!({
        "hooks": {
            // SessionStart does not accept HTTP hooks, so it runs the command form.
            "SessionStart": [{"hooks": [{"type": "command", "command": exe, "args": ["hook", "--socket", sock], "timeout": 5}]}],
            "UserPromptSubmit": [{"hooks": http}],
            "PreToolUse": [{"matcher": "^(Edit|Write|MultiEdit|NotebookEdit)$", "hooks": http}],
            "PostToolUse": [{"matcher": "*", "hooks": http}],
            "SessionEnd": [{"hooks": http}],
        }
    });
    let mcp = json!({
        "mcpServers": {"wormhole": {"command": exe, "args": ["mcp-channel", "--socket", sock]}}
    });
    let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap_or_default();
    format!(
        "wormhole install prints configuration; it does not write any file.\n\n\
1. Merge into {p}/.claude/settings.local.json (not settings.json: it contains this machine's hook token, \
and settings.local.json is not committed). Hooks time out after 5 s; the daemon itself answers within about 1 s \
and lets the action go ahead if the hub is unreachable.\n\n```json\n{s}\n```\n\n\
2. Merge into {p}/.mcp.json (or register the same server in ~/.claude.json):\n\n```json\n{m}\n```\n\n\
3. The MCP server provides the wormhole_* tools in every session. To also receive pushed messages \
(channels are a research preview), start Claude Code with:\n\n    claude --dangerously-load-development-channels server:wormhole\n\n\
The server never declares permission relay, so no other session can approve tool calls here.\n",
        p = project.display(),
        s = pretty(&settings),
        m = pretty(&mcp),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn prints_valid_settings_and_mcp_config() {
        let out = render(
            Path::new("/p"),
            Path::new("/bin/wormhole"),
            7421,
            Path::new("/s/d.sock"),
            "abc123",
        );
        // Every fenced JSON block parses.
        let blocks: Vec<&str> = out
            .split("```json\n")
            .skip(1)
            .map(|b| b.split("```").next().unwrap())
            .collect();
        assert_eq!(blocks.len(), 2);
        let settings: Value = serde_json::from_str(blocks[0]).unwrap();
        let mcp: Value = serde_json::from_str(blocks[1]).unwrap();
        let hooks = &settings["hooks"];
        // SessionStart only supports command hooks.
        assert_eq!(hooks["SessionStart"][0]["hooks"][0]["type"], "command");
        assert_eq!(
            hooks["SessionStart"][0]["hooks"][0]["command"],
            "/bin/wormhole"
        );
        for ev in [
            "PreToolUse",
            "PostToolUse",
            "UserPromptSubmit",
            "SessionEnd",
        ] {
            let h = &hooks[ev][0]["hooks"][0];
            assert_eq!(h["type"], "http", "{ev}");
            assert_eq!(h["url"], "http://127.0.0.1:7421/hook", "{ev}");
            assert!(h.get("onFailure").is_none());
            assert_eq!(h["headers"]["Authorization"], "Bearer abc123", "{ev}");
        }
        assert_eq!(
            hooks["PreToolUse"][0]["matcher"],
            "^(Edit|Write|MultiEdit|NotebookEdit)$"
        );
        assert_eq!(mcp["mcpServers"]["wormhole"]["command"], "/bin/wormhole");
        assert_eq!(mcp["mcpServers"]["wormhole"]["args"][0], "mcp-channel");
        assert!(out.contains("--dangerously-load-development-channels server:wormhole"));
        // The token is a secret: the snippet goes in the git-ignored local settings file.
        assert!(out.contains("settings.local.json"));
    }
}
