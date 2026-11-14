//! `wormhole install`: print, never write, the Claude Code settings for a project.

use std::path::Path;

/// The text `wormhole install` prints.
pub fn render(project: &Path, exe: &Path, http_port: u16, socket: &Path) -> String {
    let _ = (project, exe, http_port, socket);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn prints_valid_settings_and_mcp_config() {
        let out = render(Path::new("/p"), Path::new("/bin/wormhole"), 7421, Path::new("/s/d.sock"));
        // Every fenced JSON block parses.
        let blocks: Vec<&str> = out.split("```json\n").skip(1).map(|b| b.split("```").next().unwrap()).collect();
        assert_eq!(blocks.len(), 2);
        let settings: Value = serde_json::from_str(blocks[0]).unwrap();
        let mcp: Value = serde_json::from_str(blocks[1]).unwrap();
        let hooks = &settings["hooks"];
        // SessionStart only supports command hooks.
        assert_eq!(hooks["SessionStart"][0]["hooks"][0]["type"], "command");
        assert_eq!(hooks["SessionStart"][0]["hooks"][0]["command"], "/bin/wormhole");
        for ev in ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionEnd"] {
            let h = &hooks[ev][0]["hooks"][0];
            assert_eq!(h["type"], "http", "{ev}");
            assert_eq!(h["url"], "http://127.0.0.1:7421/hook", "{ev}");
            assert!(h.get("onFailure").is_none());
        }
        assert_eq!(hooks["PreToolUse"][0]["matcher"], "^(Edit|Write|MultiEdit|NotebookEdit)$");
        assert_eq!(mcp["mcpServers"]["wormhole"]["command"], "/bin/wormhole");
        assert_eq!(mcp["mcpServers"]["wormhole"]["args"][0], "mcp-channel");
        assert!(out.contains("--dangerously-load-development-channels server:wormhole"));
    }
}
