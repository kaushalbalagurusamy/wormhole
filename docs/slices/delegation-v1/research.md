# Research brief: delegation-v1 (2026-11-15)

Primary sources read on 2026-11-15. Parts of the hooks page came back as a summary rather than verbatim text;
those claims are marked (summary) and should be re-read against the live page before relying on exact wording.

| Claim | Source | Status |
|---|---|---|
| A `PreToolUse` hook answering `permissionDecision: "allow"` skips the permission prompt, except for actions no mode auto-approves and some MCP tools that need user interaction. | code.claude.com/docs/en/hooks, PreToolUse decision control | (summary) |
| Settings deny and ask rules are still evaluated when a hook answers `allow`; a matching deny blocks, a matching ask prompts. | code.claude.com/docs/en/permissions | (summary); rule order "deny, then ask, then allow" verbatim |
| In plan mode a hook's `allow` has no effect on edits or other calls that are not read-only. | code.claude.com/docs/en/permissions | (summary) |
| With several PreToolUse hooks, precedence is deny > defer > ask > allow. | code.claude.com/docs/en/hooks | (summary) |
| Exit code 2 blocks the call even if JSON says `allow`. | code.claude.com/docs/en/hooks | verbatim |
| A channel declaring `claude/channel/permission` receives tool approval prompts; the first answer (terminal or channel) wins; "anyone who can reply through your channel can approve or deny tool use in your session". | code.claude.com/docs/en/channels-reference.md | verbatim |

Could not verify: how a hook's `allow` interacts with `acceptEdits`, `bypassPermissions` and `auto` modes (not
stated). Consequence: the bypass levels are an addition to whatever mode the receiving user runs; they cannot
loosen a settings deny or ask rule, and they do nothing in plan mode.

Code facts (this repository, `main` at 07aa08d):
- `src/hub/mod.rs` drops a connection on a frame it cannot parse (`Ok(Up::Resume { .. }) | Err(_) => break`),
  so new request variants must be gated on a hub capability.
- `State::apply` ignores unknown event kinds and `Down` parse failures are ignored, so old daemons never answer a
  delegation request: the hub must refuse requests to sessions whose daemon lacks the capability.
- `Hub::visible` restricts only `msg`; `page::redact` strips only `msg` bodies.
- serde ignores unknown fields on these types (no `deny_unknown_fields`), so added fields with `#[serde(default)]`
  are readable by old and new peers.
