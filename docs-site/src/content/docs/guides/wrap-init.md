---
title: Wrap & init
description: Let mcpwn edit your MCP client's config to route every stdio server through the proxy - idempotent, backed up, and reversible. Or onboard in one step with init.
---

## One-step onboarding

```bash
mcpwn init
```

`mcpwn init` detects your installed MCP clients (Claude Desktop, Cursor, Cline,
VS Code, Windsurf), offers to route one through mcpwn, and drops a starter
`mcpwn.config.json` / `mcpwn.policy.json`.

## Wire it into your MCP client

Let mcpwn edit the client's config for you - it finds the file (per-OS standard
path), **backs it up**, and routes every configured stdio server through mcpwn:

```bash
mcpwn wrap --client claude-desktop            # or: cursor | cline | vscode | windsurf
mcpwn wrap --client cursor --server weather --dry-run   # preview one entry, write nothing
mcpwn unwrap --client claude-desktop          # restore the backup byte-for-byte
```

`wrap` is idempotent (a second run is a no-op), never clobbers without a
`*.mcpwn.bak` backup, and `--dry-run` prints the diff. Use `--config-path <file>`
for a non-standard install. Supported clients and their config paths:

| Client | Config path (per OS) |
| --- | --- |
| `claude-desktop` | mac `~/Library/Application Support/Claude/claude_desktop_config.json` · linux `~/.config/Claude/…` · win `%APPDATA%\Claude\…` |
| `cursor` | `~/.cursor/mcp.json` |
| `cline` | `…/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| `vscode` | `…/Code/User/mcp.json` (uses the `servers` key) |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |

## By hand

The transform is just:

```jsonc
// before
{ "command": "npx", "args": ["-y", "@some/mcp-server"] }

// after — wrap it with mcpwn
{ "command": "mcpwn", "args": ["--", "npx", "-y", "@some/mcp-server"] }
```

That's the only change. When you run with no rules, mcpwn is a transparent
pass-through.
