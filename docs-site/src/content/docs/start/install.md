---
title: Install
description: Install mcpwn globally with npm, run it ad-hoc with npx, or build the Docker image. Requires Node >= 18 — zero other runtime dependencies.
---

```bash
npm install -g @moizxsec/mcpwn      # then run:  mcpwn ...

# or ad-hoc, zero install:
npx @moizxsec/mcpwn -- npx -y @some/mcp-server

# or Docker (stdin/stdout are the MCP channel, so run with -i and no -t):
docker build -t mcpwn .
docker run --rm -i mcpwn scan --http https://mcp.example.com/mcp
```

The installed command is `mcpwn` (the package is published under a scope, but
the binary name is unscoped). Requires Node ≥ 18. **No other runtime
dependencies.**

## Onboard in one step

`mcpwn init` detects your installed MCP clients (Claude Desktop, Cursor, Cline,
VS Code, Windsurf), offers to route one through mcpwn, and drops a starter
`mcpwn.config.json` / `mcpwn.policy.json`.

- **Shell completions:** `mcpwn completions <bash|zsh|fish>`
- **Man page:** `mcpwn man` (or `npm run man`)

See the [Wrap & init guide](/mcpwn/guides/wrap-init/) for wiring mcpwn into a
specific client config.
