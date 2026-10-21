---
title: Transports & CI
description: Proxy remote Streamable HTTP + SSE MCP servers, run the headless helpers (baseline, pin, replay, diff, conformance, eval), and wire mcpwn into GitHub Actions.
---

mcpwn also proxies **remote HTTP MCP servers** and ships a few headless helpers.
All subcommands share `-r`/`-l`/`-v` plus the detection and scope flags.

```bash
# Reverse-proxy a remote Streamable HTTP + SSE MCP server (Mcp-Session-Id,
# Last-Event-ID and SSE event:/id: framing are preserved; interactive -i is
# disabled for HTTP — there is no single flow to pause).
mcpwn http --listen 127.0.0.1:8900 --upstream https://mcp.example.com/mcp \
  -r attack.json --findings-out ./out            # --mode streamable|sse|auto

# Rug-pull detection: capture the tool set once, then watch for drift
mcpwn baseline capture --out base.json -- node ./my-server.js
mcpwn --baseline base.json --findings-out ./out -- node ./my-server.js

# Replay recorded client->server traffic through a fresh server (rules apply)
mcpwn replay session.jsonl -- node ./my-server.js   # --only-method, --repeat <n>

# Differential regression: replay a golden session and diff live vs recorded
# responses; flags drift AND newly-introduced injection surfaces across versions
mcpwn diff golden.jsonl --findings-out ./out -- node ./my-server.js  # --ignore <jsonpath>

# MCP spec conformance: framing, initialize caps, id echo, error codes, clean
# stdout, pagination, ping — security-relevant violations become findings
mcpwn conformance -- node ./my-server.js            # --json report.json

# Browse the bundled attack payload libraries
mcpwn payloads list
mcpwn payloads show path-traversal
```

| Command | Purpose |
| --- | --- |
| `mcpwn http --listen … --upstream …` | Streamable HTTP + SSE reverse proxy. Interactive mode disabled. |
| `mcpwn baseline capture [--out <file>] -- <cmd>` | Record the first `tools/list` to a baseline file. |
| `mcpwn pin capture [--out mcpwn.lock] -- <cmd>` | Hash the whole advertised surface (tools + resources + prompts) into a cross-session lockfile for `--pin`. |
| `mcpwn replay <session.jsonl> -- <cmd>` | Replay recorded `client->server` traffic through a fresh server. |
| `mcpwn diff <golden.jsonl> -- <cmd>` | Differential replay: diff live vs golden responses; flags drift + new injection surfaces. CI exit via `--fail-on`. |
| `mcpwn conformance -- <cmd>` | MCP spec conformance checks; security-relevant violations become findings. Nonzero exit on any FAIL. |
| `mcpwn eval [--agent mock\|command] …` | Agent-susceptibility harness: drive a target agent through the DVMCP suite, score (deterministically) whether it took the bait. |
| `mcpwn payloads list` / `show <name>` | List / print the bundled payload libraries. |

## GitHub Action & scan gate

A reusable composite **GitHub Action**
([`action.yml`](https://github.com/moizxsec/mcpwn/blob/main/action.yml)) installs
mcpwn, scans a server you name, fails the job on findings at/above a severity,
and uploads `findings.sarif` to the **Security tab** (code scanning):

```yaml
# .github/workflows/mcpwn-scan.yml  (full example: examples/github-action/mcpwn-scan.yml)
permissions:
  contents: read
  security-events: write          # required to upload SARIF
jobs:
  mcpwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: moizxsec/mcpwn@v1  # or pin an exact release, e.g. @v0.3.0
        with:
          server-command: "node ./my-server.js"   # or: http-url: https://…/mcp
          fail-on: high
          fuzz: "true"
```

| Input | Default | Purpose |
| --- | --- | --- |
| `server-command` | - | stdio server command to scan (or use `http-url`). |
| `http-url` | - | remote Streamable HTTP server to scan instead. |
| `fail-on` | `high` | fail the job at/above this severity. |
| `fuzz` | `false` | enable active tool fuzzing. |
| `findings-dir` | `mcpwn-findings` | output dir (SARIF is uploaded from here). |
| `mcpwn-version` | `latest` | npm dist-tag / version to install. |
| `upload-sarif` | `true` | upload `findings.sarif` to the Security tab. |
