---
title: Intercept proxy
description: The live proxy - passive X-ray, the interactive Repeater loop, the read-only detectors, and interception scoping.
---

mcpwn wraps a **stdio** MCP server: the host launches mcpwn, mcpwn launches the
real server and relays the traffic, logging every message to **stderr**
(stdout/stdin stay byte-clean for the protocol).

```bash
# Passive X-ray — watch all traffic, change nothing
mcpwn -v -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Interactive — hold every message and decide: forward / drop / edit / tamper
mcpwn -i -- node ./my-server.js

# Tamper headlessly — apply JSON rules to messages in flight
mcpwn -r attack.json -- node ./my-server.js

# Record a session log (JSONL) for later review
mcpwn -l session.jsonl -- node ./my-server.js
```

## Interactive intercept (the Repeater loop)

With `-i`, mcpwn holds each message and waits for you on the controlling
terminal (keyboard input comes from the console directly - `/dev/tty` on POSIX,
`CONIN$`/`CONOUT$` on Windows - so it never collides with the MCP channel on
stdin/stdout):

```text
┌─ HELD S→C tools/call #7
│ { "jsonrpc": "2.0", "id": 7, "result": { "content": [ ... ] } }
└─ [f]orward [d]rop [e]dit [t]amper [F]orward-all [q]uit >
```

| Key | Action |
| --- | --- |
| `f` | Forward the message as-is. |
| `d` | Drop it (forward nothing). |
| `e` | Open it in `$EDITOR` (or `nano`); edited JSON is re-validated before sending. |
| `t` | Quick-tamper: inject a marker into a `tools/call` result. |
| `F` | Forward this one and turn intercept off (auto-forward the rest). |
| `q` | Quit and tear down the server. |

Interactive mode needs a real terminal; when mcpwn is spawned by a GUI client
with no tty, it logs a notice and falls back to auto-forward (rules still apply).

## Options

| Flag | Description |
| --- | --- |
| `-i, --intercept` | Interactively hold each message for review (needs a terminal; **stdio only**). |
| `-r, --rule <file>` | Load a JSON tamper-rule file (repeatable). |
| `-l, --log <file>` | Append a JSONL session log of all traffic. |
| `-v, --verbose` | Pretty-print full message bodies to stderr. |
| `-h, --help` | Show help. |
| `--version` | Print version. |

## Detection & reporting

Passive detectors run **read-only** alongside the proxy - they never change
what's forwarded, they only record findings.

| Flag | Description |
| --- | --- |
| `--findings-out <dir>` | On exit, write `findings.json` + `findings.md` + `findings.sarif` (also enables the passive secret/poisoning linters). |
| `--baseline <file>` | Diff each `tools/list` against a captured baseline - **rug-pull detection** (tool set / schema / description drift mid-session). |
| `--baseline-capture <file>` | Capture the first `tools/list` to `<file>` inline while proxying. |
| `--pin <file>` | Diff the live tool/resource/prompt surface against a committed `mcpwn.lock` - **cross-session rug-pull pinning**; any silent drift is a **HIGH** finding. Capture with `mcpwn pin capture`. |
| `--taint` | **Provenance tainting** - flag the injection→action kill chain: untrusted server output (a tool result / resource) that is later reused inside a `tools/call` argument (**HIGH**). Read-only, opt-in. |
| `--redact` | Mask built-in secret patterns (API keys, tokens, …) in the stderr log + JSONL. |
| `--redact-file <file>` | Add redaction patterns, one `label=regex` per line. |

## Scoping

Narrow what mcpwn acts on; **out-of-scope traffic is always forwarded
untouched** and hidden from the live log (so a noisy session stays readable and
tamper stays surgical).

| Flag | Description |
| --- | --- |
| `--scope-method <glob>` | Only methods matching this glob (repeatable), e.g. `tools/*`. |
| `--scope-tool <name>` | Only `tools/call` for this tool name (repeatable). |
| `--scope-direction c2s\|s2c` | Only this direction. |
| `--only-tampered` | Only show messages a rule actually changed. |
| `--scope-affects-log` | Also omit out-of-scope traffic from the `--log` JSONL. |

## Batched messages

JSON-RPC 2.0 allows a **batch** - an array of messages on a single line. mcpwn
does **not** classify, correlate, or tamper batch elements individually: a batch
is relayed **opaquely** (logged with `kind: "unknown"`, forwarded byte-for-byte),
so rules do not currently apply inside a batch. This is deliberate - batches are
rare in MCP and were removed in the 2025-06-18 spec revision. If you need to
tamper a batched server, split it upstream or open an issue.
