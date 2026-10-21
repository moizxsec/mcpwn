---
title: Reports & advisories
description: Turn a recorded session and its findings into one self-contained HTML advisory, and findings into filled CVSS v3.1 + CWE GHSA-style advisories.
---

The pieces you reach for in a write-up: a shareable HTML advisory, and filled
CVSS v3.1 + CWE markdown advisories.

```bash
# Render a recorded session (+ findings) into ONE self-contained HTML advisory
mcpwn report session.jsonl --findings ./out -o report.html

# Turn findings into filled CVSS v3.1 + CWE advisories (GHSA-style markdown)
mcpwn advisory ./out -o ./advisories
```

## `mcpwn report`

Turns a session log (the JSONL the proxy writes via `--log`) plus an optional
findings dir into a **single zero-dependency HTML advisory**: header stats,
findings by severity, side-by-side tamper diffs, and a tiny vanilla-JS severity
filter. It is a **static file** - nothing listens, fetches, or executes. It
opens offline and screenshots cleanly. Every byte of session/finding content is
HTML-escaped (the content is literally the attacker-controlled traffic under
test).

## `mcpwn advisory`

Turns a findings dir / `findings.json` into filled **CVSS v3.1 + CWE advisories**
(GHSA-style markdown mirroring the
[advisory template](/mcpwn/project/advisory-template/)) - one `.md` per finding,
a combined doc, or stdout:

```bash
mcpwn advisory ./out -o ./advisories      # one .md per finding
mcpwn advisory ./out -o advisories.md     # one combined document
mcpwn advisory ./out                      # combined document to stdout
```

CWE/CVSS also enrich the SARIF rule metadata and the HTML report. The CWE + CVSS
v3.1 scoring for each finding id lives in
[`src/advisory.ts`](https://github.com/moizxsec/mcpwn/blob/main/src/advisory.ts).
See the [threat taxonomy](/mcpwn/threats/) for the per-class mapping, and
disclose responsibly per the [security policy](/mcpwn/project/security/).
