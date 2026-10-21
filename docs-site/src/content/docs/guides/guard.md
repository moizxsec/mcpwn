---
title: Guard mode
description: Point mcpwn defensively and it becomes a protective firewall on the agent↔server channel - allow / warn / sanitize / block, plus rug-pull pinning and provenance tainting.
---

mcpwn is an offensive tool by default, but the same message plumbing runs the
other way too. Point it **defensively** and it becomes a protective firewall on
the agent↔server channel. These three features are read-only or fail-open - they
make traffic safer or leave it unchanged, never deadlocking the stream.

## Guard mode (`--guard` / `--policy <file>`)

The defensive inverse of the tamper proxy. For every parseable message mcpwn
recognises the same content classes the passive detectors flag
(prompt-injection phrasing, leaked secrets, exfil URLs, invisible-unicode
smuggling) and, per an active JSON **policy** (`mcpwn.policy.json`), decides to:

- `allow` - forward untouched
- `warn` - forward, but record a finding
- **`sanitize`** - strip only the offending span and forward
- **`block`** - drop the message **before the agent ever sees it**

Guard mode is the one place mcpwn may drop a message - and it **fails open**: a
buggy policy or pathological payload forwards the original untouched. With no
policy it ships a built-in default that *sanitises* the four high-severity
classes (least-disruptive: the agent keeps working, only the malicious span is
removed). Precedence: `--policy <file>` > `./mcpwn.policy.json` > built-in
default.

## Rug-pull pinning (`pin capture` + `--pin <file>`)

The cross-session cousin of `--baseline`. `mcpwn pin capture` hashes a server's
**whole advertised surface** - tools *and* resources *and* prompts - into a
committed `mcpwn.lock`; `--pin` then diffs later runs against it and raises a
**HIGH** finding on any silent description/schema/metadata change, or any
added/removed item. Because the lock lives on disk, the pin and the check can be
weeks and many processes apart - it catches a server that re-poisons long after
the user approved it. Commit `mcpwn.lock` to your repo and gate CI on it.

## Provenance tainting (`--taint`)

Makes the indirect-injection **kill chain** explicit. It tags text originating
from an untrusted server→client tool result / resource as *untrusted-external*,
then raises a **HIGH** finding when that same text later reappears inside a
client→server `tools/call` argument (source message id → sink call). It is
read-only, keeps its own pipeline-owned state, and stays cheap via a bounded,
minimum-length substring index.

```bash
# Run as a firewall (built-in default policy: sanitise injection/secrets/exfil/unicode)
mcpwn --guard -- node ./my-server.js
mcpwn --policy mcpwn.policy.json -- node ./my-server.js   # custom block/sanitise rules

# Commit a lock, then fail later if the advertised surface drifts (cross-session)
mcpwn pin capture --out mcpwn.lock -- node ./my-server.js
mcpwn --pin mcpwn.lock --taint --findings-out ./out -- node ./my-server.js

# Pin + taint also work under the self-driving scanner (CI)
mcpwn scan --pin mcpwn.lock --findings-out ./out -- node ./my-server.js
```

For the defensive framing of each class and its remediation, see the
[threat taxonomy](/mcpwn/threats/).
