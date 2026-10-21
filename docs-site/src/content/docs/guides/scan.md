---
title: Active scan
description: The self-driving, agent-free scanner - paginated enumeration, content sampling, optional fuzzing, and a CI fail-on gate emitting JSON / Markdown / SARIF.
---

Beyond the live proxy, mcpwn ships a self-driving scanner - no agent in the
loop. It drives the handshake, enumerates every surface (tools / resources /
prompts, paginated), samples content, runs all passive detectors, and fails CI
on findings.

```bash
mcpwn scan --fuzz --findings-out ./out --fail-on high -- node ./my-server.js
mcpwn scan --http https://mcp.example.com/mcp --findings-out ./out
```

| Behaviour | Detail |
| --- | --- |
| Transport | stdio or HTTP (`--http <url>`). |
| Enumeration | paginated `tools/list`, `resources/list`, `prompts/list`. |
| Sampling | reads representative tool/resource/prompt content. |
| Fuzzing | `--fuzz` cycles the bundled payload libraries into string params. |
| CI gate | `--fail-on <severity>` sets the non-zero-exit threshold. |
| Output | `findings.json` / `.md` / **`.sarif`** (stable `partialFingerprints`, so code-scanning de-dupes across runs). |

## Templates & payloads

```bash
mcpwn templates list
mcpwn --template tool-poisoning --findings-out ./out -- node ./my-server.js

mcpwn payloads list
mcpwn payloads show path-traversal
```

Browse every bundled rule-pack in the [template gallery](/mcpwn/templates/).

## Plugins

Custom **detector** and **rule-action plugins** (`--detector` / `--rule-plugin`,
both load local code you wrote or audited) extend the proxy and the scanner
alike.

## Status badge

Emit a shields-style SVG a server author can embed, from a scan or a findings
dir:

```bash
mcpwn scan --badge mcpwn.svg --findings-out ./out -- node ./my-server.js
mcpwn badge --findings ./out -o mcpwn.svg      # or: mcpwn badge --count 0 -o mcpwn.svg
```

0 findings renders green; any findings render red.

See the [Transports & CI guide](/mcpwn/guides/transports-ci/) to wire `scan`
into GitHub Actions, and the [Auditing playbook](/mcpwn/guides/auditing/) for
threat-class recipes.
