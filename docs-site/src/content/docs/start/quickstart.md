---
title: Quickstart
description: Wrap a stdio MCP server, watch its traffic, tamper it headlessly, and run the self-driving scanner - the four commands you reach for first.
---

mcpwn wraps a **stdio** MCP server: the host launches mcpwn, mcpwn launches the
real server and relays the traffic, logging every message to **stderr**
(stdout/stdin stay byte-clean for the protocol).

## The 30-second tour

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

## Self-driving scan (no agent in the loop)

```bash
# Drives the handshake, enumerates every surface, samples content, runs all
# passive detectors, and fails CI on findings at/above a severity.
mcpwn scan --fuzz --findings-out ./out --fail-on high -- node ./my-server.js
mcpwn scan --http https://mcp.example.com/mcp --findings-out ./out
```

## Try the bundled demo

```bash
npm run demo     # end-to-end inject -> exfil demo (no network, no API key)
npm run dvmcp    # the Damn-Vulnerable MCP scoreboard
```

## Where to next

- [Intercept proxy](/mcpwn/guides/proxy/) - the Repeater loop, detectors, scope.
- [Tamper rules](/mcpwn/guides/tamper-rules/) - the JSON rule format and actions.
- [Active scan](/mcpwn/guides/scan/) - the agent-free scanner and templates.
- [Auditing playbook](/mcpwn/guides/auditing/) - threat class → concrete workflow.
