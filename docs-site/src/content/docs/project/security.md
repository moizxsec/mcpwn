---
title: "Security policy"
description: "Intended use, how to report a vulnerability in mcpwn, and responsible disclosure of findings made with mcpwn."
---


## Intended use

mcpwn is an **offensive security testing tool**. It is designed to intercept
and tamper with Model Context Protocol traffic so operators can assess agents
and MCP servers **they own or are explicitly authorized to test**. Using it
against systems without authorization may be illegal.

## Reporting a vulnerability in mcpwn

If you find a security issue in mcpwn itself (e.g. it leaks captured data,
egresses traffic, or can be made to crash a host destructively), please open a
GitHub security advisory or a private report rather than a public issue.

## Responsible disclosure of findings made *with* mcpwn

If you use mcpwn to find a vulnerability in a third-party MCP server or agent:

1. **Report privately to the maintainer** of the affected project first.
2. **Allow reasonable remediation time** (commonly 90 days) before publishing.
3. **Do not exfiltrate or retain** any real user data encountered during testing.
4. When you publish, a link back to mcpwn is appreciated but not required.

## Data handling

mcpwn keeps all captured traffic **local**. It has **no telemetry** and makes
**no outbound network connections** of its own. Session logs (`--log`) are
written only to the path you specify and may contain secrets observed on the
wire — treat them accordingly.
