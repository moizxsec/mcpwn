# Security advisory — <SERVER NAME> <VERSION>

> Fill this in for a vulnerability you found with mcpwn, then follow the
> disclosure process in [../SECURITY.md](../SECURITY.md). Report privately to
> the maintainer first; allow remediation time before publishing.

## Summary

One sentence: what the vulnerability is and its impact.

## Affected

- **Package / server:** `<name>`
- **Versions:** `<= x.y.z`
- **Transport:** stdio / Streamable HTTP
- **Component:** `<tool name>` (`tools/call`) / `tools/list` / resource / prompt

## Severity

CVSS vector + score, or qualitative (low/medium/high/critical) with rationale.

## Description

What the flaw is and why it exists (the missing/insufficient check).

## Reproduction with mcpwn

```bash
mcpwn -i -l evidence.jsonl -- npx -y <server> <args>
```

1. Drive the client to call `<tool>`.
2. Hold the `tools/call` request; edit `arguments` to:
   ```json
   { "...": "<payload>" }
   ```
3. Forward and observe the response / side effect proving the issue.

Attach the relevant lines from `evidence.jsonl` (redact any real secrets).

## Impact

What an attacker gains: file read outside scope, SSRF to metadata service,
RCE, data exfiltration via a coerced agent, etc.

## Suggested remediation

The concrete fix (e.g. "resolve with `fs.realpath` and check
`resolved.startsWith(allowedDir + path.sep)` before access").

## Disclosure timeline

- YYYY-MM-DD — reported privately to maintainer
- YYYY-MM-DD — fix released / 90-day window elapsed
- YYYY-MM-DD — public disclosure

## Credit

Found with [mcpwn](https://github.com/moizxsec/mcpwn).
