# Contributing to mcpwn

Thanks for your interest. mcpwn is a security-testing tool; contributions that
sharpen its offensive capabilities, broaden transport/protocol coverage, or
improve safety and documentation are all welcome.

## Ground rules

- **Authorized use only.** Do not submit examples, payloads, or test fixtures
  that target real third-party services. Use the bundled vulnerable server or
  your own infrastructure.
- **Responsible disclosure.** Findings against real MCP servers go through the
  process in [SECURITY.md](./SECURITY.md), not into issues/PRs.

## Development

```bash
npm install
npm run build      # tsc -> dist/
npm run demo       # end-to-end inject -> exfil demo (no network, no API key)
```

The codebase is small and layered:

| Path | Responsibility |
| --- | --- |
| `src/engine/parser.ts` | JSON-RPC framing + tolerant parse/serialize |
| `src/engine/correlator.ts` | id → method mapping so responses are attributable |
| `src/engine/rules.ts` | headless tamper rule engine |
| `src/transports/stdio.ts` | wrap-and-spawn stdio relay |
| `src/logger.ts` | stderr-only logging (never touches the MCP channel) |
| `src/cli.ts` | arg parsing + wiring |
| `examples/` | vulnerable demo server, attack rules, runnable demo |

## Invariants (please don't break these)

1. **stdout/stdin are sacred.** All human output goes to stderr. A byte on
   stdout that isn't a forwarded protocol message will corrupt the session.
2. **Transparent when idle.** With no rules, traffic must pass through
   unchanged in content, order, and framing.
3. **Never crash on bad input.** Unparseable lines are relayed opaquely.
4. **No telemetry, no network egress.** Captured data stays local.

## Pull requests

- Keep commits atomic and use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Run `npm run build` and `npm run demo` before pushing.
- One logical change per PR; describe the security rationale where relevant.
