---
title: "Contributing"
description: "Project layout, invariants, and how to add a new rule kind or transport."
---


Thanks for your interest. mcpwn is a security-testing tool; contributions that
sharpen its offensive capabilities, broaden transport/protocol coverage, or
improve safety and documentation are all welcome.

## Ground rules

- **Authorized use only.** Do not submit examples, payloads, or test fixtures
  that target real third-party services. Use the bundled vulnerable server or
  your own infrastructure.
- **Responsible disclosure.** Findings against real MCP servers go through the
  process in [SECURITY.md](/mcpwn/project/security/), not into issues/PRs.

## Development

```bash
npm install
npm run build        # tsc -> dist/
npm test             # build + node --test (all test/**/*.test.js)
npm run lint         # eslint (src only)
npm run format       # prettier --write src
npm run format:check # prettier --check src (CI gate)
npm run coverage     # c8 line coverage for src/engine + src/core
npm run docs:api     # typedoc -> docs/api/ (git-ignored, build-only)
npm run demo         # end-to-end inject -> exfil demo (no network, no API key)
```

All dependencies are **devDependencies** - mcpwn itself has **zero runtime
dependencies** (Node built-ins only). Please keep it that way: validation is
hand-rolled, and transports use `node:http`/`node:crypto` directly.

The codebase is small and layered:

| Path | Responsibility |
| --- | --- |
| `src/engine/parser.ts` | JSON-RPC framing + tolerant parse/serialize |
| `src/engine/correlator.ts` | id → method mapping so responses are attributable |
| `src/engine/rules.ts` | headless tamper rule engine (`applyAction`) |
| `src/engine/validate.ts` | hand-rolled, zero-dep rule-file validation |
| `src/engine/jsonpath.ts` | tiny JSON path access for argument tampering |
| `src/engine/intercept.ts` | interactive hold/forward/drop/edit controller |
| `src/engine/tty.ts` | cross-platform controlling-terminal open (`/dev/tty`, `CONIN$`/`CONOUT$`) |
| `src/core/pipeline.ts` | transport-agnostic parse→correlate→rules→intercept→log |
| `src/core/scope.ts` | in-scope membership test |
| `src/transports/stdio.ts` | wrap-and-spawn stdio relay (`Transport`) |
| `src/transports/http.ts` | Streamable HTTP + SSE reverse proxy (`Transport`) |
| `src/detect/*` | passive detectors (baseline rug-pull, linters) |
| `src/findings.ts` | findings model + JSON/Markdown/SARIF writers |
| `src/logger.ts` | stderr-only logging (never touches the MCP channel) |
| `src/cli.ts` | arg parsing + wiring |
| `examples/` | vulnerable demo server(s), attack rules, runnable demo |

## Extending mcpwn

### Adding a new rule kind

A tamper action (`RuleAction`) is a discriminated union keyed on `kind`. To add
one - say `truncateResult`:

1. **Extend the union.** Add the new variant to `RuleAction` in
   [`src/types.ts`](https://github.com/moizxsec/mcpwn/blob/main/src/types.ts), e.g.
   `| { kind: "truncateResult"; maxLen: number }`.
2. **Handle it in `applyAction`.** In [`src/engine/rules.ts`](https://github.com/moizxsec/mcpwn/blob/main/src/engine/rules.ts),
   add a `case "truncateResult":` **before the `default:` throw**. Mutate the
   cloned `json` in place and return `true` when you changed it, `false` when the
   action did not apply. The `default:` branch must stay - an unknown kind has to
   *fail loud* so the per-rule try/catch logs it and forwards untampered
   (Invariant: never block the wire).
3. **Add a schema + validate branch.** Register the kind in
   [`src/engine/validate.ts`](https://github.com/moizxsec/mcpwn/blob/main/src/engine/validate.ts): add it to `ACTION_KINDS`,
   list its allowed fields in `ACTION_FIELDS`, and add a `case` in
   `validateAction` that checks its required/typed fields (reuse the
   `requireString`/`requireObject`/`optionalEnum`/… helpers). Mirror the shape in
   [`schema/rules.schema.json`](https://github.com/moizxsec/mcpwn/blob/main/schema/rules.schema.json) so editors/CI get the
   same `oneOf` discrimination.
4. **Add tests.** Cover the happy path and no-op path in `test/rules*.test.js`,
   and the validation errors (missing/wrong-typed fields, typo suggestion) in
   `test/validate.test.js`.

### Adding a transport

Transports own framing + I/O only; all tamper/correlation/logging semantics live
in `MessagePipeline`, so a new transport inherits them for free:

1. Implement the `Transport` interface from
   [`src/transports/transport.ts`](https://github.com/moizxsec/mcpwn/blob/main/src/transports/transport.ts)
   (`start(): Promise<number>`, `stop()`).
2. For every logical JSON-RPC message you frame, call
   `pipeline.process(raw, direction)` and write back `result.forward` (with your
   transport's framing) unless it is `null` (dropped). **Do not** re-implement
   rules/correlation/logging.
3. Honour the invariants: forward the original bytes on any failure, preserve
   framing/ordering when idle, and keep the human/log output off the data channel.
4. Add an "idle = byte-identical" assertion test for the transport (see
   `test/stdio-idle.test.js` / `test/http.test.js`) plus a `process()`-driven
   behaviour test.

## Invariants (please don't break these)

1. **stdout/stdin are sacred.** All human output goes to stderr (or `/dev/tty`).
   A byte on stdout that isn't a forwarded protocol message corrupts the session.
2. **Never block the wire.** Every path forwards the original bytes on any
   failure. Detectors are read-only and must never mutate the flow or throw into
   the pipeline.
3. **Transparent when idle.** With no rules/detectors/scope, traffic passes
   through unchanged in content, order, and framing - on *both* transports.
4. **Protocol correctness.** Preserve `Mcp-Session-Id`/`Last-Event-ID` and SSE
   `event:`/`id:` framing on HTTP; newline framing on stdio; correlation keys
   intact in both directions.
5. **No telemetry, no egress** beyond the explicit `--upstream`.
6. **Zero runtime deps.** Node built-ins only; hand-rolled schema validation.
   New deps are devDependencies only.
7. **Forget on drop.** Any drop path calls `correlator.forget` so a dropped
   request doesn't leak a correlation entry.
8. **`applyAction` has a `default:` throw** for unknown kinds (surfaced as a
   logged error, never a crash).

## Pull requests

- Keep commits atomic and use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Run `npm run lint`, `npm run build`, `npm test`, and `npm run demo` before pushing.
- One logical change per PR; describe the security rationale where relevant.

## Release checklist

1. All green: `npm run lint && npm run build && npm test && npm run coverage`.
2. `npm run format:check` is clean.
3. Bump `version` in `package.json` (SemVer).
4. Add a dated section to [`CHANGELOG.md`](/mcpwn/project/changelog/) (Keep a Changelog
   format) summarising the release.
5. Verify the publish tarball contents: `npm pack --dry-run` - confirm `dist/`,
   `schema/`, `payloads/`, `examples/`, and `README.md` are included and nothing
   sensitive leaks. (`prepublishOnly` runs `npm run build` automatically.)
6. Tag and publish: `git tag vX.Y.Z` then `npm publish` (scope is published with
   `--access public`, already set in `publishConfig`).
