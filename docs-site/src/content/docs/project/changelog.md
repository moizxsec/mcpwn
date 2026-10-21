---
title: "Changelog"
description: "All notable changes to mcpwn, Keep-a-Changelog format."
---


All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-19

A large release taking mcpwn from a stdio-only tamper proxy to a multi-transport
MCP security tool, while keeping **zero runtime dependencies** and every
transparency/never-block-the-wire invariant intact.

### Added

- **Streamable HTTP + SSE transport** (`mcpwn http --listen <host:port>
  --upstream <url>`): a reverse proxy that runs every JSON-RPC message through
  the same tamper/correlation/logging pipeline as stdio. Preserves
  `Mcp-Session-Id` / `Last-Event-ID` and SSE `event:` / `id:` framing
  byte-for-byte, relays batches and compressed/opaque bodies unchanged, and
  forwards the original bytes on any failure. (`--mode streamable|sse|auto`.)
  Interactive `-i` is intentionally disabled for HTTP.
- **Argument tampering** for `client->server` `tools/call` — new rule actions
  `setArg`, `rewriteArgs`, and `fuzzArgs`, backed by a tiny zero-dep JSON-path
  helper (`a.b[0].c`). `fuzzArgs` cycles one payload per matching call.
- **Payload library**: bundled `prompt-injection`, `sqli`, `path-traversal`,
  `ssrf`, and `command-injection` lists, usable by name in `fuzzArgs` and via a
  new `mcpwn payloads list | show <name>` subcommand.
- **Interception scoping** (`--scope-method`, `--scope-tool`,
  `--scope-direction`, `--only-tampered`, `--scope-affects-log`): out-of-scope
  traffic is always forwarded untouched and hidden from the live log.
- **Rule-file JSON Schema + validation**: `schema/rules.schema.json` plus a
  hand-rolled validator with precise, collected errors and "did you mean …?"
  suggestions for mistyped kinds/fields. Invalid rule files exit `2`.
- **Baseline / rug-pull detection** (`--baseline <file>`,
  `--baseline-capture <file>`, `mcpwn baseline capture`): diff each `tools/list`
  against a captured baseline to catch mid-session tool/schema/description drift.
- **Passive linters + redaction**: read-only secret and tool-poisoning
  detectors, plus `--redact` / `--redact-file` to mask secrets in stderr + JSONL.
- **Findings reports** (`--findings-out <dir>`): writes `findings.json`,
  `findings.md`, and `findings.sarif` on exit.
- **Replay** (`mcpwn replay <session.jsonl> -- <cmd>`): re-drive recorded
  `client->server` traffic through a fresh server, with rules applied
  (`--only-method`, `--repeat`).
- **Cross-platform interactive mode**: `src/engine/tty.ts` opens the controlling
  terminal on POSIX (`/dev/tty`) and Windows (`CONIN$` / `CONOUT$`), degrading
  gracefully to auto-forward when headless.
- **Developer tooling** (all devDependencies): ESLint + typescript-eslint flat
  config, Prettier, `c8` coverage, and TypeDoc API docs (`npm run lint` /
  `format` / `format:check` / `coverage` / `docs:api`).

### Changed

- **Architecture:** the parse → correlate → rules → intercept → log → forward
  chain was lifted out of the stdio proxy into a transport-agnostic
  `MessagePipeline` + `Transport` interface, so stdio and HTTP share identical
  semantics. Correlation is now bidirectional, keyed by `(direction, id)`.
- `test` script now discovers all `test/**/*.test.js` (new test files run
  automatically); `applyAction` has a `default:` throw that is logged (never
  crashes) for unknown kinds.
- `package.json` `files` now ships `schema/` and `payloads/` in the tarball.
- CI builds + unit-tests on a Windows runner in addition to Linux
  (Node 18/20/22), and gates on lint + coverage.
- Version bumped to `0.2.0`.

## [0.1.0] - 2026-06-03

First public release.

### Added
- Interactive intercept mode (`-i`): hold each message and forward / drop /
  edit (`$EDITOR`) / quick-tamper, driven from `/dev/tty` so it never collides
  with the MCP channel. Falls back to auto-forward when no terminal is present.
- stdio wrap-and-spawn proxy with transparent pass-through.
- Live, direction-aware JSON-RPC logging to stderr with request/response
  correlation.
- Headless tamper-rule engine: `injectToolResult`, `poisonDescription`,
  `matchReplace`, and `drop` actions, loadable from JSON files.
- JSONL session logging (`--log`).
- Bundled vulnerable demo server and one-command end-to-end attack demo.
- Headless GIF generator (`npm run gif`) and a `vhs` tape for the README demo.
