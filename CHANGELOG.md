# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
