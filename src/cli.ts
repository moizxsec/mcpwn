#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { StdioTransport } from "./transports/stdio.js";
import { HttpTransport, type HttpMode } from "./transports/http.js";
import { MessagePipeline } from "./core/pipeline.js";
import { loadRules } from "./engine/rules.js";
import { InterceptController } from "./engine/intercept.js";
import { Logger } from "./logger.js";
import { loadPayloads, listPayloads } from "./payloads/index.js";
import { runReplay } from "./replay.js";
import { runScan } from "./core/scan.js";
import { runReport } from "./report.js";
import { ArrayFindingsSink, writeFindingsDir, type FindingsSink } from "./findings.js";
import { builtinLinters } from "./detect/linter.js";
import {
  BaselineDetector,
  BaselineCaptureDetector,
  loadBaseline,
  captureBaseline,
} from "./detect/baseline.js";
import type { Detector } from "./detect/detector.js";
import {
  loadDetectorPlugin,
  loadRuleActionPlugin,
  buildActionRegistry,
  type RuleActionPlugin,
  type RuleActionRegistry,
} from "./plugins/index.js";
import { listTemplates, findTemplate, lintTemplates } from "./templates/index.js";
import { builtinRedactPatterns, loadRedactPatterns, type RedactPattern } from "./redact.js";
import {
  loadConfig,
  resolveConfigPath,
  preScanConfigFlags,
  ConfigError,
  type McpwnConfig,
} from "./config.js";
import type { Scope } from "./core/scope.js";
import type { Direction, Rule } from "./types.js";

const HELP = `mcpwn — intercept & tamper proxy for MCP traffic

  X-ray and tamper the JSON-RPC between an AI agent and its MCP servers.
  Burp Suite for AI agents. AUTHORIZED TESTING ONLY.

USAGE
  mcpwn [options] -- <command> [args...]
  mcpwn http --listen host:port --upstream <url> [options]
  mcpwn baseline capture [--out <file>] [options] -- <command> [args...]
  mcpwn replay <session.jsonl> [options] -- <command> [args...]
  mcpwn scan [options] -- <command> [args...]   |   scan --http <url> [options]
  mcpwn report <session.jsonl> [--findings <dir>] -o report.html
  mcpwn payloads list | show <name>
  mcpwn templates list | show <id> | lint [dir]

  Wraps a stdio MCP server: the host launches mcpwn, mcpwn launches the
  real server and relays traffic, logging every message to stderr.

OPTIONS
  -i, --intercept       Interactively hold each message for review
                        (forward / drop / edit / tamper). Needs a terminal.
                        (stdio only — disabled for HTTP in v2.)
  -r, --rule <file>     Load a JSON tamper-rule file (repeatable).
      --template <id>   Load a bundled community template by id as a rule-pack
                        (repeatable; see "mcpwn templates list").
  -l, --log <file>      Append a JSONL session log of all traffic.
  -v, --verbose         Pretty-print full message bodies to stderr.
  -h, --help            Show this help.
      --version         Print version.

CONFIG (§3.13 — commit a baseline invocation; CLI flags still override it)
      --config <file>   Load a mcpwn.config.json (rules, scope, redact, findings
                        output, fail-on). Precedence: defaults < config < flags.
      --no-auto-config  Do NOT auto-load ./mcpwn.config.json (it is loaded by
                        default, with a notice, when present in the cwd).

PLUGINS (§3.11 — extensibility; TRUST MODEL below)
      --detector <file.mjs>     Load a custom passive detector (repeatable).
      --rule-plugin <file.mjs>  Load a custom tamper-action handler whose "kind"
                                rule files may then reference (repeatable).
  TRUST: loading a plugin RUNS ARBITRARY LOCAL CODE (like a nuclei template or
  an ESLint plugin). mcpwn only loads the explicit paths you pass, never
  auto-discovers or fetches anything remote, and prints a notice per plugin on
  startup. Point these flags only at code you wrote or have audited.

DETECTION & REPORTING (§3.4, §3.5, §3.9)
      --findings-out <dir>   Write findings.json + findings.md + findings.sarif
                             on exit (enables the passive linters).
      --baseline <file>      Diff each tools/list against a captured baseline
                             (rug-pull detection).
      --baseline-capture <file>  Capture the first tools/list to <file> inline.
      --redact               Mask built-in secret patterns in stderr + JSONL.
      --redact-file <file>   Add redaction patterns (label=regex per line).

SCOPING (§3.6 — out-of-scope traffic is forwarded untouched + hidden)
      --scope-method <glob>   Only methods matching this glob (repeatable).
      --scope-tool <name>     Only tools/call for this tool name (repeatable).
      --scope-direction c2s|s2c   Only this direction.
      --only-tampered         Only messages a rule actually changed.
      --scope-affects-log     Also omit out-of-scope traffic from --log.

SUBCOMMANDS
  http --listen host:port --upstream <url> [--mode streamable|sse|auto]
                                    Reverse-proxy Streamable HTTP + SSE MCP
                                    traffic. Shares -r/-l/-v, detection and
                                    scope flags. Interactive mode is disabled.
  baseline capture [--out <file>] -- <cmd>
                                    Record the first tools/list to a baseline
                                    file (default: baseline.json).
  replay <session.jsonl> -- <cmd>   Replay recorded client->server traffic
                                    through a fresh server (rules apply).
                                    Flags: -r, -l, -v, --only-method, --repeat <n>
  scan [options] -- <cmd>           Self-driving active scanner — NO agent in the
  scan --http <url> [options]       loop. Drives the handshake, enumerates every
                                    surface (tools/resources/prompts, paginated),
                                    samples resource/prompt content and runs all
                                    passive detectors over the responses.
                                    Flags: --fuzz (active tool fuzzing, default
                                    off), --findings-out <dir>, --fail-on
                                    critical|high|medium|low|info (default high),
                                    --timeout <ms>, --budget <ms>, --fuzz-max <n>,
                                    --sample-max <n>, --scope-method <glob>,
                                    --scope-tool <name>, --detector <file.mjs>,
                                    -l <file>, -v. Exits nonzero when a finding
                                    meets --fail-on (CI).
  report <session.jsonl> [--findings <dir>] -o report.html
                                    Render a recorded session (+ optional
                                    findings dir) into a SINGLE self-contained,
                                    zero-dependency HTML advisory: header + stats,
                                    findings by severity, session timeline, and
                                    side-by-side tamper diffs. A static file — no
                                    live server. Omit -o to write to stdout.
  payloads list                     List bundled payload libraries.
  payloads show <name>              Print a payload library (one per line).
  templates list                    List bundled community templates (rule-packs)
                                    as a table: id, name, severity, attack class.
  templates show <id>               Print a template's metadata + rules.
  templates lint [dir]              Validate every template in dir (default: the
                                    bundled gallery) against the template schema.
                                    Exits nonzero on any invalid template.

EXAMPLES
  # Passive X-ray: watch all traffic, change nothing
  mcpwn -v -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Tamper + report: inject, scan for secrets/poisoning, write an advisory
  mcpwn -r attack.json --findings-out ./out -- node ./my-server.js

  # Rug-pull detection: capture once, then watch for tool-definition drift
  mcpwn baseline capture --out base.json -- node ./my-server.js
  mcpwn --baseline base.json --findings-out ./out -- node ./my-server.js

  # Self-driving scan: point it at a server, fuzz it, fail CI on high findings
  mcpwn scan --fuzz --findings-out ./out -- node ./my-server.js
  mcpwn scan --http https://mcp.example.com/mcp --findings-out ./out

  # Run a community template (rule-pack) against a server
  mcpwn templates list
  mcpwn --template tool-poisoning --findings-out ./out -- node ./my-server.js

  # Extend mcpwn with a custom detector + a custom tamper action (local code!)
  mcpwn --detector ./my-detector.mjs --rule-plugin ./my-action.mjs \\
    -r uses-my-kind.json -- node ./my-server.js

  # Render a shareable HTML advisory from a recorded session + its findings
  mcpwn -l session.jsonl --findings-out ./out -- node ./my-server.js
  mcpwn report session.jsonl --findings ./out -o report.html

  # Reverse-proxy a remote HTTP MCP server
  mcpwn http --listen 127.0.0.1:8900 --upstream https://mcp.example.com/mcp \\
    -r attack.json --findings-out ./out

CONFIG (in your MCP client) — wrap the existing command:
  before:  { "command": "npx", "args": ["-y", "@some/server"] }
  after:   { "command": "mcpwn", "args": ["--", "npx", "-y", "@some/server"] }
`;

/** Flags shared by the stdio proxy and the http subcommand. */
export interface SharedArgs {
  ruleFiles: string[];
  /** Community templates to load by id (resolved against the bundled gallery). */
  templateIds: string[];
  logFile?: string;
  verbose: boolean;
  scopeMethods: string[];
  scopeTools: string[];
  scopeDirection?: Direction;
  onlyTampered: boolean;
  scopeAffectsLog: boolean;
  findingsOut?: string;
  baselineFile?: string;
  baselineCapture?: string;
  redact: boolean;
  redactFile?: string;
  /** Custom passive detectors to load (`--detector <file.mjs>`, repeatable). */
  detectorPlugins: string[];
  /** Custom tamper-action plugins to load (`--rule-plugin <file.mjs>`, repeatable). */
  ruleActionPlugins: string[];
}

export interface ParsedArgs extends SharedArgs {
  intercept: boolean;
  command?: string;
  commandArgs: string[];
}

/** Thrown for malformed CLI input (missing option value, unknown flag). The
 *  caller prints the message and usage, then exits non-zero. */
export class ArgError extends Error {}

function emptyShared(): SharedArgs {
  return {
    ruleFiles: [],
    templateIds: [],
    verbose: false,
    scopeMethods: [],
    scopeTools: [],
    onlyTampered: false,
    scopeAffectsLog: false,
    redact: false,
    detectorPlugins: [],
    ruleActionPlugins: [],
  };
}

/** Parse a flag shared by stdio + http. Returns true if `a` was consumed; the
 *  caller advances `i` via the returned next index. */
function parseSharedFlag(a: string, argv: string[], i: number, out: SharedArgs): number | null {
  const need = (what: string): string => {
    const val = argv[++i];
    if (val === undefined) throw new ArgError(`option ${a} requires ${what}`);
    return val;
  };
  switch (a) {
    case "-v":
    case "--verbose":
      out.verbose = true;
      return i;
    case "-r":
    case "--rule":
      out.ruleFiles.push(need("a <file> argument"));
      return i;
    case "--template":
      out.templateIds.push(need("a <id> argument"));
      return i;
    case "--detector":
      out.detectorPlugins.push(need("a <file.mjs> argument"));
      return i;
    case "--rule-plugin":
      out.ruleActionPlugins.push(need("a <file.mjs> argument"));
      return i;
    case "-l":
    case "--log":
      out.logFile = need("a <file> argument");
      return i;
    case "--findings-out":
      out.findingsOut = need("a <dir> argument");
      return i;
    case "--baseline":
      out.baselineFile = need("a <file> argument");
      return i;
    case "--baseline-capture":
      out.baselineCapture = need("a <file> argument");
      return i;
    case "--redact":
      out.redact = true;
      return i;
    case "--redact-file":
      out.redactFile = need("a <file> argument");
      return i;
    case "--scope-method":
      out.scopeMethods.push(need("a <glob> argument"));
      return i;
    case "--scope-tool":
      out.scopeTools.push(need("a <name> argument"));
      return i;
    case "--scope-direction": {
      const val = need("c2s or s2c");
      if (val === "c2s") out.scopeDirection = "client->server";
      else if (val === "s2c") out.scopeDirection = "server->client";
      else throw new ArgError(`option ${a} must be "c2s" or "s2c" (got "${val}")`);
      return i;
    }
    case "--only-tampered":
      out.onlyTampered = true;
      return i;
    case "--scope-affects-log":
      out.scopeAffectsLog = true;
      return i;
    // Config flags are resolved in a pre-scan (so the config can seed defaults
    // BEFORE the rest of the args parse); consume them here so they are not
    // rejected as unknown. --config takes a value; --no-auto-config is a toggle.
    case "--config":
      need("a <file> argument");
      return i;
    case "--no-auto-config":
      return i;
    default:
      return null;
  }
}

/** Seed a SharedArgs from a loaded config (defaults < config layer). The CLI
 *  parse then runs on top: list flags append, scalar flags override. */
export function sharedFromConfig(config?: McpwnConfig): SharedArgs {
  const base = emptyShared();
  if (!config) return base;
  if (config.rules) base.ruleFiles.push(...config.rules);
  if (config.templates) base.templateIds.push(...config.templates);
  if (config.scope?.methods) base.scopeMethods.push(...config.scope.methods);
  if (config.scope?.tools) base.scopeTools.push(...config.scope.tools);
  if (config.scope?.direction) {
    base.scopeDirection = config.scope.direction === "c2s" ? "client->server" : "server->client";
  }
  if (config.redact) base.redact = true;
  if (config.redactFile) base.redactFile = config.redactFile;
  if (config.findingsOut) base.findingsOut = config.findingsOut;
  if (config.log) base.logFile = config.log;
  if (config.verbose) base.verbose = true;
  return base;
}

/**
 * Resolve + load the config for a CLI invocation. Returns the parsed config (if
 * any), the SharedArgs seed it produces, and a notice string to print once a
 * logger exists. Exits 2 (via the supplied `fail`) on a malformed config.
 */
export function resolveConfig(
  argv: string[],
  fail: (msg: string) => never
): { config?: McpwnConfig; seed: SharedArgs; notice?: string } {
  const pre = preScanConfigFlags(argv);
  const chosen = resolveConfigPath({ explicit: pre.configFile, noAuto: pre.noAuto });
  if (!chosen) return { seed: emptyShared() };
  let config: McpwnConfig;
  try {
    config = loadConfig(chosen.path);
  } catch (err) {
    if (err instanceof ConfigError) fail(err.message);
    throw err;
  }
  const notice = chosen.auto
    ? `loaded ${chosen.path} (auto; pass --no-auto-config to skip)`
    : `loaded config ${chosen.path}`;
  return { config, seed: sharedFromConfig(config), notice };
}

export function parseArgs(
  argv: string[],
  base: SharedArgs = emptyShared()
): ParsedArgs | "help" | "version" {
  const out: ParsedArgs = { ...base, intercept: false, commandArgs: [] };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      i++;
      break;
    }
    if (a === "-h" || a === "--help") return "help";
    if (a === "--version") return "version";
    if (a === "-i" || a === "--intercept") {
      out.intercept = true;
      continue;
    }
    const next = parseSharedFlag(a, argv, i, out);
    if (next !== null) {
      i = next;
      continue;
    }
    // Reject stray flags instead of treating them as the command — an unknown
    // `--foo` is almost always a typo or a misplaced server flag.
    if (a.startsWith("-")) {
      throw new ArgError(
        `unknown option "${a}" — put the server command (and its flags) after "--"`
      );
    }
    // First non-flag before `--` is treated as the command start.
    out.command = a;
    out.commandArgs = argv.slice(i + 1);
    return out;
  }
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

export interface HttpArgs extends SharedArgs {
  listenHost: string;
  listenPort: number;
  upstream: string;
  mode: HttpMode;
  /** Set when -i was passed (ignored for HTTP, but warned about). */
  interceptRequested: boolean;
}

export function parseHttpArgs(argv: string[], base: SharedArgs = emptyShared()): HttpArgs {
  const shared = base;
  let listen: string | undefined;
  let upstream: string | undefined;
  let mode: HttpMode = "auto";
  let interceptRequested = false;

  const need = (a: string, what: string, i: number): [string, number] => {
    const val = argv[i + 1];
    if (val === undefined) throw new ArgError(`option ${a} requires ${what}`);
    return [val, i + 1];
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--listen") {
      [listen, i] = need(a, "host:port", i);
      continue;
    }
    if (a === "--upstream") {
      [upstream, i] = need(a, "a <url>", i);
      continue;
    }
    if (a === "--mode") {
      const [val, ni] = need(a, "streamable|sse|auto", i);
      if (val !== "streamable" && val !== "sse" && val !== "auto") {
        throw new ArgError(`option --mode must be streamable|sse|auto (got "${val}")`);
      }
      mode = val;
      i = ni;
      continue;
    }
    if (a === "-i" || a === "--intercept") {
      interceptRequested = true;
      continue;
    }
    const next = parseSharedFlag(a, argv, i, shared);
    if (next !== null) {
      i = next;
      continue;
    }
    throw new ArgError(`unknown option "${a}" for "mcpwn http"`);
  }

  if (!listen) throw new ArgError("mcpwn http: --listen host:port is required");
  if (!upstream) throw new ArgError("mcpwn http: --upstream <url> is required");

  const { host, port } = parseListen(listen);
  return { ...shared, listenHost: host, listenPort: port, upstream, mode, interceptRequested };
}

/** Parse "host:port", ":port" or "port". Host defaults to 127.0.0.1. */
export function parseListen(spec: string): { host: string; port: number } {
  const idx = spec.lastIndexOf(":");
  let host = "127.0.0.1";
  let portStr = spec;
  if (idx !== -1) {
    const h = spec.slice(0, idx);
    if (h.length) host = h;
    portStr = spec.slice(idx + 1);
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new ArgError(`invalid --listen port "${portStr}" (expected host:port)`);
  }
  return { host, port };
}

/** `mcpwn payloads list | show <name>`. */
function runPayloads(args: string[]): number {
  const action = args[0] ?? "list";
  if (action === "list") {
    for (const name of listPayloads()) process.stdout.write(name + "\n");
    return 0;
  }
  if (action === "show") {
    const name = args[1];
    if (!name) {
      process.stderr.write("mcpwn payloads show: missing <name>\n");
      return 2;
    }
    let lines: string[];
    try {
      lines = loadPayloads(name);
    } catch (err) {
      process.stderr.write(`mcpwn: ${(err as Error).message}\n`);
      return 2;
    }
    for (const l of lines) process.stdout.write(l + "\n");
    return 0;
  }
  process.stderr.write(
    `mcpwn payloads: unknown subcommand "${action}" (use "list" or "show <name>")\n`
  );
  return 2;
}

/** `mcpwn templates list | show <id> | lint [dir]` — the community gallery
 *  (§3.12). Mirrors `payloads`: `list` prints a table, `show` pretty-prints a
 *  template's metadata + rules, `lint` validates a directory of templates against
 *  schema/templates.schema.json (the contribution flow). */
function runTemplates(args: string[]): number {
  const action = args[0] ?? "list";

  if (action === "list") {
    const items = listTemplates();
    if (items.length === 0) {
      process.stderr.write("mcpwn templates: no templates found\n");
      return 0;
    }
    const headers = ["ID", "NAME", "SEVERITY", "ATTACK CLASS"];
    const rows = items.map((t) => [t.id, t.info.name, t.info.severity, t.info.attackClass]);
    const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
    const fmt = (cols: string[]): string =>
      cols
        .map((c, i) => c.padEnd(widths[i]))
        .join("  ")
        .trimEnd();
    process.stdout.write(fmt(headers) + "\n");
    for (const r of rows) process.stdout.write(fmt(r) + "\n");
    return 0;
  }

  if (action === "show") {
    const id = args[1];
    if (!id) {
      process.stderr.write("mcpwn templates show: missing <id>\n");
      return 2;
    }
    const t = findTemplate(id);
    if (!t) {
      const ids = listTemplates()
        .map((x) => x.id)
        .join(", ");
      process.stderr.write(`mcpwn templates: unknown template "${id}" (available: ${ids})\n`);
      return 2;
    }
    const w = process.stdout;
    w.write(`id:          ${t.id}\n`);
    w.write(`name:        ${t.info.name}\n`);
    w.write(`severity:    ${t.info.severity}\n`);
    w.write(`attackClass: ${t.info.attackClass}\n`);
    w.write(`author:      ${t.info.author}\n`);
    if (t.info.cwe) w.write(`cwe:         ${t.info.cwe}\n`);
    if (t.info.mcpVersion) w.write(`mcpVersion:  ${t.info.mcpVersion}\n`);
    w.write(`description: ${t.info.description}\n`);
    if (t.info.references?.length) {
      w.write(`references:\n`);
      for (const r of t.info.references) w.write(`  - ${r}\n`);
    }
    w.write(`\nrules:\n${JSON.stringify(t.rules, null, 2)}\n`);
    return 0;
  }

  if (action === "lint") {
    const results = lintTemplates(args[1]);
    if (results.length === 0) {
      process.stderr.write("mcpwn templates lint: no .json templates found\n");
      return 0;
    }
    let failed = 0;
    for (const r of results) {
      if (r.ok) {
        process.stdout.write(`ok    ${r.file}${r.id ? ` (${r.id})` : ""}\n`);
      } else {
        failed++;
        process.stdout.write(`FAIL  ${r.file}\n`);
        for (const e of r.errors) process.stdout.write(`        - ${e}\n`);
      }
    }
    process.stderr.write(
      `\nmcpwn templates lint: ${results.length - failed}/${results.length} ok\n`
    );
    return failed ? 2 : 0;
  }

  process.stderr.write(
    `mcpwn templates: unknown subcommand "${action}" (use "list", "show <id>" or "lint [dir]")\n`
  );
  return 2;
}

/** `mcpwn baseline capture [--out <file>] [-v] -- <command> [args...]` */
async function runBaseline(argv: string[]): Promise<number> {
  const sub = argv[0];
  if (sub !== "capture") {
    process.stderr.write(`mcpwn baseline: unknown subcommand "${sub ?? ""}" (use "capture")\n`);
    return 2;
  }
  let out = "baseline.json";
  let verbose = false;
  let command: string | undefined;
  let commandArgs: string[] = [];
  const rest = argv.slice(1);
  let i = 0;
  for (; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--") {
      i++;
      break;
    }
    if (a === "--out" || a === "-o") {
      const val = rest[++i];
      if (val === undefined) {
        process.stderr.write("mcpwn baseline: option --out requires a <file>\n");
        return 2;
      }
      out = val;
      continue;
    }
    if (a === "-v" || a === "--verbose") {
      verbose = true;
      continue;
    }
    if (a.startsWith("-")) {
      process.stderr.write(`mcpwn baseline: unknown option "${a}"\n`);
      return 2;
    }
    command = a;
    commandArgs = rest.slice(i + 1);
    break;
  }
  if (command === undefined) {
    command = rest[i];
    commandArgs = rest.slice(i + 1);
  }
  if (!command) {
    process.stderr.write("mcpwn baseline capture: missing server command (after --)\n");
    return 2;
  }
  const logger = new Logger({ verbose });
  return captureBaseline(command, commandArgs, out, logger);
}

/** Resolve redaction patterns (built-in + file), or undefined when disabled. */
function resolveRedact(redact: boolean, redactFile?: string): RedactPattern[] | undefined {
  if (!redact && !redactFile) return undefined;
  const out: RedactPattern[] = [];
  if (redact) out.push(...builtinRedactPatterns());
  if (redactFile) out.push(...loadRedactPatterns(redactFile));
  return out;
}

interface DetectionLayer {
  findings?: FindingsSink;
  detectors: Detector[];
  writeOnExit: () => void;
}

/** Build the detector list + findings sink shared by both transports, and a
 *  synchronous writer to run on process exit. */
function buildDetection(
  a: SharedArgs,
  logger: Logger,
  pluginDetectors: Detector[] = []
): DetectionLayer {
  const detectors: Detector[] = [];
  const needSink = !!a.findingsOut || !!a.baselineFile || pluginDetectors.length > 0;
  const findings = needSink ? new ArrayFindingsSink() : undefined;

  if (a.findingsOut) detectors.push(...builtinLinters());
  if (a.baselineFile) detectors.push(new BaselineDetector(loadBaseline(a.baselineFile)));
  if (a.baselineCapture) detectors.push(new BaselineCaptureDetector(a.baselineCapture, logger));
  // Custom detectors (§3.11) run alongside the built-ins; the pipeline wraps each
  // in the same read-only try/catch, so a throwing plugin can't block the wire.
  detectors.push(...pluginDetectors);

  const writeOnExit = () => {
    if (!findings) return;
    const items = findings.all();
    if (a.findingsOut) {
      try {
        writeFindingsDir(a.findingsOut, items);
        logger.info(`wrote ${items.length} finding(s) -> ${a.findingsOut}`);
      } catch (err) {
        logger.error(`could not write findings: ${(err as Error).message}`);
      }
    } else if (items.length) {
      logger.info(`${items.length} finding(s) recorded (use --findings-out <dir> to write them)`);
    }
  };
  return { findings, detectors, writeOnExit };
}

/** Assemble a scope only when the operator asked for one; otherwise undefined
 *  so traffic stays fully transparent (Invariant #3). */
function buildScope(a: SharedArgs): Scope | undefined {
  const hasScope =
    a.scopeMethods.length > 0 ||
    a.scopeTools.length > 0 ||
    a.scopeDirection !== undefined ||
    a.onlyTampered;
  if (!hasScope) return undefined;
  return {
    methods: a.scopeMethods.length ? a.scopeMethods : undefined,
    tools: a.scopeTools.length ? a.scopeTools : undefined,
    direction: a.scopeDirection,
    onlyTampered: a.onlyTampered || undefined,
  };
}

/** Load every tamper rule from -r files AND --template ids. `actionKinds` are the
 *  custom kinds registered by any --rule-plugin, so a rule file may reference one
 *  without tripping validation (§3.11). Exits 2 on any load/validation error. */
function loadAllRules(a: SharedArgs, logger: Logger, actionKinds: string[]): Rule[] {
  let rules: Rule[] = [];
  for (const f of a.ruleFiles) {
    try {
      rules = rules.concat(loadRules(f, actionKinds));
    } catch (err) {
      logger.error(`could not load rule file "${f}": ${(err as Error).message}`);
      process.exit(2);
    }
  }
  for (const id of a.templateIds) {
    const tmpl = findTemplate(id);
    if (!tmpl) {
      logger.error(`unknown template "${id}" — run "mcpwn templates list" to see available ids`);
      process.exit(2);
    }
    rules = rules.concat(tmpl.rules);
  }
  return rules;
}

interface LoadedPlugins {
  detectors: (Detector & { name: string })[];
  actionRegistry: RuleActionRegistry;
}

/**
 * Load the `--detector` and `--rule-plugin` modules, printing a one-line startup
 * notice per plugin (trust model: loading runs local code — see plugins/index.ts).
 * Exits 2 with a clear message when a plugin is missing or does not implement its
 * interface. Never fetches anything remote; only explicit CLI paths are loaded.
 */
async function loadPlugins(a: SharedArgs, logger: Logger): Promise<LoadedPlugins> {
  const detectors: (Detector & { name: string })[] = [];
  for (const p of a.detectorPlugins) {
    let d: Detector & { name: string };
    try {
      d = await loadDetectorPlugin(p);
    } catch (err) {
      logger.error((err as Error).message);
      process.exit(2);
    }
    logger.info(
      `detector plugin loaded: ${d.name} <- ${p} (runs local code — trusted sources only)`
    );
    detectors.push(d);
  }
  const actions: RuleActionPlugin[] = [];
  for (const p of a.ruleActionPlugins) {
    let rp: RuleActionPlugin;
    try {
      rp = await loadRuleActionPlugin(p);
    } catch (err) {
      logger.error((err as Error).message);
      process.exit(2);
    }
    logger.info(
      `rule-plugin loaded: kind "${rp.kind}" <- ${p} (runs local code — trusted sources only)`
    );
    actions.push(rp);
  }
  return { detectors, actionRegistry: buildActionRegistry(actions) };
}

async function runHttp(argv: string[]): Promise<number> {
  let configNotice: string | undefined;
  let seed: SharedArgs | undefined;
  try {
    const cfg = resolveConfig(argv, (msg) => {
      throw new ConfigError(msg);
    });
    seed = cfg.seed;
    configNotice = cfg.notice;
  } catch (err) {
    process.stderr.write(`mcpwn: ${(err as Error).message}\n`);
    return 2;
  }

  let parsed: HttpArgs;
  try {
    parsed = parseHttpArgs(argv, seed);
  } catch (err) {
    if (err instanceof ArgError) {
      process.stderr.write(`mcpwn: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  let redactPatterns: RedactPattern[] | undefined;
  try {
    redactPatterns = resolveRedact(parsed.redact, parsed.redactFile);
  } catch (err) {
    process.stderr.write(`mcpwn: could not load redaction patterns: ${(err as Error).message}\n`);
    return 2;
  }

  const logger = new Logger({ logFile: parsed.logFile, verbose: parsed.verbose, redactPatterns });
  if (configNotice) logger.info(configNotice);
  if (parsed.interceptRequested) {
    logger.info("interactive intercept (-i) is disabled for HTTP in v2 — ignoring");
  }

  const plugins = await loadPlugins(parsed, logger);
  const rules = loadAllRules(parsed, logger, [...plugins.actionRegistry.keys()]);
  let detection: DetectionLayer;
  try {
    detection = buildDetection(parsed, logger, plugins.detectors);
  } catch (err) {
    logger.error((err as Error).message);
    return 2;
  }
  if (detection.findings) process.on("exit", detection.writeOnExit);

  const pipeline = new MessagePipeline({
    rules,
    logger,
    scope: buildScope(parsed),
    scopeAffectsLog: parsed.scopeAffectsLog,
    detectors: detection.detectors,
    findings: detection.findings,
    ruleActionPlugins: plugins.actionRegistry,
    holdTimeoutMs: 0, // interactive disabled for HTTP; plumbed for completeness
  });

  const transport = new HttpTransport({
    listenHost: parsed.listenHost,
    listenPort: parsed.listenPort,
    upstream: parsed.upstream,
    mode: parsed.mode,
    pipeline,
    logger,
  });

  return transport.start();
}

async function main() {
  const argv = process.argv.slice(2);

  // Subcommands are dispatched before option parsing so their bare first token
  // is not mistaken for the proxied command.
  if (argv[0] === "payloads") process.exit(runPayloads(argv.slice(1)));
  if (argv[0] === "templates") process.exit(runTemplates(argv.slice(1)));
  if (argv[0] === "replay") process.exit(await runReplay(argv.slice(1)));
  if (argv[0] === "scan") process.exit(await runScan(argv.slice(1)));
  if (argv[0] === "report") process.exit(await runReport(argv.slice(1)));
  if (argv[0] === "baseline") process.exit(await runBaseline(argv.slice(1)));
  if (argv[0] === "http") process.exit(await runHttp(argv.slice(1)));

  const cfg = resolveConfig(argv, (msg) => {
    process.stderr.write(`mcpwn: ${msg}\n`);
    process.exit(2);
  });

  let parsed: ParsedArgs | "help" | "version";
  try {
    parsed = parseArgs(argv, cfg.seed);
  } catch (err) {
    if (err instanceof ArgError) {
      process.stderr.write(`mcpwn: ${err.message}\n\n`);
      process.stderr.write(HELP);
      process.exit(2);
    }
    throw err;
  }

  if (parsed === "help") {
    process.stderr.write(HELP);
    process.exit(0);
  }
  if (parsed === "version") {
    const { createRequire } = await import("node:module");
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json");
    process.stdout.write(`${pkg.version}\n`);
    process.exit(0);
  }

  if (!parsed.command) {
    process.stderr.write(HELP);
    process.exit(2);
  }

  let redactPatterns: RedactPattern[] | undefined;
  try {
    redactPatterns = resolveRedact(parsed.redact, parsed.redactFile);
  } catch (err) {
    process.stderr.write(`mcpwn: could not load redaction patterns: ${(err as Error).message}\n`);
    process.exit(2);
  }

  const logger = new Logger({ logFile: parsed.logFile, verbose: parsed.verbose, redactPatterns });
  if (cfg.notice) logger.info(cfg.notice);
  const plugins = await loadPlugins(parsed, logger);
  const rules = loadAllRules(parsed, logger, [...plugins.actionRegistry.keys()]);

  let detection: DetectionLayer;
  try {
    detection = buildDetection(parsed, logger, plugins.detectors);
  } catch (err) {
    logger.error((err as Error).message);
    process.exit(2);
  }
  if (detection.findings) process.on("exit", detection.writeOnExit);

  const intercept = parsed.intercept ? new InterceptController(true) : undefined;

  const pipeline = new MessagePipeline({
    rules,
    logger,
    intercept,
    scope: buildScope(parsed),
    scopeAffectsLog: parsed.scopeAffectsLog,
    detectors: detection.detectors,
    findings: detection.findings,
    ruleActionPlugins: plugins.actionRegistry,
  });

  // Compact end-of-session tally on exit (stderr only — the MCP stdout channel
  // is never touched). Registered after the findings writer so findings are
  // flushed to disk before the summary counts them.
  process.on("exit", () => {
    logger.sessionSummary(pipeline.summary(), detection.findings?.all() ?? []);
  });
  const transport = new StdioTransport({
    command: parsed.command,
    args: parsed.commandArgs,
    pipeline,
    logger,
    ruleCount: rules.length,
    intercept,
  });

  const code = await transport.start();
  process.exit(code);
}

// Only run when invoked as the binary, not when imported (e.g. by tests).
const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (invokedPath === import.meta.url) {
  main().catch((err) => {
    process.stderr.write(`mcpwn fatal: ${err?.stack ?? err}\n`);
    process.exit(1);
  });
}
