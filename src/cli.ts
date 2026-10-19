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
import { ArrayFindingsSink, writeFindingsDir, type FindingsSink } from "./findings.js";
import { builtinLinters } from "./detect/linter.js";
import {
  BaselineDetector,
  BaselineCaptureDetector,
  loadBaseline,
  captureBaseline,
} from "./detect/baseline.js";
import type { Detector } from "./detect/detector.js";
import { builtinRedactPatterns, loadRedactPatterns, type RedactPattern } from "./redact.js";
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
  mcpwn payloads list | show <name>

  Wraps a stdio MCP server: the host launches mcpwn, mcpwn launches the
  real server and relays traffic, logging every message to stderr.

OPTIONS
  -i, --intercept       Interactively hold each message for review
                        (forward / drop / edit / tamper). Needs a terminal.
                        (stdio only — disabled for HTTP in v2.)
  -r, --rule <file>     Load a JSON tamper-rule file (repeatable).
  -l, --log <file>      Append a JSONL session log of all traffic.
  -v, --verbose         Pretty-print full message bodies to stderr.
  -h, --help            Show this help.
      --version         Print version.

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
  payloads list                     List bundled payload libraries.
  payloads show <name>              Print a payload library (one per line).

EXAMPLES
  # Passive X-ray: watch all traffic, change nothing
  mcpwn -v -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Tamper + report: inject, scan for secrets/poisoning, write an advisory
  mcpwn -r attack.json --findings-out ./out -- node ./my-server.js

  # Rug-pull detection: capture once, then watch for tool-definition drift
  mcpwn baseline capture --out base.json -- node ./my-server.js
  mcpwn --baseline base.json --findings-out ./out -- node ./my-server.js

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
    verbose: false,
    scopeMethods: [],
    scopeTools: [],
    onlyTampered: false,
    scopeAffectsLog: false,
    redact: false,
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
    default:
      return null;
  }
}

export function parseArgs(argv: string[]): ParsedArgs | "help" | "version" {
  const out: ParsedArgs = { ...emptyShared(), intercept: false, commandArgs: [] };
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

export function parseHttpArgs(argv: string[]): HttpArgs {
  const shared = emptyShared();
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
function buildDetection(a: SharedArgs, logger: Logger): DetectionLayer {
  const detectors: Detector[] = [];
  const needSink = !!a.findingsOut || !!a.baselineFile;
  const findings = needSink ? new ArrayFindingsSink() : undefined;

  if (a.findingsOut) detectors.push(...builtinLinters());
  if (a.baselineFile) detectors.push(new BaselineDetector(loadBaseline(a.baselineFile)));
  if (a.baselineCapture) detectors.push(new BaselineCaptureDetector(a.baselineCapture, logger));

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

function loadAllRules(files: string[], logger: Logger): Rule[] {
  let rules: Rule[] = [];
  for (const f of files) {
    try {
      rules = rules.concat(loadRules(f));
    } catch (err) {
      logger.error(`could not load rule file "${f}": ${(err as Error).message}`);
      process.exit(2);
    }
  }
  return rules;
}

async function runHttp(argv: string[]): Promise<number> {
  let parsed: HttpArgs;
  try {
    parsed = parseHttpArgs(argv);
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
  if (parsed.interceptRequested) {
    logger.info("interactive intercept (-i) is disabled for HTTP in v2 — ignoring");
  }

  const rules = loadAllRules(parsed.ruleFiles, logger);
  let detection: DetectionLayer;
  try {
    detection = buildDetection(parsed, logger);
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
  if (argv[0] === "replay") process.exit(await runReplay(argv.slice(1)));
  if (argv[0] === "baseline") process.exit(await runBaseline(argv.slice(1)));
  if (argv[0] === "http") process.exit(await runHttp(argv.slice(1)));

  let parsed: ParsedArgs | "help" | "version";
  try {
    parsed = parseArgs(argv);
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
  const rules = loadAllRules(parsed.ruleFiles, logger);

  let detection: DetectionLayer;
  try {
    detection = buildDetection(parsed, logger);
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
