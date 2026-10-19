#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { StdioTransport } from "./transports/stdio.js";
import { MessagePipeline } from "./core/pipeline.js";
import { loadRules } from "./engine/rules.js";
import { InterceptController } from "./engine/intercept.js";
import { Logger } from "./logger.js";
import { loadPayloads, listPayloads } from "./payloads/index.js";
import { runReplay } from "./replay.js";
import type { Scope } from "./core/scope.js";
import type { Direction, Rule } from "./types.js";

const HELP = `mcpwn — intercept & tamper proxy for MCP traffic

  X-ray and tamper the JSON-RPC between an AI agent and its MCP servers.
  Burp Suite for AI agents. AUTHORIZED TESTING ONLY.

USAGE
  mcpwn [options] -- <command> [args...]
  mcpwn replay <session.jsonl> [options] -- <command> [args...]
  mcpwn payloads list | show <name>

  Wraps a stdio MCP server: the host launches mcpwn, mcpwn launches the
  real server and relays traffic, logging every message to stderr.

OPTIONS
  -i, --intercept       Interactively hold each message for review
                        (forward / drop / edit / tamper). Needs a terminal.
  -r, --rule <file>     Load a JSON tamper-rule file (repeatable).
  -l, --log <file>      Append a JSONL session log of all traffic.
  -v, --verbose         Pretty-print full message bodies to stderr.
  -h, --help            Show this help.
      --version         Print version.

SCOPING (§3.6 — out-of-scope traffic is forwarded untouched + hidden)
      --scope-method <glob>   Only methods matching this glob (repeatable).
      --scope-tool <name>     Only tools/call for this tool name (repeatable).
      --scope-direction c2s|s2c   Only this direction.
      --only-tampered         Only messages a rule actually changed.
      --scope-affects-log     Also omit out-of-scope traffic from --log.

SUBCOMMANDS
  replay <session.jsonl> -- <cmd>   Replay recorded client->server traffic
                                    through a fresh server (rules apply).
                                    Flags: -r, -l, -v, --only-method, --repeat <n>
  payloads list                     List bundled payload libraries.
  payloads show <name>              Print a payload library (one per line).

EXAMPLES
  # Passive X-ray: watch all traffic, change nothing
  mcpwn -v -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Tamper: inject into tool results / poison descriptions via rules
  mcpwn -r attack.json -- node ./my-server.js

  # Scope to a single tool's calls, hide everything else
  mcpwn --scope-tool read_file --scope-direction c2s -- node ./my-server.js

  # Fuzz a tool argument by replaying a recorded call with a payload list
  mcpwn replay session.jsonl -r fuzz.json --repeat 25 -- node ./my-server.js

CONFIG (in your MCP client) — wrap the existing command:
  before:  { "command": "npx", "args": ["-y", "@some/server"] }
  after:   { "command": "mcpwn", "args": ["--", "npx", "-y", "@some/server"] }
`;

export interface ParsedArgs {
  ruleFiles: string[];
  logFile?: string;
  verbose: boolean;
  intercept: boolean;
  /** Scope filters (§3.6). Empty arrays / undefined mean "no constraint". */
  scopeMethods: string[];
  scopeTools: string[];
  scopeDirection?: Direction;
  onlyTampered: boolean;
  scopeAffectsLog: boolean;
  command?: string;
  commandArgs: string[];
}

/** Thrown for malformed CLI input (missing option value, unknown flag). The
 *  caller prints the message and usage, then exits non-zero. */
export class ArgError extends Error {}

export function parseArgs(argv: string[]): ParsedArgs | "help" | "version" {
  const out: ParsedArgs = {
    ruleFiles: [],
    verbose: false,
    intercept: false,
    scopeMethods: [],
    scopeTools: [],
    onlyTampered: false,
    scopeAffectsLog: false,
    commandArgs: [],
  };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      i++;
      break;
    }
    switch (a) {
      case "-h":
      case "--help":
        return "help";
      case "--version":
        return "version";
      case "-v":
      case "--verbose":
        out.verbose = true;
        break;
      case "-i":
      case "--intercept":
        out.intercept = true;
        break;
      case "-r":
      case "--rule": {
        const val = argv[++i];
        if (val === undefined) throw new ArgError(`option ${a} requires a <file> argument`);
        out.ruleFiles.push(val);
        break;
      }
      case "-l":
      case "--log": {
        const val = argv[++i];
        if (val === undefined) throw new ArgError(`option ${a} requires a <file> argument`);
        out.logFile = val;
        break;
      }
      case "--scope-method": {
        const val = argv[++i];
        if (val === undefined) throw new ArgError(`option ${a} requires a <glob> argument`);
        out.scopeMethods.push(val);
        break;
      }
      case "--scope-tool": {
        const val = argv[++i];
        if (val === undefined) throw new ArgError(`option ${a} requires a <name> argument`);
        out.scopeTools.push(val);
        break;
      }
      case "--scope-direction": {
        const val = argv[++i];
        if (val === undefined) throw new ArgError(`option ${a} requires c2s or s2c`);
        if (val === "c2s") out.scopeDirection = "client->server";
        else if (val === "s2c") out.scopeDirection = "server->client";
        else throw new ArgError(`option ${a} must be "c2s" or "s2c" (got "${val}")`);
        break;
      }
      case "--only-tampered":
        out.onlyTampered = true;
        break;
      case "--scope-affects-log":
        out.scopeAffectsLog = true;
        break;
      default:
        // Reject stray flags instead of treating them as the command — an
        // unknown `--foo` is almost always a typo or a misplaced server flag
        // (those belong after `--`).
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
  }
  // Everything after `--`
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

/** `mcpwn payloads list | show <name>`. Payload output goes to stdout (this is a
 *  standalone command, not the proxy, so stdout is normal pipeable output). */
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
  process.stderr.write(`mcpwn payloads: unknown subcommand "${action}" (use "list" or "show <name>")\n`);
  return 2;
}

async function main() {
  const argv = process.argv.slice(2);

  // Subcommands are dispatched before option parsing so their bare first token
  // (e.g. a session file) is not mistaken for the proxied command.
  if (argv[0] === "payloads") {
    process.exit(runPayloads(argv.slice(1)));
  }
  if (argv[0] === "replay") {
    process.exit(await runReplay(argv.slice(1)));
  }

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
    // Read lazily to avoid a hard dep at module load.
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

  const logger = new Logger({ logFile: parsed.logFile, verbose: parsed.verbose });

  let rules: Rule[] = [];
  for (const f of parsed.ruleFiles) {
    try {
      rules = rules.concat(loadRules(f));
    } catch (err) {
      logger.error(`could not load rule file "${f}": ${(err as Error).message}`);
      process.exit(2);
    }
  }

  const intercept = parsed.intercept ? new InterceptController(true) : undefined;

  // Assemble a scope only when the operator asked for one; otherwise leave it
  // undefined so traffic stays fully transparent (Invariant #3).
  const hasScope =
    parsed.scopeMethods.length > 0 ||
    parsed.scopeTools.length > 0 ||
    parsed.scopeDirection !== undefined ||
    parsed.onlyTampered;
  const scope: Scope | undefined = hasScope
    ? {
        methods: parsed.scopeMethods.length ? parsed.scopeMethods : undefined,
        tools: parsed.scopeTools.length ? parsed.scopeTools : undefined,
        direction: parsed.scopeDirection,
        onlyTampered: parsed.onlyTampered || undefined,
      }
    : undefined;

  // The pipeline owns parse→correlate→rules→intercept→log→forward; the
  // transport owns framing + I/O. They share one intercept controller.
  const pipeline = new MessagePipeline({
    rules,
    logger,
    intercept,
    scope,
    scopeAffectsLog: parsed.scopeAffectsLog,
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
