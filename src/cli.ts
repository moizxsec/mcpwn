#!/usr/bin/env node
import { StdioProxy } from "./transports/stdio.js";
import { loadRules } from "./engine/rules.js";
import { InterceptController } from "./engine/intercept.js";
import { Logger } from "./logger.js";
import type { Rule } from "./types.js";

const HELP = `mcpwn — intercept & tamper proxy for MCP traffic

  X-ray and tamper the JSON-RPC between an AI agent and its MCP servers.
  Burp Suite for AI agents. AUTHORIZED TESTING ONLY.

USAGE
  mcpwn [options] -- <command> [args...]

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

EXAMPLES
  # Passive X-ray: watch all traffic, change nothing
  mcpwn -v -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Tamper: inject into tool results / poison descriptions via rules
  mcpwn -r attack.json -- node ./my-server.js

CONFIG (in your MCP client) — wrap the existing command:
  before:  { "command": "npx", "args": ["-y", "@some/server"] }
  after:   { "command": "mcpwn", "args": ["--", "npx", "-y", "@some/server"] }
`;

interface ParsedArgs {
  ruleFiles: string[];
  logFile?: string;
  verbose: boolean;
  intercept: boolean;
  command?: string;
  commandArgs: string[];
}

function parseArgs(argv: string[]): ParsedArgs | "help" | "version" {
  const out: ParsedArgs = { ruleFiles: [], verbose: false, intercept: false, commandArgs: [] };
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
      case "--rule":
        out.ruleFiles.push(argv[++i]);
        break;
      case "-l":
      case "--log":
        out.logFile = argv[++i];
        break;
      default:
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

async function main() {
  const argv = process.argv.slice(2);
  const parsed = parseArgs(argv);

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

  const proxy = new StdioProxy({
    command: parsed.command,
    args: parsed.commandArgs,
    rules,
    logger,
    intercept: parsed.intercept ? new InterceptController(true) : undefined,
  });

  const code = await proxy.start();
  process.exit(code);
}

main().catch((err) => {
  process.stderr.write(`mcpwn fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
