import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { MessagePipeline } from "./core/pipeline.js";
import { LineFramer, parseLine } from "./engine/parser.js";
import { loadRules } from "./engine/rules.js";
import { Logger } from "./logger.js";
import type { Rule } from "./types.js";

/**
 * Session replay (§3.8).
 *
 *   mcpwn replay <session.jsonl> [options] -- <server> [args...]
 *
 * Reads a JSONL session log, keeps the client->server requests + notifications,
 * and feeds each (through a fresh MessagePipeline so tamper rules — including
 * stateful `fuzzArgs` — apply) into a freshly-spawned MCP server over stdio,
 * printing the server's responses to stdout. Pairs with `fuzzArgs` + `--repeat`
 * to cycle a payload list through the same request.
 *
 * Unlike the proxy, replay owns its own child process and drives it directly, so
 * stdout here is normal CLI output (the recorded host is simulated, not wired to
 * our stdout). Human progress + per-message logs go to stderr.
 */

export class ReplayArgError extends Error {}

export interface ReplayArgs {
  sessionFile?: string;
  ruleFiles: string[];
  logFile?: string;
  verbose: boolean;
  /** Only replay messages whose method equals this. */
  onlyMethod?: string;
  /** Replay the whole selected sequence this many times (cycles fuzz payloads). */
  repeat: number;
  command?: string;
  commandArgs: string[];
}

export function parseReplayArgs(argv: string[]): ReplayArgs {
  const out: ReplayArgs = { ruleFiles: [], verbose: false, repeat: 1, commandArgs: [] };
  let i = 0;
  const value = (flag: string): string => {
    const v = argv[++i];
    if (v === undefined) throw new ReplayArgError(`option ${flag} requires an argument`);
    return v;
  };
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      i++;
      break;
    }
    switch (a) {
      case "-r":
      case "--rule":
        out.ruleFiles.push(value(a));
        break;
      case "-l":
      case "--log":
        out.logFile = value(a);
        break;
      case "-v":
      case "--verbose":
        out.verbose = true;
        break;
      case "--only-method":
        out.onlyMethod = value(a);
        break;
      case "--repeat": {
        const n = Number(value(a));
        if (!Number.isInteger(n) || n < 1) {
          throw new ReplayArgError(`--repeat must be a positive integer`);
        }
        out.repeat = n;
        break;
      }
      default:
        if (a.startsWith("-")) {
          throw new ReplayArgError(
            `unknown option "${a}" - put the server command (and its flags) after "--"`
          );
        }
        if (out.sessionFile === undefined) {
          out.sessionFile = a;
          break;
        }
        // Second bare token starts the server command (no "--" required).
        out.command = a;
        out.commandArgs = argv.slice(i + 1);
        return out;
    }
  }
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

interface SessionRecord {
  raw: string;
  direction?: string;
  kind?: string;
  method?: string;
}

/** The client->server requests/notifications to replay, in order. */
function selectRecords(records: SessionRecord[], onlyMethod?: string): SessionRecord[] {
  return records.filter((r) => {
    if (typeof r.raw !== "string") return false;
    if (r.direction !== "client->server") return false;
    const parsed = parseLine(r.raw);
    const kind = r.kind ?? parsed.kind;
    if (kind !== "request" && kind !== "notification") return false;
    if (onlyMethod !== undefined) {
      const method = r.method ?? parsed.method;
      if (method !== onlyMethod) return false;
    }
    return true;
  });
}

const RESPONSE_TIMEOUT_MS = 5000;

export async function runReplay(argv: string[]): Promise<number> {
  let args: ReplayArgs;
  try {
    args = parseReplayArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn replay: ${(err as Error).message}\n`);
    return 2;
  }
  if (!args.sessionFile) {
    process.stderr.write("mcpwn replay: missing <session.jsonl>\n");
    return 2;
  }
  if (!args.command) {
    process.stderr.write('mcpwn replay: missing server command (put it after "--")\n');
    return 2;
  }

  const logger = new Logger({ logFile: args.logFile, verbose: args.verbose });

  let rules: Rule[] = [];
  for (const f of args.ruleFiles) {
    try {
      rules = rules.concat(loadRules(f));
    } catch (err) {
      logger.error(`could not load rule file "${f}": ${(err as Error).message}`);
      return 2;
    }
  }

  let records: SessionRecord[];
  try {
    records = readFileSync(args.sessionFile, "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as SessionRecord);
  } catch (err) {
    logger.error(`could not read session "${args.sessionFile}": ${(err as Error).message}`);
    return 2;
  }

  const selected = selectRecords(records, args.onlyMethod);
  if (selected.length === 0) {
    logger.info("no client->server requests/notifications to replay");
    return 0;
  }

  logger.info(
    `replaying ${selected.length} message(s) x${args.repeat} against: ` +
      `${args.command} ${args.commandArgs.join(" ")}`.trim()
  );

  const child = spawn(args.command, args.commandArgs, { stdio: ["pipe", "pipe", "inherit"] });
  // One pipeline for the whole replay so fuzzArgs cursors advance across sends.
  const pipeline = new MessagePipeline({ rules, logger });

  const pending = new Map<string, () => void>();
  const framer = new LineFramer();
  let serverChain: Promise<void> = Promise.resolve();

  const onServerLine = async (line: string) => {
    // Run the response through the pipeline too (correlation + any s->c rules),
    // then print it to stdout as the replay's machine-readable output.
    const { forward, flow } = await pipeline.process(line, "server->client");
    const out = forward ?? line;
    process.stdout.write(out + "\n");
    if (flow.id !== undefined) {
      const key = JSON.stringify(flow.id);
      const resolve = pending.get(key);
      if (resolve) {
        pending.delete(key);
        resolve();
      }
    }
  };

  child.stdout.on("data", (chunk: Buffer) => {
    for (const line of framer.push(chunk)) {
      serverChain = serverChain.then(() => onServerLine(line)).catch(() => undefined);
    }
  });

  const spawnFailed = new Promise<number>((resolve) => {
    child.on("error", (err) => {
      logger.error(`failed to spawn "${args.command}": ${err.message}`);
      resolve(127);
    });
  });

  const driver = (async (): Promise<number> => {
    for (let rep = 0; rep < args.repeat; rep++) {
      for (const rec of selected) {
        const { forward, flow } = await pipeline.process(rec.raw, "client->server");
        if (forward === null) continue; // dropped by a rule
        child.stdin.write(forward + "\n");
        // Requests expect a reply; wait for it (bounded) so sends stay ordered
        // and fuzz payloads pair cleanly with their responses.
        if (flow.kind === "request" && flow.id !== undefined) {
          const key = JSON.stringify(flow.id);
          await new Promise<void>((resolve) => {
            const timer = setTimeout(() => {
              pending.delete(key);
              resolve();
            }, RESPONSE_TIMEOUT_MS);
            pending.set(key, () => {
              clearTimeout(timer);
              resolve();
            });
          });
        }
      }
    }
    child.stdin.end();
    return await new Promise<number>((resolve) => {
      child.on("close", (code) => resolve(code ?? 0));
    });
  })();

  return Promise.race([spawnFailed, driver]);
}
