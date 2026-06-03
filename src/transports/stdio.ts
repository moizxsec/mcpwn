import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { LineFramer, parseLine, serialize } from "../engine/parser.js";
import { Correlator } from "../engine/correlator.js";
import { applyRules } from "../engine/rules.js";
import { InterceptController } from "../engine/intercept.js";
import type { Direction, FlowMessage, Rule } from "../types.js";
import type { Logger } from "../logger.js";

export interface StdioProxyOptions {
  command: string;
  args: string[];
  rules: Rule[];
  logger: Logger;
  /** When set, hold messages for interactive review (the Repeater loop). */
  intercept?: InterceptController;
}

/**
 * Wrap-and-spawn stdio relay.
 *
 *   host ──stdin──►  mcpwn  ──child.stdin──►  real server
 *   host ◄─stdout──  mcpwn  ◄─child.stdout──  real server
 *
 * Every line is parsed, correlated, run through rules, logged to stderr,
 * then forwarded. Unparseable lines are relayed opaquely (NFR-3). The
 * child's own stderr is passed straight through so server logs survive.
 */
export class StdioProxy {
  private child!: ChildProcessByStdio<Writable, Readable, null>;
  private correlator = new Correlator();
  private closing = false;

  constructor(private opts: StdioProxyOptions) {}

  start(): Promise<number> {
    const { command, args, logger } = this.opts;
    logger.banner(`${command} ${args.join(" ")}`.trim(), this.opts.rules.length);

    this.child = spawn(command, args, {
      stdio: ["pipe", "pipe", "inherit"],
    });

    this.child.on("error", (err) => {
      logger.error(`failed to spawn "${command}": ${err.message}`);
      this.shutdown(127);
    });

    // Interactive intercept needs a controlling terminal; degrade gracefully.
    if (this.opts.intercept) {
      if (this.opts.intercept.available()) {
        this.opts.intercept.start();
      } else {
        logger.info("interactive intercept requested but no /dev/tty — auto-forwarding");
        this.opts.intercept = undefined;
      }
    }

    // client -> server : host stdin into child stdin
    this.pump(process.stdin, this.child.stdin, "client->server");
    // server -> client : child stdout into host stdout
    this.pump(this.child.stdout, process.stdout, "server->client");

    return new Promise<number>((resolve) => {
      this.child.on("close", (code) => {
        if (!this.closing) logger.info(`server exited (code ${code ?? 0})`);
        resolve(code ?? 0);
      });
      this.installSignalHandlers();
    });
  }

  private pump(
    src: NodeJS.ReadableStream,
    dst: NodeJS.WritableStream,
    direction: Direction
  ) {
    const framer = new LineFramer();
    // Per-direction async chain: preserves forward order even when a message
    // is held for interactive review (which awaits operator input).
    let queue: Promise<void> = Promise.resolve();
    const enqueue = (raw: string) => {
      queue = queue.then(() => this.handleLine(raw, dst, direction)).catch(() => {});
    };

    src.on("data", (chunk: Buffer) => {
      for (const line of framer.push(chunk)) enqueue(line);
    });
    src.on("end", () => {
      const rest = framer.flush();
      if (rest) enqueue(rest);
      // Half-close downstream after the queue drains, so the peer sees EOF.
      queue.then(() => {
        if (dst !== process.stdout && typeof (dst as any).end === "function") {
          (dst as any).end();
        }
      });
    });
  }

  private async handleLine(raw: string, dst: NodeJS.WritableStream, direction: Direction) {
    const parsed = parseLine(raw);

    // Maintain correlation map regardless of tampering.
    if (direction === "client->server") this.correlator.noteRequest(parsed);
    const correlatedMethod =
      direction === "server->client" ? this.correlator.resolve(parsed) : undefined;

    const flow: FlowMessage = { ...parsed, direction, correlatedMethod, ts: Date.now() };

    // Opaque relay for anything we couldn't parse — never block the wire.
    if (parsed.kind === "unknown" || !parsed.json) {
      this.opts.logger.message(flow, [], false);
      dst.write(raw + "\n");
      return;
    }

    // 1) Headless rules run first (auto-tamper).
    const result = applyRules(this.opts.rules, flow);
    if (result.json === null) {
      this.opts.logger.message(flow, result.applied, true);
      return; // dropped by a rule
    }

    // 2) Interactive review (optional) — operator sees the rule-applied message.
    let outJson = result.json;
    let changed = result.changed;
    if (this.opts.intercept?.shouldHold()) {
      const decision = await this.opts.intercept.review(flow, outJson);
      if (decision.action === "drop") {
        this.opts.logger.message(flow, [...result.applied, "manual-drop"], true);
        return;
      }
      if (JSON.stringify(decision.json) !== JSON.stringify(outJson)) {
        outJson = decision.json;
        changed = true;
      }
    }

    this.opts.logger.message(flow, result.applied, false);
    const out = changed ? serialize(outJson) : raw;
    dst.write(out + "\n");
  }

  private installSignalHandlers() {
    const onSignal = (sig: NodeJS.Signals) => {
      this.opts.logger.info(`received ${sig}, tearing down server`);
      this.shutdown(0);
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
  }

  private shutdown(code: number) {
    if (this.closing) return;
    this.closing = true;
    this.opts.intercept?.stop();
    try {
      this.child?.kill("SIGTERM");
    } catch {
      /* already gone */
    }
    // Give the child a moment, then hard-exit so we never orphan it (NFR-8).
    setTimeout(() => {
      try {
        this.child?.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      process.exit(code);
    }, 500).unref();
  }
}
