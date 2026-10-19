import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { LineFramer } from "../engine/parser.js";
import type { InterceptController } from "../engine/intercept.js";
import type { MessagePipeline } from "../core/pipeline.js";
import type { Transport, TransportDeps } from "./transport.js";
import type { Direction } from "../types.js";

export interface StdioTransportOptions extends TransportDeps {
  command: string;
  args: string[];
  /** Number of active rules, for the startup banner (the pipeline owns the
   *  rules themselves). Defaults to 0. */
  ruleCount?: number;
  /** When set, hold messages for interactive review (the Repeater loop). The
   *  same controller is handed to the pipeline, which drives the review; the
   *  transport only owns its lifecycle (availability + start/stop). */
  intercept?: InterceptController;
}

/**
 * Wrap-and-spawn stdio relay.
 *
 *   host ──stdin──►  mcpwn  ──child.stdin──►  real server
 *   host ◄─stdout──  mcpwn  ◄─child.stdout──  real server
 *
 * Framing lives here (one JSON message per line); the pipeline decides what to
 * forward. Each framed line is handed to `pipeline.process`, and whatever it
 * returns is written back with the stdio newline (unless it was dropped).
 * Unparseable lines are relayed opaquely by the pipeline (NFR-3). The child's
 * own stderr is passed straight through so server logs survive.
 */
export class StdioTransport implements Transport {
  private child!: ChildProcessByStdio<Writable, Readable, null>;
  private closing = false;
  private pipeline: MessagePipeline;
  private intercept?: InterceptController;

  constructor(private opts: StdioTransportOptions) {
    this.pipeline = opts.pipeline;
    this.intercept = opts.intercept;
  }

  start(): Promise<number> {
    const { command, args, logger } = this.opts;
    logger.banner(`${command} ${args.join(" ")}`.trim(), this.opts.ruleCount ?? 0);

    this.child = spawn(command, args, {
      stdio: ["pipe", "pipe", "inherit"],
    });

    this.child.on("error", (err) => {
      logger.error(`failed to spawn "${command}": ${err.message}`);
      this.shutdown(127);
    });

    // Interactive intercept needs a controlling terminal; degrade gracefully.
    // When unavailable we simply never start the controller: shouldHold() then
    // reports false, so the pipeline auto-forwards without holding.
    if (this.intercept) {
      if (this.intercept.available()) {
        this.intercept.start();
      } else {
        logger.info("interactive intercept requested but no /dev/tty — auto-forwarding");
        this.intercept = undefined;
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

  stop(): void {
    this.shutdown(0);
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
      queue = queue.then(() => this.handleLine(raw, dst, direction)).catch((err) => {
        // Never block the wire: if handling a line fails unexpectedly, forward
        // the original bytes untouched rather than silently dropping them (the
        // host would otherwise hang waiting for a response that never comes).
        this.opts.logger.error(
          `pump failure (${direction}); forwarding raw line: ${(err as Error)?.message ?? err}`
        );
        try {
          dst.write(raw + "\n");
        } catch {
          /* destination already gone */
        }
      });
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
    // The pipeline owns parse→correlate→rules→intercept→log and returns the
    // exact bytes to forward (no framing), or null to drop. We add the stdio
    // newline and nothing else, so idle traffic is byte-identical.
    const { forward } = await this.pipeline.process(raw, direction);
    if (forward !== null) dst.write(forward + "\n");
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
    this.intercept?.stop();
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
