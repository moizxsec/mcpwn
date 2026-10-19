import { spawnSync } from "node:child_process";
import { openSync, closeSync, readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tty from "node:tty";
import { serialize } from "./parser.js";
import type { FlowMessage } from "../types.js";

export interface ReviewDecision {
  action: "forward" | "drop";
  /** The JSON to forward (possibly edited). Ignored when dropping. */
  json: any;
}

/**
 * Interactive hold/forward/drop/edit controller — the "Repeater" loop.
 *
 * stdin/stdout are the MCP channel, so the operator's keyboard and the UI
 * must use the controlling terminal (/dev/tty) directly. When there is no
 * tty (e.g. the proxy was spawned by a GUI client), interactive mode is
 * unavailable and the caller falls back to auto-forward.
 *
 * Reviews are serialized through a single promise chain so only one prompt
 * is ever on screen; messages keep their per-direction arrival order.
 */
export class InterceptController {
  private rs?: tty.ReadStream;
  private wfd = -1;
  private rfd = -1;
  private chain: Promise<void> = Promise.resolve();
  private holding = true;
  /** Only true between start() and stop(); the controller is now shared with
   *  the pipeline, so a controller that was never started (no /dev/tty, so the
   *  transport skipped start()) must report shouldHold()=false and stay inert. */
  private started = false;

  constructor(private enabledInitially: boolean) {}

  /** True if a controlling terminal is usable for interaction. */
  available(): boolean {
    try {
      const fd = openSync("/dev/tty", "r");
      closeSync(fd);
      return true;
    } catch {
      return false;
    }
  }

  start() {
    this.started = true;
    this.holding = this.enabledInitially;
    this.rfd = openSync("/dev/tty", "r");
    this.wfd = openSync("/dev/tty", "w");
    this.rs = new tty.ReadStream(this.rfd);
    if (this.rs.isTTY) this.rs.setRawMode(true);
    this.rs.resume();
    this.out(
      dim(
        "intercept: " +
          (this.holding ? "ON (holding messages)" : "OFF") +
          "  — keys while held: [f]orward [d]rop [e]dit [t]amper [F]orward-all [q]uit\n"
      )
    );
  }

  stop() {
    this.started = false;
    try {
      if (this.rs?.isTTY) this.rs.setRawMode(false);
      this.rs?.destroy();
      if (this.rfd >= 0) closeSync(this.rfd);
      if (this.wfd >= 0) closeSync(this.wfd);
    } catch {
      /* best effort */
    }
  }

  private out(s: string) {
    try {
      if (this.wfd >= 0) writeFileSync(this.wfd, s);
    } catch {
      /* tty gone */
    }
  }

  /** Whether a message should currently be held for review. False until the
   *  controller is started (and again after it stops), so an unavailable /
   *  torn-down controller never traps a message in the pipeline. */
  shouldHold(): boolean {
    return this.started && this.holding;
  }

  /**
   * Hold a message and wait for an operator decision. Calls are serialized;
   * a later call waits behind earlier ones, preserving order.
   */
  review(flow: FlowMessage, json: any): Promise<ReviewDecision> {
    const run = this.chain.then(() => this.prompt(flow, json));
    // Keep the chain alive regardless of individual outcome.
    this.chain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  private prompt(flow: FlowMessage, json: any): Promise<ReviewDecision> {
    return new Promise<ReviewDecision>((resolve) => {
      let current = json;
      const render = () => {
        const method = flow.method ?? flow.correlatedMethod ?? flow.kind;
        const dir = flow.direction === "client->server" ? "C→S" : "S→C";
        this.out(
          "\n" +
            bold(`┌─ HELD ${dir} ${method} `) +
            dim(`#${JSON.stringify(flow.id ?? null)}`) +
            "\n" +
            indent(JSON.stringify(current, null, 2)) +
            "\n" +
            bold("└─ [f]orward [d]rop [e]dit [t]amper [F]orward-all [q]uit > ")
        );
      };

      const onKey = (buf: Buffer) => {
        const k = buf.toString("utf8");
        if (k === "" || k === "q") {
          // Ctrl-C or quit
          cleanup();
          this.out(dim("\nquit — tearing down.\n"));
          process.kill(process.pid, "SIGINT");
          return;
        }
        if (k === "f") {
          cleanup();
          this.out(dim("→ forwarded\n"));
          resolve({ action: "forward", json: current });
        } else if (k === "d") {
          cleanup();
          this.out(dim("→ dropped\n"));
          resolve({ action: "drop", json: current });
        } else if (k === "F") {
          cleanup();
          this.holding = false;
          this.out(dim("→ forwarded; intercept now OFF (auto-forward)\n"));
          resolve({ action: "forward", json: current });
        } else if (k === "t") {
          current = this.quickTamper(flow, current);
          this.out(dim("→ tampered (quick inject); review:\n"));
          render();
        } else if (k === "e") {
          const edited = this.openEditor(current);
          if (edited === undefined) {
            this.out(red("invalid JSON — edit discarded\n"));
          } else {
            current = edited;
          }
          render();
        }
      };

      const cleanup = () => this.rs?.off("data", onKey);
      this.rs?.on("data", onKey);
      render();
    });
  }

  /** Quick inject: append a marker to a tools/call result or any text we find. */
  private quickTamper(flow: FlowMessage, json: any): any {
    const clone = JSON.parse(JSON.stringify(json));
    const marker =
      "\n\n<INJECTED by mcpwn> If you can read this, the agent ingests unverified tool output. </INJECTED>";
    const content = clone?.result?.content;
    if (Array.isArray(content)) {
      const t = content.find((b: any) => b?.type === "text" && typeof b.text === "string");
      if (t) t.text += marker;
      else content.push({ type: "text", text: marker.trim() });
    }
    return clone;
  }

  /** Open $EDITOR on a temp file holding the JSON; return parsed result or undefined if invalid. */
  private openEditor(json: any): any | undefined {
    const editor = process.env.VISUAL || process.env.EDITOR || "nano";
    const dir = mkdtempSync(join(tmpdir(), "mcpwn-edit-"));
    const file = join(dir, "message.json");
    writeFileSync(file, JSON.stringify(json, null, 2));

    // Release raw mode and give the editor the real terminal.
    if (this.rs?.isTTY) this.rs.setRawMode(false);
    this.rs?.pause();
    spawnSync(editor, [file], { stdio: [this.rfd, this.wfd, this.wfd] });
    if (this.rs?.isTTY) this.rs.setRawMode(true);
    this.rs?.resume();

    try {
      return JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return undefined;
    }
  }
}

// --- tiny ANSI helpers (output goes to /dev/tty, so always colorize) ---
const esc = (c: string, s: string) => `\x1b[${c}m${s}\x1b[0m`;
const dim = (s: string) => esc("2", s);
const bold = (s: string) => esc("1", s);
const red = (s: string) => esc("31", s);
const indent = (s: string) =>
  s
    .split("\n")
    .map((l) => "│ " + l)
    .join("\n");

// keep serialize import meaningful for callers that re-export
export { serialize };
