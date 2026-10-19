import { appendFileSync } from "node:fs";
import type { FlowMessage } from "./types.js";

/**
 * All human-facing output goes to STDERR. stdout/stdin are the MCP channel
 * and must stay byte-clean (NFR-1). Never console.log here.
 */

const useColor = process.stderr.isTTY && !process.env.NO_COLOR;

const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s: string) => c("2", s);
const bold = (s: string) => c("1", s);
const red = (s: string) => c("31", s);
const green = (s: string) => c("32", s);
const yellow = (s: string) => c("33", s);
const cyan = (s: string) => c("36", s);

function arrow(dir: FlowMessage["direction"]): string {
  return dir === "client->server" ? cyan("C→S") : green("S→C");
}

export interface LoggerOptions {
  /** Also append structured JSONL records to this file (session log). */
  logFile?: string;
  /** Print full pretty-printed bodies, not just a one-line summary. */
  verbose?: boolean;
}

export interface MessageLogExtra {
  /** The exact bytes actually forwarded on the wire (no trailing newline),
   *  or null when the message was dropped. Defaults to the original raw line
   *  when omitted (untampered relay). */
  forwarded?: string | null;
  /** True when the operator hand-edited the message in interactive mode. */
  manualEdit?: boolean;
}

export class Logger {
  constructor(private opts: LoggerOptions = {}) {}

  private write(line: string) {
    process.stderr.write(line + "\n");
  }

  banner(childCmd: string, ruleCount: number) {
    this.write(bold(cyan("mcpwn")) + dim(" — MCP intercept & tamper proxy"));
    this.write(dim(`  proxying: ${childCmd}`));
    this.write(dim(`  rules:    ${ruleCount} active`));
    this.write(dim("  authorized testing only — traffic stays local, no telemetry"));
    this.write("");
  }

  message(msg: FlowMessage, applied: string[], dropped: boolean, extra: MessageLogExtra = {}) {
    const manualEdit = extra.manualEdit ?? false;
    const method = msg.method ?? msg.correlatedMethod ?? dim("(" + msg.kind + ")");
    const id = msg.id !== undefined ? dim(`#${JSON.stringify(msg.id)}`) : "";
    let tag = "";
    if (dropped) {
      tag = " " + red("[DROPPED]");
    } else {
      const parts: string[] = [];
      if (applied.length) parts.push(`tampered: ${applied.join(",")}`);
      if (manualEdit) parts.push("edited");
      if (parts.length) tag = " " + yellow(`[${parts.join(" ")}]`);
    }

    this.write(`${arrow(msg.direction)} ${bold(String(method))} ${id}${tag}`);

    if (this.opts.verbose && msg.json) {
      const pretty = JSON.stringify(msg.json, null, 2)
        .split("\n")
        .map((l) => dim("  │ ") + l)
        .join("\n");
      this.write(pretty);
    }

    if (this.opts.logFile) {
      // Evidence integrity: record BOTH the original line we received and the
      // exact bytes we put back on the wire (null if dropped), plus whether a
      // human hand-edited it — not just whether a rule fired.
      const record = {
        ts: msg.ts,
        direction: msg.direction,
        kind: msg.kind,
        method: msg.method ?? msg.correlatedMethod ?? null,
        id: msg.id ?? null,
        applied,
        dropped,
        manualEdit,
        raw: msg.raw,
        forwarded: dropped ? null : extra.forwarded ?? msg.raw,
      };
      try {
        appendFileSync(this.opts.logFile, JSON.stringify(record) + "\n");
      } catch {
        /* best-effort session log */
      }
    }
  }

  error(text: string) {
    this.write(red("mcpwn error: ") + text);
  }

  info(text: string) {
    this.write(dim("mcpwn: " + text));
  }
}
