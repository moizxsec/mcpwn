import type { Direction, FlowMessage } from "../types.js";

/**
 * Scoping / filtering (§3.6). A scope narrows which messages mcpwn treats as
 * "interesting" — i.e. which ones get held for interactive review and shown on
 * the stderr log. Out-of-scope traffic is ALWAYS forwarded untouched (the
 * pipeline never runs rules or holds it); it is merely suppressed from the
 * human log, and optionally from the JSONL session log.
 */
export interface Scope {
  /** Glob patterns matched against the (resolved) JSON-RPC method. `*` matches
   *  any run of characters, `?` a single character. */
  methods?: string[];
  /** Tool names matched against `params.name` (the tool being called). */
  tools?: string[];
  /** Restrict to a single direction. */
  direction?: Direction;
  /** Only messages a rule actually tampered are in scope (post-rules filter). */
  onlyTampered?: boolean;
}

/** Compile a shell-style glob to an anchored RegExp. Only `*` and `?` are
 *  special; every other character is matched literally. */
function globToRegExp(glob: string): RegExp {
  const body = glob
    .split("")
    .map((ch) => {
      if (ch === "*") return ".*";
      if (ch === "?") return ".";
      return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("");
  return new RegExp("^" + body + "$");
}

/** The tool name a message refers to, if it carries one (tools/call requests
 *  put it at `params.name`). Responses carry no name on the wire. */
function toolName(flow: FlowMessage): string | undefined {
  const name = flow.json?.params?.name;
  return typeof name === "string" ? name : undefined;
}

/**
 * Is `flow` in scope? With no scope, everything is in scope (transparent).
 *
 * All specified criteria must match. `applied` is the list of rules that fired
 * (pass it after rules run); it is only consulted when `onlyTampered` is set,
 * so callers gating rule execution should omit it (or clear `onlyTampered`).
 */
export function inScope(scope: Scope | undefined, flow: FlowMessage, applied?: string[]): boolean {
  if (!scope) return true;

  if (scope.direction && scope.direction !== flow.direction) return false;

  if (scope.methods && scope.methods.length > 0) {
    const method = flow.method ?? flow.correlatedMethod ?? "";
    if (!scope.methods.some((g) => globToRegExp(g).test(method))) return false;
  }

  if (scope.tools && scope.tools.length > 0) {
    const name = toolName(flow);
    if (name === undefined || !scope.tools.includes(name)) return false;
  }

  if (scope.onlyTampered) {
    if (!applied || applied.length === 0) return false;
  }

  return true;
}
