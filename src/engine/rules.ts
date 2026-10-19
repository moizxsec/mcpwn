import { readFileSync } from "node:fs";
import type { FlowMessage, Rule, RuleAction } from "../types.js";
import { validateRuleFile } from "./validate.js";

export interface RuleResult {
  /** The (possibly rewritten) JSON to forward, or null to DROP the message. */
  json: any;
  /** Names of rules that fired, for logging. */
  applied: string[];
  changed: boolean;
}

/** Minimal logging surface used for rule-failure reporting; the real Logger
 *  satisfies it. Kept narrow so the rules engine stays easy to test. */
export interface RuleLogger {
  error(text: string): void;
}

export function loadRules(path: string): Rule[] {
  const data = JSON.parse(readFileSync(path, "utf8"));
  const result = validateRuleFile(data);
  if (!result.ok) {
    // Surface every problem at once; the CLI logs this and exits 2.
    throw new Error(`invalid rule file:\n  - ${result.errors.join("\n  - ")}`);
  }
  return result.rules;
}

/** Does this rule apply to the given flow message? */
function matches(rule: Rule, msg: FlowMessage): boolean {
  if (rule.enabled === false) return false;
  if (rule.direction && rule.direction !== msg.direction) return false;
  if (rule.kind && rule.kind !== msg.kind) return false;
  if (rule.method) {
    const method = msg.method ?? msg.correlatedMethod;
    if (method !== rule.method) return false;
  }
  return true;
}

function applyText(original: string, text: string, mode: string | undefined): string {
  switch (mode) {
    case "prepend":
      return text + original;
    case "replace":
      return text;
    case "append":
    default:
      return original + text;
  }
}

/** Apply a single action in-place to the message JSON. Returns true if changed. */
function applyAction(action: RuleAction, json: any): boolean {
  switch (action.kind) {
    case "drop":
      return true; // signalled separately by caller

    case "matchReplace": {
      const before = JSON.stringify(json);
      const re = new RegExp(action.find, action.flags ?? "g");
      const after = before.replace(re, action.replace);
      if (after === before) return false;
      // Re-parse so we forward valid JSON, not a mangled string.
      let reparsed: any;
      try {
        reparsed = JSON.parse(after);
      } catch {
        return false; // refuse to forward invalid JSON
      }
      // Guard: a JSON-RPC message is always a JSON object. If the replace
      // turned it into an array or scalar, Object.assign would silently
      // corrupt the message — refuse the change and keep the original.
      if (reparsed === null || typeof reparsed !== "object" || Array.isArray(reparsed)) {
        return false;
      }
      for (const k of Object.keys(json)) delete json[k];
      Object.assign(json, reparsed);
      return true;
    }

    case "injectToolResult": {
      // server->client tools/call response: result.content[] text blocks.
      const content = json?.result?.content;
      if (!Array.isArray(content)) return false;
      let changed = false;
      const target = content.find((b: any) => b?.type === "text" && typeof b.text === "string");
      if (target) {
        target.text = applyText(target.text, action.text, action.mode);
        changed = true;
      } else if (action.mode !== "replace") {
        content.push({ type: "text", text: action.text });
        changed = true;
      }
      return changed;
    }

    case "poisonDescription": {
      // server->client tools/list response: result.tools[].description.
      const tools = json?.result?.tools;
      if (!Array.isArray(tools)) return false;
      let changed = false;
      for (const t of tools) {
        // Skip holes / non-object entries so a malformed tools array can't
        // throw (setting a property on null) and abort the whole message.
        if (t == null || typeof t !== "object") continue;
        if (action.tool && t.name !== action.tool) continue;
        if (typeof t.description !== "string") t.description = "";
        t.description = applyText(t.description, action.text, action.mode);
        changed = true;
      }
      return changed;
    }

    default: {
      // Unreachable for well-formed rules (the loader validates kinds), but an
      // unknown kind must FAIL LOUD here rather than silently no-op: the per-rule
      // try/catch in applyRules turns this throw into a logged error and forwards
      // the message untampered, so the wire is never blocked (NFR-8).
      const kind = (action as { kind?: unknown }).kind;
      throw new Error(`unknown action kind: ${String(kind)}`);
    }
  }
}

/**
 * Run all rules against a flow message. Headless tamper core: returns the
 * JSON to forward (or null to drop) plus which rules fired.
 *
 * A rule that throws (e.g. an invalid regex, malformed payload) must never
 * take the message down with it: the failure is logged, any partial mutation
 * is rolled back, and the message is forwarded UNtampered for that rule. Only
 * an explicit `drop` action stops forwarding.
 */
export function applyRules(rules: Rule[], msg: FlowMessage, logger?: RuleLogger): RuleResult {
  if (!msg.json) return { json: msg.json, applied: [], changed: false };

  // Deep clone so an aborted/partial mutation never corrupts the raw record.
  const json = JSON.parse(JSON.stringify(msg.json));
  const applied: string[] = [];
  let changed = false;

  for (const rule of rules) {
    if (!matches(rule, msg)) continue;
    if (rule.action.kind === "drop") {
      return { json: null, applied: [...applied, rule.name], changed: true };
    }

    // Snapshot before the (mutating) action so a throw rolls back cleanly.
    const snapshot = JSON.stringify(json);
    let did = false;
    try {
      did = applyAction(rule.action, json);
    } catch (err) {
      // Restore the pre-rule state in place (keep the same object identity so
      // later rules and the caller see an intact message), then carry on.
      const restored = JSON.parse(snapshot);
      for (const k of Object.keys(json)) delete json[k];
      Object.assign(json, restored);
      logger?.error(
        `rule "${rule.name}" threw (${(err as Error)?.message ?? err}); forwarding untampered`
      );
      did = false;
    }
    if (did) {
      applied.push(rule.name);
      changed = true;
    }
  }

  return { json, applied, changed };
}
