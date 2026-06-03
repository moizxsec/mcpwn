import { readFileSync } from "node:fs";
import type { FlowMessage, Rule, RuleAction, RuleFile } from "../types.js";

export interface RuleResult {
  /** The (possibly rewritten) JSON to forward, or null to DROP the message. */
  json: any;
  /** Names of rules that fired, for logging. */
  applied: string[];
  changed: boolean;
}

export function loadRules(path: string): Rule[] {
  const data = JSON.parse(readFileSync(path, "utf8")) as RuleFile;
  if (!data || !Array.isArray(data.rules)) {
    throw new Error(`Rule file ${path} has no "rules" array`);
  }
  return data.rules;
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
      try {
        const reparsed = JSON.parse(after);
        for (const k of Object.keys(json)) delete json[k];
        Object.assign(json, reparsed);
        return true;
      } catch {
        return false; // refuse to forward invalid JSON
      }
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
        if (action.tool && t?.name !== action.tool) continue;
        if (typeof t?.description !== "string") t.description = "";
        t.description = applyText(t.description, action.text, action.mode);
        changed = true;
      }
      return changed;
    }
  }
}

/**
 * Run all rules against a flow message. Headless tamper core: returns the
 * JSON to forward (or null to drop) plus which rules fired.
 */
export function applyRules(rules: Rule[], msg: FlowMessage): RuleResult {
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
    const did = applyAction(rule.action, json);
    if (did) {
      applied.push(rule.name);
      changed = true;
    }
  }

  return { json, applied, changed };
}
