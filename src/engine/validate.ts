import type { Direction, MessageKind, Rule } from "../types.js";

/**
 * Hand-rolled, zero-dependency validation for tamper-rule files. We refuse to
 * pull in a JSON-Schema runtime (NFR-6: zero runtime deps) yet still want the
 * precise, friendly errors a schema would give — including "did you mean …?"
 * suggestions for mistyped action kinds and field names. `schema/rules.schema.json`
 * is the published machine-readable mirror of these rules for editors/CI.
 */

export type ValidationResult =
  | { ok: true; rules: Rule[] }
  | { ok: false; errors: string[] };

const DIRECTIONS: Direction[] = ["client->server", "server->client"];
const MESSAGE_KINDS: MessageKind[] = ["request", "response", "error", "notification", "unknown"];
const ACTION_KINDS = [
  "injectToolResult",
  "poisonDescription",
  "matchReplace",
  "setArg",
  "rewriteArgs",
  "fuzzArgs",
  "drop",
] as const;
const MODES = ["append", "prepend", "replace"];
const REWRITE_MODES = ["replace", "merge"];

/** Allowed keys per rule and per action kind — used for typo detection. */
const RULE_FIELDS = ["name", "enabled", "direction", "method", "kind", "action"];
const ACTION_FIELDS: Record<string, string[]> = {
  injectToolResult: ["kind", "text", "mode"],
  poisonDescription: ["kind", "tool", "text", "mode"],
  matchReplace: ["kind", "find", "replace", "flags"],
  setArg: ["kind", "tool", "path", "value"],
  rewriteArgs: ["kind", "tool", "args", "mode"],
  fuzzArgs: ["kind", "tool", "path", "payloads"],
  drop: ["kind"],
};

/** Classic Levenshtein edit distance (iterative, two-row). */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

/** Nearest candidate within a tolerance proportional to its length, or none. */
function nearest(input: string, candidates: readonly string[]): string | undefined {
  let best: string | undefined;
  let bestDistance = Infinity;
  for (const c of candidates) {
    const d = levenshtein(input, c);
    if (d < bestDistance) {
      bestDistance = d;
      best = c;
    }
  }
  if (best !== undefined && bestDistance <= Math.max(2, Math.floor(best.length / 2))) {
    return best;
  }
  return undefined;
}

/** `" (did you mean \"x\"?)"` when a close candidate exists, else "". */
function suggest(input: string, candidates: readonly string[]): string {
  const n = nearest(input, candidates);
  return n ? ` (did you mean "${n}"?)` : "";
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/** Validate a whole rule file (already JSON-parsed). Collects every error. */
export function validateRuleFile(data: unknown): ValidationResult {
  if (!isPlainObject(data)) {
    return {
      ok: false,
      errors: [`rule file must be a JSON object with a "rules" array (got ${typeName(data)})`],
    };
  }
  if (!("rules" in data)) {
    return { ok: false, errors: ['rule file: missing required "rules" array'] };
  }
  if (!Array.isArray(data.rules)) {
    return { ok: false, errors: [`rule file: "rules" must be an array (got ${typeName(data.rules)})`] };
  }

  const errors: string[] = [];
  data.rules.forEach((rule, i) => validateRule(rule, `rules[${i}]`, errors));

  if (errors.length) return { ok: false, errors };
  return { ok: true, rules: data.rules as Rule[] };
}

function validateRule(rule: unknown, path: string, errors: string[]): void {
  if (!isPlainObject(rule)) {
    errors.push(`${path}: must be an object (got ${typeName(rule)})`);
    return;
  }

  // name (required, string)
  if (!("name" in rule)) {
    errors.push(`${path}: missing required "name"`);
  } else if (typeof rule.name !== "string") {
    errors.push(`${path}.name: must be a string (got ${typeName(rule.name)})`);
  }

  // enabled (optional, boolean)
  if ("enabled" in rule && typeof rule.enabled !== "boolean") {
    errors.push(`${path}.enabled: must be a boolean (got ${typeName(rule.enabled)})`);
  }

  // direction (optional, enum)
  if ("direction" in rule && !DIRECTIONS.includes(rule.direction as Direction)) {
    errors.push(
      `${path}.direction: must be one of ${quoteList(DIRECTIONS)} (got ${render(rule.direction)})`
    );
  }

  // method (optional, string)
  if ("method" in rule && typeof rule.method !== "string") {
    errors.push(`${path}.method: must be a string (got ${typeName(rule.method)})`);
  }

  // kind (optional, enum)
  if ("kind" in rule && !MESSAGE_KINDS.includes(rule.kind as MessageKind)) {
    errors.push(
      `${path}.kind: must be one of ${quoteList(MESSAGE_KINDS)} (got ${render(rule.kind)})`
    );
  }

  // Unknown rule-level keys (typo detection).
  for (const key of Object.keys(rule)) {
    if (!RULE_FIELDS.includes(key)) {
      errors.push(`${path}: unknown field "${key}"${suggest(key, RULE_FIELDS)}`);
    }
  }

  // action (required, object)
  if (!("action" in rule)) {
    errors.push(`${path}: missing required "action"`);
    return;
  }
  validateAction(rule.action, `${path}.action`, errors);
}

function validateAction(action: unknown, path: string, errors: string[]): void {
  if (!isPlainObject(action)) {
    errors.push(`${path}: must be an object (got ${typeName(action)})`);
    return;
  }
  if (!("kind" in action)) {
    errors.push(`${path}: missing required "kind" (one of ${quoteList(ACTION_KINDS)})`);
    return;
  }
  const kind = action.kind;
  if (typeof kind !== "string" || !ACTION_KINDS.includes(kind as (typeof ACTION_KINDS)[number])) {
    errors.push(`${path}: unknown kind ${render(kind)}${suggest(String(kind), ACTION_KINDS)}`);
    return;
  }

  // Per-kind required/typed fields.
  switch (kind) {
    case "injectToolResult":
      requireString(action, "text", path, errors);
      optionalMode(action, path, errors);
      break;
    case "poisonDescription":
      requireString(action, "text", path, errors);
      optionalString(action, "tool", path, errors);
      optionalMode(action, path, errors);
      break;
    case "matchReplace":
      requireString(action, "find", path, errors);
      requireString(action, "replace", path, errors);
      optionalString(action, "flags", path, errors);
      break;
    case "setArg":
      requireString(action, "path", path, errors);
      optionalString(action, "tool", path, errors);
      requirePresent(action, "value", path, errors);
      break;
    case "rewriteArgs":
      requireObject(action, "args", path, errors);
      optionalString(action, "tool", path, errors);
      optionalEnum(action, "mode", REWRITE_MODES, path, errors);
      break;
    case "fuzzArgs":
      requireString(action, "path", path, errors);
      optionalString(action, "tool", path, errors);
      requirePayloads(action, path, errors);
      break;
    case "drop":
      // No further fields.
      break;
  }

  // Unknown action-level keys (typo detection, scoped to this kind).
  const allowed = ACTION_FIELDS[kind];
  for (const key of Object.keys(action)) {
    if (!allowed.includes(key)) {
      errors.push(`${path}: unknown field "${key}" for kind "${kind}"${suggest(key, allowed)}`);
    }
  }
}

function requireString(
  obj: Record<string, unknown>,
  field: string,
  path: string,
  errors: string[]
): void {
  if (!(field in obj)) {
    errors.push(`${path}: missing required "${field}"`);
  } else if (typeof obj[field] !== "string") {
    errors.push(`${path}.${field}: must be a string (got ${typeName(obj[field])})`);
  }
}

function optionalString(
  obj: Record<string, unknown>,
  field: string,
  path: string,
  errors: string[]
): void {
  if (field in obj && typeof obj[field] !== "string") {
    errors.push(`${path}.${field}: must be a string (got ${typeName(obj[field])})`);
  }
}

function optionalMode(obj: Record<string, unknown>, path: string, errors: string[]): void {
  if ("mode" in obj && !MODES.includes(obj.mode as string)) {
    errors.push(`${path}.mode: must be one of ${quoteList(MODES)} (got ${render(obj.mode)})`);
  }
}

function optionalEnum(
  obj: Record<string, unknown>,
  field: string,
  allowed: readonly string[],
  path: string,
  errors: string[]
): void {
  if (field in obj && !allowed.includes(obj[field] as string)) {
    errors.push(`${path}.${field}: must be one of ${quoteList(allowed)} (got ${render(obj[field])})`);
  }
}

/** A field that must be present, of any JSON type (e.g. setArg.value). */
function requirePresent(
  obj: Record<string, unknown>,
  field: string,
  path: string,
  errors: string[]
): void {
  if (!(field in obj)) errors.push(`${path}: missing required "${field}"`);
}

function requireObject(
  obj: Record<string, unknown>,
  field: string,
  path: string,
  errors: string[]
): void {
  if (!(field in obj)) {
    errors.push(`${path}: missing required "${field}"`);
  } else if (!isPlainObject(obj[field])) {
    errors.push(`${path}.${field}: must be an object (got ${typeName(obj[field])})`);
  }
}

/** fuzzArgs.payloads: a payload-library name (string) or an array of strings. */
function requirePayloads(obj: Record<string, unknown>, path: string, errors: string[]): void {
  if (!("payloads" in obj)) {
    errors.push(`${path}: missing required "payloads"`);
    return;
  }
  const p = obj.payloads;
  if (typeof p === "string") return;
  if (Array.isArray(p) && p.every((x) => typeof x === "string")) return;
  errors.push(
    `${path}.payloads: must be a string (payload-library name) or an array of strings (got ${typeName(p)})`
  );
}

function quoteList(items: readonly string[]): string {
  return items.map((i) => `"${i}"`).join(", ");
}

/** Human-readable rendering of an unexpected value for an error message. */
function render(v: unknown): string {
  if (typeof v === "string") return `"${v}"`;
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (typeof v === "object") return typeName(v);
  return String(v);
}
