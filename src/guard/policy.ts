import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Direction } from "../types.js";

/**
 * Guard policy model + hand-rolled validator (§3.14).
 *
 * In GUARD MODE (`mcpwn --mode guard`) mcpwn stops being an attack proxy and
 * becomes a protective firewall on the agent↔server channel: it runs the passive
 * detector signatures and, per this policy, BLOCKS or SANITIZES malicious content
 * before the agent ever sees it. A policy is plain JSON (`mcpwn.policy.json`);
 * like the rest of mcpwn it ships ZERO runtime deps, so this validator is
 * hand-rolled (mirroring src/config.ts + src/engine/validate.ts) and
 * `schema/policy.schema.json` is the published machine-readable mirror.
 *
 * Precedence for the active policy: `--policy <file>` > `./mcpwn.policy.json`
 * (auto) > the baked-in {@link defaultPolicy} (deny the high-severity classes).
 */

export const DEFAULT_POLICY_FILENAME = "mcpwn.policy.json";

/** What a matched policy rule does to the message. */
export type PolicyAction = "allow" | "warn" | "sanitize" | "block";

/**
 * Content classes mcpwn can recognise in agent-bound text (server->client) or in
 * a tools/call's arguments (client->server). Each maps to the same signatures the
 * passive linters use, so the firewall and the detector never disagree.
 */
export type ContentClass = "injection" | "secret" | "exfil-url" | "invisible-unicode";

export const CONTENT_CLASSES: ContentClass[] = [
  "injection",
  "secret",
  "exfil-url",
  "invisible-unicode",
];

/** A JSONPath predicate over the message (reuses src/engine/jsonpath.ts). The
 *  value at `path` is read and tested; an absent path fails every test except
 *  `exists:false`. */
export interface PolicyPredicate {
  path: string;
  exists?: boolean;
  equals?: unknown;
  contains?: string;
  matches?: string;
}

/** Match criteria for a policy rule. An omitted field is a wildcard; ALL present
 *  fields must match. An empty/absent `match` matches every message. */
export interface PolicyMatch {
  direction?: Direction;
  /** Shell-style glob over the (resolved) JSON-RPC method. */
  method?: string;
  /** Shell-style glob over the tool name (`params.name`). */
  tool?: string;
  /** Any-of: the rule matches when ANY listed class is present in the message. */
  contentClass?: ContentClass[];
  /** Predicate over the message JSON (typically the tools/call arguments). */
  jsonpath?: PolicyPredicate;
}

export interface PolicyRule {
  name: string;
  match?: PolicyMatch;
  action: PolicyAction;
  /** Human reason surfaced in the finding + log (a reason code). */
  reason?: string;
}

export interface Policy {
  /** Optional label for the policy, echoed in startup logs. */
  name?: string;
  /** Action when no rule matches. Defaults to "allow" (fail-open by default). */
  defaultAction?: PolicyAction;
  rules: PolicyRule[];
}

/**
 * The baked-in default policy used when no `mcpwn.policy.json` is present: deny
 * (neutralise) the four high-severity content classes by SANITISING them — the
 * least-disruptive protective action that still removes the threat (the agent
 * keeps working; only the malicious span is stripped/redacted). Point `--policy`
 * at a file to BLOCK instead, or to add JSONPath/tool rules.
 */
export function defaultPolicy(): Policy {
  return {
    name: "mcpwn-default-guard",
    defaultAction: "allow",
    rules: [
      {
        name: "deny-secret-exposure",
        match: { contentClass: ["secret"] },
        action: "sanitize",
        reason: "credential/secret in agent-bound content",
      },
      {
        name: "deny-prompt-injection",
        match: { contentClass: ["injection"] },
        action: "sanitize",
        reason: "imperative/override instructions in agent-bound content",
      },
      {
        name: "deny-invisible-unicode",
        match: { contentClass: ["invisible-unicode"] },
        action: "sanitize",
        reason: "hidden/invisible unicode (ASCII smuggling)",
      },
      {
        name: "deny-exfil-url",
        match: { contentClass: ["exfil-url"] },
        action: "sanitize",
        reason: "out-of-band / exfil URL in agent-bound content",
      },
    ],
  };
}

/** Thrown for an unreadable / malformed / schema-invalid policy file. */
export class PolicyError extends Error {}

export type PolicyValidationResult = { ok: true; policy: Policy } | { ok: false; errors: string[] };

const ACTIONS: PolicyAction[] = ["allow", "warn", "sanitize", "block"];
const DIRECTIONS: Direction[] = ["client->server", "server->client"];
const POLICY_FIELDS = ["$schema", "name", "defaultAction", "rules"];
const RULE_FIELDS = ["name", "match", "action", "reason"];
const MATCH_FIELDS = ["direction", "method", "tool", "contentClass", "jsonpath"];
const PREDICATE_FIELDS = ["path", "exists", "equals", "contains", "matches"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function quoteList(items: readonly string[]): string {
  return items.map((i) => `"${i}"`).join(", ");
}

/** Validate a parsed policy value (hand-rolled, zero-dep). Collects every error. */
export function validatePolicy(
  data: unknown,
  source = DEFAULT_POLICY_FILENAME
): PolicyValidationResult {
  const errors: string[] = [];
  if (!isPlainObject(data)) {
    return {
      ok: false,
      errors: [`${source}: top level must be a JSON object (got ${typeName(data)})`],
    };
  }
  for (const k of Object.keys(data)) {
    if (!POLICY_FIELDS.includes(k)) errors.push(`${source}: unknown key "${k}"`);
  }
  if ("name" in data && typeof data.name !== "string") {
    errors.push(`${source}: "name" must be a string`);
  }
  if ("defaultAction" in data && !ACTIONS.includes(data.defaultAction as PolicyAction)) {
    errors.push(`${source}: "defaultAction" must be one of ${quoteList(ACTIONS)}`);
  }
  if (!("rules" in data)) {
    errors.push(`${source}: missing required "rules" array`);
  } else if (!Array.isArray(data.rules)) {
    errors.push(`${source}: "rules" must be an array (got ${typeName(data.rules)})`);
  } else {
    data.rules.forEach((r, i) => validateRule(r, `${source}: rules[${i}]`, errors));
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, policy: data as unknown as Policy };
}

function validateRule(rule: unknown, where: string, errors: string[]): void {
  if (!isPlainObject(rule)) {
    errors.push(`${where}: must be an object (got ${typeName(rule)})`);
    return;
  }
  for (const k of Object.keys(rule)) {
    if (!RULE_FIELDS.includes(k)) errors.push(`${where}: unknown field "${k}"`);
  }
  if (typeof rule.name !== "string" || rule.name.length === 0) {
    errors.push(`${where}: "name" must be a non-empty string`);
  }
  if (!("action" in rule)) {
    errors.push(`${where}: missing required "action"`);
  } else if (!ACTIONS.includes(rule.action as PolicyAction)) {
    errors.push(
      `${where}.action: must be one of ${quoteList(ACTIONS)} (got ${typeName(rule.action)})`
    );
  }
  if ("reason" in rule && typeof rule.reason !== "string") {
    errors.push(`${where}.reason: must be a string`);
  }
  if ("match" in rule) validateMatch(rule.match, `${where}.match`, errors);
}

function validateMatch(match: unknown, where: string, errors: string[]): void {
  if (!isPlainObject(match)) {
    errors.push(`${where}: must be an object (got ${typeName(match)})`);
    return;
  }
  for (const k of Object.keys(match)) {
    if (!MATCH_FIELDS.includes(k)) errors.push(`${where}: unknown field "${k}"`);
  }
  if ("direction" in match && !DIRECTIONS.includes(match.direction as Direction)) {
    errors.push(`${where}.direction: must be one of ${quoteList(DIRECTIONS)}`);
  }
  if ("method" in match && typeof match.method !== "string") {
    errors.push(`${where}.method: must be a string`);
  }
  if ("tool" in match && typeof match.tool !== "string") {
    errors.push(`${where}.tool: must be a string`);
  }
  if ("contentClass" in match) {
    const cc = match.contentClass;
    if (!Array.isArray(cc) || !cc.every((c) => typeof c === "string")) {
      errors.push(`${where}.contentClass: must be an array of strings`);
    } else {
      for (const c of cc) {
        if (!CONTENT_CLASSES.includes(c as ContentClass)) {
          errors.push(
            `${where}.contentClass: unknown class "${c}" (one of ${quoteList(CONTENT_CLASSES)})`
          );
        }
      }
    }
  }
  if ("jsonpath" in match) validatePredicate(match.jsonpath, `${where}.jsonpath`, errors);
}

function validatePredicate(pred: unknown, where: string, errors: string[]): void {
  if (!isPlainObject(pred)) {
    errors.push(`${where}: must be an object (got ${typeName(pred)})`);
    return;
  }
  for (const k of Object.keys(pred)) {
    if (!PREDICATE_FIELDS.includes(k)) errors.push(`${where}: unknown field "${k}"`);
  }
  if (typeof pred.path !== "string" || pred.path.length === 0) {
    errors.push(`${where}.path: must be a non-empty string`);
  }
  if ("exists" in pred && typeof pred.exists !== "boolean") {
    errors.push(`${where}.exists: must be a boolean`);
  }
  if ("contains" in pred && typeof pred.contains !== "string") {
    errors.push(`${where}.contains: must be a string`);
  }
  if ("matches" in pred) {
    if (typeof pred.matches !== "string") {
      errors.push(`${where}.matches: must be a string (regex)`);
    } else {
      try {
        new RegExp(pred.matches);
      } catch (err) {
        errors.push(`${where}.matches: invalid regex (${(err as Error).message})`);
      }
    }
  }
}

/** Read + parse + validate a policy file. Throws PolicyError on any failure. */
export function loadPolicy(path: string): Policy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new PolicyError(`cannot read policy "${path}": ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new PolicyError(`invalid JSON in policy "${path}": ${(err as Error).message}`);
  }
  const res = validatePolicy(data, path);
  if (!res.ok) {
    throw new PolicyError(`invalid policy "${path}":\n  - ${res.errors.join("\n  - ")}`);
  }
  return res.policy;
}

/** The auto-load path (`./mcpwn.policy.json`), or undefined if absent. */
export function findDefaultPolicy(cwd: string = process.cwd()): string | undefined {
  const p = resolve(cwd, DEFAULT_POLICY_FILENAME);
  return existsSync(p) ? p : undefined;
}
