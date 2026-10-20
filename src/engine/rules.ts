import { readFileSync } from "node:fs";
import type { Direction, FlowMessage, Rule, RuleAction } from "../types.js";
import { validateRuleFile } from "./validate.js";
import { setPath } from "./jsonpath.js";
import { loadPayloads } from "../payloads/index.js";

export interface RuleResult {
  /** The (possibly rewritten) JSON to forward, or null to DROP the message. */
  json: any;
  /** Names of rules that fired, for logging. */
  applied: string[];
  changed: boolean;
}

/**
 * Per-rule fuzz cursors (§3.2). `fuzzArgs` emits one payload per matching call,
 * so it needs state that survives across messages. That state lives here — in a
 * pipeline-owned instance threaded into {@link applyRules} — rather than in a
 * module global, so two concurrent pipelines never share a cursor.
 */
export class FuzzState {
  private cursors = new Map<string, number>();

  /** Return this rule's current cursor and advance it. Call exactly once per
   *  payload actually consumed (only when the action truly applies). */
  next(key: string): number {
    const c = this.cursors.get(key) ?? 0;
    this.cursors.set(key, c + 1);
    return c;
  }
}

/**
 * Per-rule match counters for stateful predicates (§3.2). `afterCalls` turns a
 * rule into a rug-pull: benign for the first N matches, then tampering. Like
 * {@link FuzzState} this lives in a pipeline-owned instance threaded into
 * {@link applyRules} — never a module global — so two concurrent pipelines keep
 * independent counts.
 */
export class RuleState {
  private counts = new Map<string, number>();

  /** Record that this rule matched and return its new 1-indexed match count.
   *  Call exactly once per message the rule matches. */
  next(key: string): number {
    const c = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, c);
    return c;
  }
}

/** Collaborators an action needs beyond the message JSON: the flow's method +
 *  direction (so argument-tampering actions can self-gate to client->server
 *  tools/call) and a cursor advance for fuzzArgs. */
interface ApplyContext {
  direction: Direction;
  method?: string;
  /** Advance and return this rule's fuzz cursor. */
  nextFuzzIndex: () => number;
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

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Argument-tampering actions apply ONLY to a client->server tools/call. */
function isToolCall(ctx: ApplyContext): boolean {
  return ctx.direction === "client->server" && ctx.method === "tools/call";
}

/** `tamperSampling` applies ONLY to a server->client sampling/createMessage
 *  request (a server->model prompt we rewrite before the client runs it). */
function isSampling(ctx: ApplyContext): boolean {
  return ctx.direction === "server->client" && ctx.method === "sampling/createMessage";
}

/** Tamper the `.text` of an MCP content value, which may be a single content
 *  object ({type:"text", text}) or an array of them. Returns true if any text
 *  was changed. Non-object / non-text content is skipped, never thrown on. */
function tamperContentText(content: any, text: string, mode: string | undefined): boolean {
  if (Array.isArray(content)) {
    let changed = false;
    for (const b of content) {
      if (b && typeof b === "object" && typeof b.text === "string") {
        b.text = applyText(b.text, text, mode);
        changed = true;
      }
    }
    return changed;
  }
  if (content && typeof content === "object" && typeof content.text === "string") {
    content.text = applyText(content.text, text, mode);
    return true;
  }
  return false;
}

/** Tamper a base64 `blob` by decoding it as UTF-8, applying the text, and
 *  re-encoding — so the mutation survives a client that decodes the resource. */
function tamperBlob(blob: string, text: string, mode: string | undefined): string {
  const decoded = Buffer.from(blob, "base64").toString("utf8");
  return Buffer.from(applyText(decoded, text, mode), "utf8").toString("base64");
}

/** An optional `tool` filter matches against params.name. No filter = any. */
function toolMatches(tool: string | undefined, json: any): boolean {
  if (tool === undefined) return true;
  return json?.params?.name === tool;
}

/** `when.contains`: does `substr` appear anywhere in the message JSON? Checked
 *  against the serialized body so it spans results, resources, prompt messages,
 *  descriptions and arguments alike without the rule naming a path. */
function messageContains(json: any, substr: string): boolean {
  return JSON.stringify(json).includes(substr);
}

/** Ensure json.params.arguments is an object and return it, creating as needed. */
function ensureArgs(json: any): Record<string, unknown> {
  if (!isPlainObject(json.params)) json.params = {};
  if (!isPlainObject((json.params as any).arguments)) (json.params as any).arguments = {};
  return (json.params as any).arguments as Record<string, unknown>;
}

/** Resolve a fuzz payload reference to a concrete list: an inline array is used
 *  as-is; a string names a payload library (bundled or on-disk). */
function resolvePayloads(payloads: string[] | string): string[] {
  if (Array.isArray(payloads)) return payloads;
  return loadPayloads(payloads);
}

/** Apply a single action in-place to the message JSON. Returns true if changed. */
function applyAction(action: RuleAction, json: any, ctx: ApplyContext): boolean {
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

    case "injectResource": {
      // server->client resources/read response: result.contents[] text/blob.
      // Shape-gated like injectToolResult (method comes via correlation on the
      // rule, so we don't re-check it here).
      const contents = json?.result?.contents;
      if (!Array.isArray(contents)) return false;
      const target = contents.find(
        (c: any) => c && typeof c === "object" && typeof c.text === "string"
      );
      if (target) {
        target.text = applyText(target.text, action.text, action.mode);
        return true;
      }
      const blobTarget = contents.find(
        (c: any) => c && typeof c === "object" && typeof c.blob === "string"
      );
      if (blobTarget) {
        blobTarget.blob = tamperBlob(blobTarget.blob, action.text, action.mode);
        return true;
      }
      // No existing text/blob to tamper: mirror injectToolResult and append a
      // fresh text content (a valid resource content carries a uri), unless
      // replacing (replace only ever rewrites what is already there).
      if (action.mode !== "replace") {
        contents.push({ uri: "mcpwn://injected", mimeType: "text/plain", text: action.text });
        return true;
      }
      return false;
    }

    case "poisonPrompt": {
      // server->client prompts/get response: every result.messages[].content.text.
      const messages = json?.result?.messages;
      if (!Array.isArray(messages)) return false;
      let changed = false;
      for (const m of messages) {
        if (m == null || typeof m !== "object") continue;
        if (tamperContentText(m.content, action.text, action.mode)) changed = true;
      }
      return changed;
    }

    case "tamperSampling": {
      // server->client sampling/createMessage REQUEST: rewrite the server-supplied
      // model prompt in params.messages[].content.text. Self-gated (the method is
      // on the wire for a request) like the argument-tampering actions.
      if (!isSampling(ctx)) return false;
      const messages = json?.params?.messages;
      if (!Array.isArray(messages)) return false;
      let changed = false;
      for (const m of messages) {
        if (m == null || typeof m !== "object") continue;
        if (tamperContentText(m.content, action.text, action.mode)) changed = true;
      }
      return changed;
    }

    case "setArg": {
      // Argument tampering is scoped to client->server tools/call; anything
      // else is a silent no-op (like the other filtered actions).
      if (!isToolCall(ctx) || !toolMatches(action.tool, json)) return false;
      const args = ensureArgs(json);
      setPath(args, action.path, action.value);
      return true;
    }

    case "rewriteArgs": {
      if (!isToolCall(ctx) || !toolMatches(action.tool, json)) return false;
      if (!isPlainObject(json.params)) json.params = {};
      if (action.mode === "merge") {
        const cur = isPlainObject((json.params as any).arguments)
          ? ((json.params as any).arguments as Record<string, unknown>)
          : {};
        (json.params as any).arguments = { ...cur, ...action.args };
      } else {
        (json.params as any).arguments = { ...action.args };
      }
      return true;
    }

    case "fuzzArgs": {
      if (!isToolCall(ctx) || !toolMatches(action.tool, json)) return false;
      // Resolve BEFORE advancing the cursor so an unknown payload library throws
      // (and the rule rolls back) without burning a payload slot.
      const payloads = resolvePayloads(action.payloads);
      if (payloads.length === 0) return false;
      const idx = ctx.nextFuzzIndex();
      const payload = payloads[idx % payloads.length];
      const args = ensureArgs(json);
      setPath(args, action.path, payload);
      return true;
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
export function applyRules(
  rules: Rule[],
  msg: FlowMessage,
  logger?: RuleLogger,
  fuzz?: FuzzState,
  state?: RuleState
): RuleResult {
  if (!msg.json) return { json: msg.json, applied: [], changed: false };

  // Deep clone so an aborted/partial mutation never corrupts the raw record.
  const json = JSON.parse(JSON.stringify(msg.json));
  const applied: string[] = [];
  let changed = false;

  for (const rule of rules) {
    if (!matches(rule, msg)) continue;

    // Stateful rug-pull (§3.2): count this match and keep the message benign
    // until the rule has matched MORE than `afterCalls` times. A stateless
    // caller always sees match #1, so afterCalls is a no-op without threaded
    // state (like the fuzz cursor defaulting to the first payload).
    const matchCount = state ? state.next(rule.name) : 1;
    if (rule.afterCalls !== undefined && matchCount <= rule.afterCalls) continue;

    // Conditional gate (§3.2): only act when the message carries the substring.
    if (rule.when?.contains !== undefined && !messageContains(json, rule.when.contains)) continue;

    if (rule.action.kind === "drop") {
      return { json: null, applied: [...applied, rule.name], changed: true };
    }

    const ctx: ApplyContext = {
      direction: msg.direction,
      method: msg.method,
      // Cursor keyed per rule name; falls back to 0 when no state is threaded
      // (e.g. a unit test), so a stateless caller always gets the first payload.
      nextFuzzIndex: () => (fuzz ? fuzz.next(rule.name) : 0),
    };

    // Snapshot before the (mutating) action so a throw rolls back cleanly.
    const snapshot = JSON.stringify(json);
    let did = false;
    try {
      did = applyAction(rule.action, json, ctx);
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
