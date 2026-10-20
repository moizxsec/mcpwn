import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";
import { builtinRedactPatterns, redact } from "../redact.js";
import {
  INJECTION_PATTERNS,
  RTL_CHARS,
  INVISIBLE_SRC,
  extractHosts,
  isExfilHost,
} from "../detect/linter.js";
import type { ContentClass, Policy, PolicyAction, PolicyRule } from "./policy.js";
import { getPath } from "../engine/jsonpath.js";

/**
 * Guard engine (§3.14) — the defensive inverse of the tamper proxy.
 *
 * In guard mode mcpwn is a protective firewall sitting on the agent↔server
 * channel. For each parseable message it recognises the same content classes the
 * passive detectors flag (prompt-injection phrasing, leaked secrets, exfil URLs,
 * invisible-unicode smuggling) and, per the active {@link Policy}, decides to
 * allow, warn, SANITISE (strip only the offending span, let the message through)
 * or BLOCK (drop the message) BEFORE the agent ever sees it.
 *
 * Relationship to the never-block-the-wire invariant: in the default (observe /
 * tamper) modes the wire is never blocked. Guard mode is the ONE place where
 * dropping a message is the intended behaviour — and even there it is designed to
 * FAIL OPEN: {@link evaluate} never throws into the pipeline, and the pipeline
 * forwards the original message if the engine errors. The firewall can only ever
 * make traffic safer or leave it unchanged; it can never deadlock the stream.
 */

/** The outcome of evaluating one message against the policy. */
export interface GuardDecision {
  /** The strongest action any matching rule demanded (block > sanitize > warn >
   *  allow), or the policy default when nothing matched. */
  action: PolicyAction;
  /** Content classes recognised in the message. */
  classes: ContentClass[];
  /** Reason code(s) from the matched rule(s), for the log + finding. */
  reason: string;
  /** For a "sanitize" decision: the cleaned message JSON (a deep clone; the
   *  original is never mutated). Present only when sanitising actually changed
   *  something. */
  sanitized?: unknown;
}

/** Compile a shell-style glob (`*`, `?`) to an anchored RegExp — local copy so
 *  the guard does not reach into scope.ts internals. */
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

const INVISIBLE_GLOBAL = new RegExp(INVISIBLE_SRC, "gu");
const RTL_GLOBAL = new RegExp(RTL_CHARS.source, "g");
// A deliberately simple URL matcher, used only to locate a span to neutralise.
const URL_GLOBAL = /\bhttps?:\/\/[^\s"'`)<>]+/gi;
const SECRET_PATTERNS = builtinRedactPatterns();

/** Collect every string value anywhere in a JSON value (bounded walk). */
function collectStrings(node: unknown, out: string[], depth = 0): void {
  if (depth > 12 || out.length > 5000) return;
  if (typeof node === "string") {
    out.push(node);
  } else if (Array.isArray(node)) {
    for (const v of node) collectStrings(v, out, depth + 1);
  } else if (node && typeof node === "object") {
    for (const v of Object.values(node as Record<string, unknown>)) {
      collectStrings(v, out, depth + 1);
    }
  }
}

function hasInjection(s: string): boolean {
  return INJECTION_PATTERNS.some((re) => re.test(s)) || RTL_CHARS.test(s);
}
function hasSecret(s: string): boolean {
  return SECRET_PATTERNS.some((p) => new RegExp(p.re.source, p.re.flags).test(s));
}
function hasExfilUrl(s: string): boolean {
  return extractHosts(s).some((h) => isExfilHost(h));
}
function hasInvisible(s: string): boolean {
  return new RegExp(INVISIBLE_SRC, "u").test(s);
}

/** Which content classes are present anywhere in the message. */
export function presentClasses(flow: FlowMessage): ContentClass[] {
  const strings: string[] = [];
  collectStrings(flow.json, strings);
  const found = new Set<ContentClass>();
  for (const s of strings) {
    if (hasInjection(s)) found.add("injection");
    if (hasSecret(s)) found.add("secret");
    if (hasExfilUrl(s)) found.add("exfil-url");
    if (hasInvisible(s)) found.add("invisible-unicode");
  }
  return [...found];
}

/** Neutralise the given content classes in a single string. */
function cleanString(s: string, classes: Set<ContentClass>): string {
  let out = s;
  if (classes.has("secret")) out = redact(out, SECRET_PATTERNS);
  if (classes.has("invisible-unicode")) {
    out = out.replace(INVISIBLE_GLOBAL, "").replace(RTL_GLOBAL, "");
  }
  if (classes.has("injection")) {
    for (const re of INJECTION_PATTERNS) {
      out = out.replace(
        new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"),
        "[removed-by-mcpwn-guard]"
      );
    }
    out = out.replace(RTL_GLOBAL, "");
  }
  if (classes.has("exfil-url")) {
    out = out.replace(URL_GLOBAL, (m) => {
      try {
        const host = new URL(m).hostname;
        return isExfilHost(host) ? "[removed-url-by-mcpwn-guard]" : m;
      } catch {
        return m;
      }
    });
  }
  return out;
}

/** Deep-clone `node`, cleaning every string for the given classes. Returns the
 *  cleaned clone and whether anything changed. */
function cleanDeep(
  node: unknown,
  classes: Set<ContentClass>
): { value: unknown; changed: boolean } {
  let changed = false;
  const walk = (n: unknown, depth: number): unknown => {
    if (depth > 12) return n;
    if (typeof n === "string") {
      const c = cleanString(n, classes);
      if (c !== n) changed = true;
      return c;
    }
    if (Array.isArray(n)) return n.map((v) => walk(v, depth + 1));
    if (n && typeof n === "object") {
      const o: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(n as Record<string, unknown>)) o[k] = walk(v, depth + 1);
      return o;
    }
    return n;
  };
  const value = walk(node, 0);
  return { value, changed };
}

function matchesPredicate(
  flow: FlowMessage,
  pred: NonNullable<PolicyRule["match"]>["jsonpath"]
): boolean {
  if (!pred) return true;
  let v: unknown;
  try {
    v = getPath(flow.json, pred.path);
  } catch {
    v = undefined;
  }
  if ("exists" in pred && pred.exists !== undefined) {
    const present = v !== undefined;
    if (present !== pred.exists) return false;
  }
  if ("equals" in pred && pred.equals !== undefined) {
    if (JSON.stringify(v) !== JSON.stringify(pred.equals)) return false;
  }
  if (pred.contains !== undefined) {
    if (typeof v !== "string" || !v.includes(pred.contains)) return false;
  }
  if (pred.matches !== undefined) {
    try {
      if (typeof v !== "string" || !new RegExp(pred.matches).test(v)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

/** Does `rule` match `flow` given the recognised `classes`? All present match
 *  fields must hold; an absent field is a wildcard. */
function ruleMatches(rule: PolicyRule, flow: FlowMessage, classes: Set<ContentClass>): boolean {
  const m = rule.match;
  if (!m) return true;
  if (m.direction && m.direction !== flow.direction) return false;
  if (m.method) {
    const method = flow.method ?? flow.correlatedMethod ?? "";
    if (!globToRegExp(m.method).test(method)) return false;
  }
  if (m.tool) {
    const name = flow.json?.params?.name;
    if (typeof name !== "string" || !globToRegExp(m.tool).test(name)) return false;
  }
  if (m.contentClass && m.contentClass.length > 0) {
    if (!m.contentClass.some((c) => classes.has(c))) return false;
  }
  if (m.jsonpath && !matchesPredicate(flow, m.jsonpath)) return false;
  return true;
}

const STRENGTH: Record<PolicyAction, number> = { allow: 0, warn: 1, sanitize: 2, block: 3 };

/**
 * The guard firewall. Deterministic, total, and read-only toward its inputs —
 * {@link evaluate} never mutates the flow and never throws (all signature checks
 * are guarded), so a buggy policy or a pathological payload fails open.
 */
export class GuardEngine {
  constructor(
    private policy: Policy,
    private sink?: FindingsSink
  ) {}

  /** Evaluate one message. Returns the strongest decision across all matching
   *  rules (block > sanitize > warn > allow); the policy default applies only if
   *  NO rule matched. For a sanitise decision the cleaned clone is returned. */
  evaluate(flow: FlowMessage): GuardDecision {
    let classes: ContentClass[];
    try {
      classes = presentClasses(flow);
    } catch {
      classes = [];
    }
    const classSet = new Set(classes);

    const matched = this.policy.rules.filter((r) => {
      try {
        return ruleMatches(r, flow, classSet);
      } catch {
        return false; // a bad rule must never take down the firewall
      }
    });

    let action: PolicyAction;
    let reason: string;
    if (matched.length === 0) {
      action = this.policy.defaultAction ?? "allow";
      reason = action === "allow" ? "" : `policy default (${action})`;
    } else {
      const strongest = matched.reduce((a, b) => (STRENGTH[b.action] > STRENGTH[a.action] ? b : a));
      action = strongest.action;
      reason = matched
        .filter((r) => r.action === action)
        .map((r) => r.reason ?? r.name)
        .join("; ");
    }

    const decision: GuardDecision = { action, classes, reason };

    if (action === "sanitize") {
      // Strip every class any matching sanitize rule targeted; a sanitize rule
      // with no contentClass filter cleans all recognised classes.
      const targets = new Set<ContentClass>();
      for (const r of matched) {
        if (r.action !== "sanitize") continue;
        const cc = r.match?.contentClass;
        if (!cc || cc.length === 0) {
          for (const c of classSet) targets.add(c);
        } else {
          for (const c of cc) if (classSet.has(c)) targets.add(c);
        }
      }
      try {
        const { value, changed } = cleanDeep(flow.json, targets);
        if (changed) decision.sanitized = value;
        else decision.action = "warn"; // nothing to strip ⇒ degrade to warn
      } catch {
        decision.action = "warn"; // never fail closed
      }
    }

    if (
      (decision.action === "block" ||
        decision.action === "sanitize" ||
        decision.action === "warn") &&
      this.sink
    ) {
      this.record(flow, decision);
    }
    return decision;
  }

  private record(flow: FlowMessage, d: GuardDecision): void {
    try {
      this.sink?.add({
        id: `guard-${d.action}`,
        title: `guard ${d.action}: ${d.reason || d.classes.join(", ") || "policy"}`,
        severity: d.action === "block" ? "high" : d.action === "sanitize" ? "medium" : "low",
        direction: flow.direction,
        method: flow.method ?? flow.correlatedMethod,
        tool: typeof flow.json?.params?.name === "string" ? flow.json.params.name : undefined,
        evidence: d.classes.join(", ") || undefined,
        description: `Guard policy ${d.action} on ${d.classes.join(", ") || "matched rule"}. Reason: ${d.reason || "policy"}.`,
        ts: Date.now(),
      });
    } catch {
      /* recording a finding must never affect the wire */
    }
  }
}
