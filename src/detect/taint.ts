import type { Detector } from "./detector.js";
import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";
import { agentBoundTexts } from "./linter.js";

/**
 * Provenance TAINTING (§3.14, A4) — injection → action kill-chain detection.
 *
 * A prompt-injection in a tool result or resource is only dangerous when the
 * agent ACTS on it. This opt-in (`--taint`) analyzer makes that chain explicit:
 * it tags text that originated from an untrusted server->client tool result /
 * resource as "untrusted-external", then raises a HIGH finding when that same
 * text later reappears inside a subsequent client->server `tools/call` ARGUMENT —
 * i.e. attacker-controlled content from a SOURCE message is flowing into a
 * privileged SINK call.
 *
 * Invariants:
 *  - READ-ONLY: never mutates or blocks the message (it is an ordinary
 *    {@link Detector}; it only records findings — Invariant #2).
 *  - PIPELINE-OWNED STATE, NO MODULE GLOBALS: the taint index lives on the
 *    detector INSTANCE, which the pipeline owns for the life of one session. It
 *    does NOT touch the Correlator, so the Phase-6 TTL/LRU + normal correlation
 *    stay exactly as they were.
 *  - CHEAP: a bounded substring index. Only "significant" tokens (>= a minimum
 *    length, to avoid trivial matches on short common words) are indexed, the
 *    index is capped, per-source and per-message work is capped, and reported
 *    chains are de-duplicated. Matching is O(args × taintedTokens), both bounded.
 *  - NOT a builtin linter: it is wired only via `--taint`, like `--baseline`, so
 *    builtinLinters() stays the 8 passive detectors.
 */

/** Minimum token length to index — short, common strings ("file", "true", a
 *  small number) would match everywhere and are worthless as provenance. */
const MIN_TOKEN_LEN = 12;
/** Skip pathologically long tokens (keeps the needle set small + bounded). */
const MAX_TOKEN_LEN = 512;
/** Hard cap on indexed tainted tokens (bounded memory + match cost). */
const MAX_TOKENS = 512;
/** Only tokenise the first N chars of any one source text. */
const MAX_SOURCE_CHARS = 8192;
/** Cap arg strings inspected per tools/call. */
const MAX_ARG_STRINGS = 256;
/** Cap de-dup memory so a long hostile session can't grow it without bound. */
const MAX_REPORTED = 2048;

/** Where a tainted token came from, carried into the finding (the kill-chain
 *  source: message id → sink call). */
interface TaintSource {
  id: string;
  method: string;
  where: string;
  tool?: string;
}

/** Split text into whitespace/quote/bracket-delimited tokens, keeping URLs,
 *  paths, emails and hashes intact (only trivial separators are split on). */
function tokenize(text: string): string[] {
  return text.slice(0, MAX_SOURCE_CHARS).split(/[\s"'`<>(){}[\],;]+/);
}

function significant(token: string): boolean {
  return token.length >= MIN_TOKEN_LEN && token.length <= MAX_TOKEN_LEN;
}

function snippet(s: string, max = 80): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
}

/** Collect every string value under a JSON value (bounded walk) — used to read a
 *  tools/call's arguments wholesale, wherever they nest. */
function collectStrings(node: unknown, out: string[], depth = 0): void {
  if (out.length >= MAX_ARG_STRINGS || depth > 10) return;
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

export class TaintDetector implements Detector {
  /** token (lowercased) -> originating source. Insertion-ordered so the oldest
   *  tokens are evicted first when the cap is hit. */
  private readonly tainted = new Map<string, TaintSource>();
  /** De-dup of already-reported (source-id → token) chains. */
  private readonly reported = new Set<string>();

  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction === "server->client") {
      this.taintSources(flow);
      return;
    }
    // client->server: only a tools/call can be a sink.
    const method = flow.method ?? flow.correlatedMethod;
    if (method === "tools/call") this.checkSink(flow, sink);
  }

  /** Index the significant tokens of any tool-result / resource text flowing
   *  back from the server as "untrusted-external". */
  private taintSources(flow: FlowMessage): void {
    for (const seg of agentBoundTexts(flow)) {
      if (seg.method !== "tools/call" && seg.method !== "resources/read") continue;
      const source: TaintSource = {
        id: String(flow.id ?? "?"),
        method: seg.method,
        where: seg.where,
        tool: seg.tool,
      };
      for (const tok of tokenize(seg.text)) {
        if (!significant(tok)) continue;
        const key = tok.toLowerCase();
        if (this.tainted.has(key)) continue;
        if (this.tainted.size >= MAX_TOKENS) {
          const oldest = this.tainted.keys().next().value;
          if (oldest !== undefined) this.tainted.delete(oldest);
        }
        this.tainted.set(key, source);
      }
    }
  }

  /** Flag a tools/call whose arguments reuse any tainted token. */
  private checkSink(flow: FlowMessage, sink: FindingsSink): void {
    if (this.tainted.size === 0) return;
    const args = flow.json?.params?.arguments;
    if (args === undefined) return;
    const strings: string[] = [];
    collectStrings(args, strings);
    if (strings.length === 0) return;
    const haystacks = strings.map((s) => s.toLowerCase());
    const tool = typeof flow.json?.params?.name === "string" ? flow.json.params.name : undefined;

    for (const [token, source] of this.tainted) {
      for (const hay of haystacks) {
        if (!hay.includes(token)) continue;
        const dedupe = `${source.id}\u0000${token}\u0000${tool ?? ""}`;
        if (this.reported.has(dedupe)) break;
        if (this.reported.size < MAX_REPORTED) this.reported.add(dedupe);
        sink.add({
          id: "provenance-taint",
          severity: "high",
          title: `Untrusted server output reused in a tools/call argument${tool ? `: ${tool}` : ""}`,
          direction: "client->server",
          method: "tools/call",
          tool,
          evidence:
            `tainted text "${snippet(token)}" originated from ${source.method} ` +
            `(${source.where}${source.tool ? ` of ${source.tool}` : ""}, id=${source.id}) ` +
            "and is now an argument of this call",
          description:
            "Text that originated from an untrusted server->client tool result / resource is now " +
            "flowing back into a client->server tools/call argument. This is an injection → action " +
            "kill-chain: attacker-controlled content from one message (the source) is steering a " +
            "privileged tool call (the sink), exactly how an indirect prompt injection turns into a " +
            "real action.",
          remediation:
            "Do not let the agent pass server-supplied text verbatim into further tool calls; treat " +
            "tool output as untrusted data and require explicit confirmation for actions derived from it.",
          ts: flow.ts,
        });
        break; // one finding per (token) per call is enough
      }
    }
  }
}
