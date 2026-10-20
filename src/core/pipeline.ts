import { parseLine, serialize } from "../engine/parser.js";
import { Correlator } from "../engine/correlator.js";
import { applyRules, FuzzState, RuleState } from "../engine/rules.js";
import { inScope, type Scope } from "./scope.js";
import type { InterceptController } from "../engine/intercept.js";
import type { Direction, FlowMessage, Rule } from "../types.js";
import type { Logger, MessageLogExtra } from "../logger.js";
import type { Detector } from "../detect/detector.js";
import type { FindingsSink } from "../findings.js";
import type { RuleActionRegistry } from "../plugins/index.js";

/**
 * Transport-agnostic processing options. A transport (stdio, and later HTTP)
 * owns framing + I/O; the pipeline owns the parse→correlate→rules→intercept→
 * log→forward-decision chain and nothing else.
 */
export interface PipelineOptions {
  rules: Rule[];
  logger: Logger;
  /** When set, hold messages for interactive review (the Repeater loop). */
  intercept?: InterceptController;
  /** Narrow which traffic is "in scope" (§3.6). Out-of-scope messages are
   *  always forwarded untouched (no rules, no hold) and suppressed from the
   *  stderr log. When unset, all traffic is in scope (transparent). */
  scope?: Scope;
  /** When true, out-of-scope messages are also omitted from the --log JSONL
   *  (--scope-affects-log). By default they are still recorded. */
  scopeAffectsLog?: boolean;
  /** Max time to hold a message for interactive review before auto-forwarding.
   *  0 (the default, used by stdio) means unlimited. A bounded hold is only
   *  meaningful for request/response transports (HTTP, M3). */
  holdTimeoutMs?: number;
  /** Passive detectors (§3.4, §3.9). Run read-only on every parseable message;
   *  they only record findings and NEVER affect what is forwarded. */
  detectors?: Detector[];
  /** Where detectors record findings. */
  findings?: FindingsSink;
  /** Custom tamper-action kinds registered via `--rule-plugin` (§3.11). Threaded
   *  into the rules engine so a rule may reference a plugin's `kind`. */
  ruleActionPlugins?: RuleActionRegistry;
}

/** A compact end-of-session tally the proxy prints on exit (§3.6, mirrors the
 *  scan summary). Pure counters — accumulating them NEVER changes what is
 *  forwarded on the wire (Invariant #2). */
export interface SessionSummary {
  /** Every message the pipeline processed, in either direction. */
  messages: number;
  /** Messages a rule (or the operator) changed or dropped. */
  tampered: number;
  /** Messages dropped (a subset of `tampered`). */
  dropped: number;
  /** Distinct tool names seen in `tools/call` traffic. */
  tools: string[];
}

/** What a single processed message resolves to. */
export interface ProcessResult {
  /** The exact bytes to put back on the wire with NO framing (the transport
   *  adds its own newline / SSE frame), or null to DROP the message. */
  forward: string | null;
  /** The annotated message (direction + correlation) for the caller's use. */
  flow: FlowMessage;
  /** Names of the rules that fired, for logging / findings. */
  applied: string[];
  /** True when the operator hand-edited the message in interactive mode. */
  manualEdit: boolean;
}

/**
 * The heart of mcpwn, lifted out of the stdio transport so every transport
 * shares identical tamper/correlation/logging semantics.
 *
 * `process` NEVER writes to the wire and NEVER throws into the caller: it
 * returns what to forward (or null to drop) so the transport decides how to
 * frame and emit it. The correlator lives here because correlation is a
 * property of the logical flow, not of any one transport.
 */
export class MessagePipeline {
  private correlator = new Correlator();
  /** Per-rule fuzz cursors — owned here so each pipeline has its own state and
   *  no module globals are involved (§3.2). */
  private fuzz = new FuzzState();
  /** Per-rule match counters for stateful predicates (afterCalls) — owned here
   *  for the same reason: pipeline-scoped state, never a module global (§3.2). */
  private ruleState = new RuleState();

  /** Running session tally for the end-of-session summary (§3.6). */
  private stats = { messages: 0, tampered: 0, dropped: 0, tools: new Set<string>() };

  constructor(private opts: PipelineOptions) {}

  /** Snapshot the session counters for the exit summary. */
  summary(): SessionSummary {
    return {
      messages: this.stats.messages,
      tampered: this.stats.tampered,
      dropped: this.stats.dropped,
      tools: [...this.stats.tools].sort(),
    };
  }

  /** Static scope membership (direction/method/tool), ignoring onlyTampered —
   *  this gates whether rules run and whether the message may be held. */
  private isCandidate(flow: FlowMessage): boolean {
    const s = this.opts.scope;
    if (!s) return true;
    return inScope({ ...s, onlyTampered: false }, flow);
  }

  /** Emit a log record, suppressing stderr (and optionally the JSONL record)
   *  for out-of-scope traffic. */
  private log(
    flow: FlowMessage,
    applied: string[],
    dropped: boolean,
    extra: MessageLogExtra,
    visible: boolean
  ): void {
    this.opts.logger.message(flow, applied, dropped, {
      ...extra,
      quiet: !visible,
      skipRecord: !visible && !!this.opts.scopeAffectsLog,
    });
  }

  /** Run every detector read-only against the flow, isolating failures. A
   *  detector that throws is logged and skipped — it never takes the message
   *  (or any other detector) down with it (Invariant #2). */
  private detect(flow: FlowMessage): void {
    const detectors = this.opts.detectors;
    const sink = this.opts.findings;
    if (!detectors || detectors.length === 0 || !sink) return;
    for (const d of detectors) {
      try {
        d.inspect(flow, sink);
      } catch (err) {
        this.opts.logger.error(`detector threw (${(err as Error)?.message ?? err}); ignoring`);
      }
    }
  }

  async process(raw: string, direction: Direction): Promise<ProcessResult> {
    this.stats.messages++;
    const parsed = parseLine(raw);

    // Maintain correlation in BOTH directions, for EVERY message (even out of
    // scope) so correlation keys stay intact (Invariant #4). MCP is
    // bidirectional: the server issues requests too (sampling/createMessage,
    // roots/list, elicitation/create) whose replies travel the other way. The
    // correlator keys by (direction, id) so the two id-spaces never collide.
    this.correlator.noteRequest(parsed, direction);
    const correlatedMethod = this.correlator.resolve(parsed, direction);

    const flow: FlowMessage = { ...parsed, direction, correlatedMethod, ts: Date.now() };

    // Record every tool name we see — before the scope gate, so out-of-scope
    // (forwarded-untouched) tool traffic still counts toward "tools seen".
    const method = flow.method ?? flow.correlatedMethod;
    const toolName = flow.json?.params?.name;
    if (method === "tools/call" && typeof toolName === "string") this.stats.tools.add(toolName);

    // Opaque relay for anything we couldn't parse — never block the wire. Scope
    // still decides visibility (an unparseable line has no method, so a
    // method/tool scope treats it as out of scope).
    if (parsed.kind === "unknown" || !parsed.json) {
      this.log(flow, [], false, { forwarded: raw }, this.isCandidate(flow));
      return { forward: raw, flow, applied: [], manualEdit: false };
    }

    // Passive detection (§3.4, §3.9). Run on EVERY parseable message, regardless
    // of scope or any later tamper/drop decision, so out-of-scope and dropped
    // server output is still inspected. Detectors read the ORIGINAL message
    // (never the tampered clone), are read-only, and are each wrapped so a
    // throwing detector can never block the wire (Invariant #2).
    this.detect(flow);

    // Scope gate: out-of-scope traffic is ALWAYS forwarded untouched — no rules,
    // no interactive hold — and suppressed from the stderr log (§3.6).
    if (!this.isCandidate(flow)) {
      this.log(flow, [], false, { forwarded: raw }, false);
      return { forward: raw, flow, applied: [], manualEdit: false };
    }

    // 1) Headless rules run first (auto-tamper).
    const result = applyRules(
      this.opts.rules,
      flow,
      this.opts.logger,
      this.fuzz,
      this.ruleState,
      this.opts.ruleActionPlugins
    );
    if (result.json === null) {
      // Dropped by a rule: don't leak the correlator entry for a dropped
      // request (its reply will never arrive to clear it).
      this.correlator.forget(parsed, direction);
      this.stats.tampered++;
      this.stats.dropped++;
      this.log(flow, result.applied, true, { forwarded: null }, true);
      return { forward: null, flow, applied: result.applied, manualEdit: false };
    }

    // onlyTampered (§3.6): a candidate that no rule changed is out of scope for
    // display + interactive hold, but is still forwarded (untouched) and logged.
    const visible = inScope(this.opts.scope, flow, result.applied);

    // 2) Interactive review (optional, in-scope only) — operator sees the
    //    rule-applied message.
    let outJson = result.json;
    let changed = result.changed;
    let manualEdit = false;
    if (visible && this.opts.intercept?.shouldHold()) {
      const decision = await this.opts.intercept.review(flow, outJson);
      if (decision.action === "drop") {
        this.correlator.forget(parsed, direction);
        this.stats.tampered++;
        this.stats.dropped++;
        const applied = [...result.applied, "manual-drop"];
        this.log(flow, applied, true, { forwarded: null }, true);
        return { forward: null, flow, applied, manualEdit: false };
      }
      if (JSON.stringify(decision.json) !== JSON.stringify(outJson)) {
        outJson = decision.json;
        changed = true;
        manualEdit = true;
      }
    }

    if (result.applied.length > 0 || manualEdit) this.stats.tampered++;
    const out = changed ? serialize(outJson) : raw;
    this.log(flow, result.applied, false, { forwarded: out, manualEdit }, visible);
    return { forward: out, flow, applied: result.applied, manualEdit };
  }
}
