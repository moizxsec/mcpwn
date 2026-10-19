import { parseLine, serialize } from "../engine/parser.js";
import { Correlator } from "../engine/correlator.js";
import { applyRules } from "../engine/rules.js";
import type { InterceptController } from "../engine/intercept.js";
import type { Direction, FlowMessage, Rule } from "../types.js";
import type { Logger } from "../logger.js";

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
  /** Max time to hold a message for interactive review before auto-forwarding.
   *  0 (the default, used by stdio) means unlimited. A bounded hold is only
   *  meaningful for request/response transports (HTTP, M3). */
  holdTimeoutMs?: number;
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

  constructor(private opts: PipelineOptions) {}

  async process(raw: string, direction: Direction): Promise<ProcessResult> {
    const parsed = parseLine(raw);

    // Maintain correlation in BOTH directions. MCP is bidirectional: the server
    // issues requests too (sampling/createMessage, roots/list, elicitation/
    // create) whose replies travel the other way. The correlator keys by
    // (direction, id) so the two id-spaces never collide.
    this.correlator.noteRequest(parsed, direction);
    const correlatedMethod = this.correlator.resolve(parsed, direction);

    const flow: FlowMessage = { ...parsed, direction, correlatedMethod, ts: Date.now() };

    // Opaque relay for anything we couldn't parse — never block the wire.
    if (parsed.kind === "unknown" || !parsed.json) {
      this.opts.logger.message(flow, [], false, { forwarded: raw });
      return { forward: raw, flow, applied: [], manualEdit: false };
    }

    // 1) Headless rules run first (auto-tamper).
    const result = applyRules(this.opts.rules, flow, this.opts.logger);
    if (result.json === null) {
      // Dropped by a rule: don't leak the correlator entry for a dropped
      // request (its reply will never arrive to clear it).
      this.correlator.forget(parsed, direction);
      this.opts.logger.message(flow, result.applied, true, { forwarded: null });
      return { forward: null, flow, applied: result.applied, manualEdit: false };
    }

    // 2) Interactive review (optional) — operator sees the rule-applied message.
    let outJson = result.json;
    let changed = result.changed;
    let manualEdit = false;
    if (this.opts.intercept?.shouldHold()) {
      const decision = await this.opts.intercept.review(flow, outJson);
      if (decision.action === "drop") {
        this.correlator.forget(parsed, direction);
        const applied = [...result.applied, "manual-drop"];
        this.opts.logger.message(flow, applied, true, { forwarded: null });
        return { forward: null, flow, applied, manualEdit: false };
      }
      if (JSON.stringify(decision.json) !== JSON.stringify(outJson)) {
        outJson = decision.json;
        changed = true;
        manualEdit = true;
      }
    }

    const out = changed ? serialize(outJson) : raw;
    this.opts.logger.message(flow, result.applied, false, { forwarded: out, manualEdit });
    return { forward: out, flow, applied: result.applied, manualEdit };
  }
}
