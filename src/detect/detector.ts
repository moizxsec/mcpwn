import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";

/**
 * A passive detector (§3.4, §3.9). The pipeline calls `inspect` on every
 * parseable message, read-only: a detector MUST NOT mutate the flow and MUST
 * NOT throw into the pipeline (each call is wrapped in try/catch, but a detector
 * is still expected to be total). Detectors only ever record {@link Finding}s on
 * the sink — they never change what mcpwn forwards on the wire (Invariant #2).
 */
export interface Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void;
}
