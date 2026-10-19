import type { MessagePipeline } from "../core/pipeline.js";
import type { Logger } from "../logger.js";

/**
 * A transport relays framed MCP traffic through a {@link MessagePipeline}. It
 * owns framing + I/O (stdio newlines, HTTP/SSE frames) and the child/connection
 * lifecycle; the pipeline owns the parse→correlate→rules→intercept→forward
 * decision. Keeping the two apart lets stdio and HTTP share identical tamper
 * semantics.
 */
export interface Transport {
  /** Start relaying; resolves with the exit/status code when the session ends. */
  start(): Promise<number>;
  /** Tear down the transport (kill child, close sockets, restore the tty). */
  stop(): Promise<void> | void;
}

/** The collaborators every transport needs. */
export interface TransportDeps {
  pipeline: MessagePipeline;
  logger: Logger;
}
