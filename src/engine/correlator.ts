import type { RpcMessage } from "../types.js";

/**
 * Tracks in-flight requests so responses (which carry no `method` on the
 * wire) can be tagged with the method that produced them. Without this,
 * rules and the UI cannot say "this is the tools/call result".
 */
export class Correlator {
  private inFlight = new Map<string, string>();

  private key(id: unknown): string {
    return JSON.stringify(id ?? null);
  }

  /** Record an outgoing request's id->method mapping. */
  noteRequest(msg: RpcMessage): void {
    if (msg.kind === "request" && msg.method && msg.id !== undefined) {
      this.inFlight.set(this.key(msg.id), msg.method);
    }
  }

  /** Resolve the originating method for a response/error by its id. */
  resolve(msg: RpcMessage): string | undefined {
    if ((msg.kind === "response" || msg.kind === "error") && msg.id !== undefined) {
      const k = this.key(msg.id);
      const method = this.inFlight.get(k);
      this.inFlight.delete(k);
      return method;
    }
    return undefined;
  }
}
