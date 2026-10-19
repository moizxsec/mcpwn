import type { Direction, RpcMessage } from "../types.js";

/** The reply to a request flows back the opposite way it was sent. */
function opposite(direction: Direction): Direction {
  return direction === "client->server" ? "server->client" : "client->server";
}

/**
 * Tracks in-flight requests so responses (which carry no `method` on the
 * wire) can be tagged with the method that produced them. Without this,
 * rules and the UI cannot say "this is the tools/call result".
 *
 * MCP is bidirectional: the client issues requests (tools/call, tools/list,
 * …) *and* the server issues requests back (sampling/createMessage,
 * roots/list, elicitation/create) whose replies travel the other way. The
 * two id-spaces are independent and collide (both start at 1), so the
 * in-flight map is keyed by `(request-direction, id)`.
 */
export class Correlator {
  private inFlight = new Map<string, string>();

  private key(direction: Direction, id: unknown): string {
    return direction + "\u0000" + JSON.stringify(id ?? null);
  }

  /** Record an outgoing request's id->method mapping, keyed by the direction
   *  the request itself travelled. */
  noteRequest(msg: RpcMessage, direction: Direction): void {
    if (msg.kind === "request" && msg.method && msg.id !== undefined) {
      this.inFlight.set(this.key(direction, msg.id), msg.method);
    }
  }

  /** Resolve the originating method for a response/error by its id. The
   *  request it answers flowed the *opposite* direction, so look there. */
  resolve(msg: RpcMessage, direction: Direction): string | undefined {
    if ((msg.kind === "response" || msg.kind === "error") && msg.id !== undefined) {
      const k = this.key(opposite(direction), msg.id);
      const method = this.inFlight.get(k);
      this.inFlight.delete(k);
      return method;
    }
    return undefined;
  }

  /** Forget a request we noted but then dropped, so its entry does not leak
   *  (the response will never arrive to clear it). No-op for non-requests. */
  forget(msg: RpcMessage, direction: Direction): void {
    if (msg.kind === "request" && msg.id !== undefined) {
      this.inFlight.delete(this.key(direction, msg.id));
    }
  }
}
