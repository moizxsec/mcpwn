import type { Direction, RpcMessage } from "../types.js";

/** The reply to a request flows back the opposite way it was sent. */
function opposite(direction: Direction): Direction {
  return direction === "client->server" ? "server->client" : "client->server";
}

/** Tunables for in-flight bookkeeping. Both default to sane values; a value of
 *  0 disables that bound. */
export interface CorrelatorOptions {
  /** Evict in-flight requests that have gone unanswered for longer than this
   *  (ms). Default 5 minutes; 0 disables TTL eviction. A generous default so
   *  it never races normal request/response timing — it only reaps the entries
   *  a response will realistically never arrive to clear. */
  ttlMs?: number;
  /** Hard cap on simultaneously-tracked in-flight requests. When exceeded the
   *  oldest entries are evicted first (bounded LRU). Default 10 000; 0 = no cap. */
  maxEntries?: number;
}

const DEFAULT_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_ENTRIES = 10_000;

interface Entry {
  method: string;
  /** When the request was noted (ms epoch) — for TTL eviction. */
  ts: number;
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
 *
 * Entries are normally cleared the instant their response is correlated. But
 * a dropped request, a crashed peer, or a server that simply never replies
 * would otherwise leak an entry forever — unbounded growth over a long
 * session. A TTL + size cap reap those orphans without ever disturbing a
 * normally-timed round trip. The `Map` preserves insertion order, which (since
 * each entry's `ts` is stamped at insertion) is also oldest-first order, so
 * both evictors can scan/trim from the front.
 */
export class Correlator {
  private inFlight = new Map<string, Entry>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(opts: CorrelatorOptions = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  }

  private key(direction: Direction, id: unknown): string {
    return direction + "\u0000" + JSON.stringify(id ?? null);
  }

  /** Record an outgoing request's id->method mapping, keyed by the direction
   *  the request itself travelled. Reaps expired/overflowing orphans first so
   *  the map stays bounded in a long session. */
  noteRequest(msg: RpcMessage, direction: Direction, now: number = Date.now()): void {
    if (msg.kind === "request" && msg.method && msg.id !== undefined) {
      this.evictExpired(now);
      // Re-insert at the tail so insertion order stays oldest-first even if the
      // same key is re-noted (keeps the LRU trim correct).
      this.inFlight.delete(this.key(direction, msg.id));
      this.inFlight.set(this.key(direction, msg.id), { method: msg.method, ts: now });
      this.evictOverflow();
    }
  }

  /** Resolve the originating method for a response/error by its id. The
   *  request it answers flowed the *opposite* direction, so look there. An
   *  entry that has already passed its TTL is treated as absent (the response
   *  arrived too late to be trusted) and cleared. */
  resolve(msg: RpcMessage, direction: Direction, now: number = Date.now()): string | undefined {
    if ((msg.kind === "response" || msg.kind === "error") && msg.id !== undefined) {
      const k = this.key(opposite(direction), msg.id);
      const entry = this.inFlight.get(k);
      this.inFlight.delete(k);
      if (!entry) return undefined;
      if (this.ttlMs > 0 && now - entry.ts > this.ttlMs) return undefined;
      return entry.method;
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

  /** Current number of tracked in-flight requests (for tests / introspection). */
  size(): number {
    return this.inFlight.size;
  }

  /** Drop every entry older than the TTL. Entries are in insertion order, which
   *  is ascending-`ts` order, so we can stop at the first live entry. */
  private evictExpired(now: number): void {
    if (this.ttlMs <= 0) return;
    for (const [k, v] of this.inFlight) {
      if (now - v.ts > this.ttlMs) this.inFlight.delete(k);
      else break;
    }
  }

  /** Trim the oldest entries until the map is within its size cap. */
  private evictOverflow(): void {
    if (this.maxEntries <= 0) return;
    while (this.inFlight.size > this.maxEntries) {
      const oldest = this.inFlight.keys().next().value;
      if (oldest === undefined) break;
      this.inFlight.delete(oldest);
    }
  }
}
