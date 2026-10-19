import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Transport, TransportDeps } from "./transport.js";
import type { MessagePipeline } from "../core/pipeline.js";
import type { Logger } from "../logger.js";

export type HttpMode = "streamable" | "sse" | "auto";

export interface HttpTransportOptions extends TransportDeps {
  /** Interface to bind. Empty / "0.0.0.0" binds all; endpoint rewrites use
   *  127.0.0.1 in that case. */
  listenHost: string;
  /** Port to bind. 0 picks an ephemeral port (used by tests — see `port()`). */
  listenPort: number;
  /** Remote MCP HTTP endpoint, e.g. http://host:1234/mcp. */
  upstream: string;
  /** streamable | sse (legacy) | auto. Only affects legacy endpoint rewriting. */
  mode?: HttpMode;
}

/** HTTP hop-by-hop headers that must not be forwarded by a proxy. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Streamable HTTP + SSE reverse proxy (§3.1).
 *
 *   MCP client ──HTTP──►  mcpwn  ──HTTP──►  remote MCP server (--upstream)
 *
 * Every JSON-RPC message — whether it arrives as a POST body, an
 * `application/json` response, or a `data:` line inside a `text/event-stream` —
 * goes through the SAME {@link MessagePipeline} as stdio, so tamper rules,
 * correlation, logging and detectors behave identically across transports.
 *
 * Framing lives here: SSE event frames are re-serialized preserving `event:` /
 * `id:` lines byte-for-byte, JSON-RPC batches are relayed opaquely, and
 * `Mcp-Session-Id` / `Last-Event-ID` are forwarded verbatim both ways. On any
 * failure the original bytes are forwarded (Invariant #2); when idle, traffic is
 * byte-identical at the JSON layer and SSE framing is preserved (Invariant #3).
 *
 * Interactive intercept (-i) is DISABLED for HTTP in v2 (there is no single
 * controlling flow to pause); holdTimeoutMs is plumbed through the pipeline but
 * inert while intercept is off.
 */
export class HttpTransport implements Transport {
  private readonly pipeline: MessagePipeline;
  private readonly logger: Logger;
  private readonly upstreamUrl: URL;
  private readonly mode: HttpMode;
  private readonly rewriteEndpoint: boolean;
  private readonly listenHost: string;

  private server?: http.Server;
  private boundPort = 0;
  private publicOrigin!: URL;
  private closing = false;
  private signalHandler?: (sig: NodeJS.Signals) => void;

  private readonly ready: Promise<{ host: string; port: number }>;
  private readyResolve!: (v: { host: string; port: number }) => void;

  constructor(private opts: HttpTransportOptions) {
    this.pipeline = opts.pipeline;
    this.logger = opts.logger;
    this.upstreamUrl = new URL(opts.upstream);
    this.mode = opts.mode ?? "auto";
    // Legacy SSE advertises a POST endpoint via an `endpoint` event; rewrite it
    // so the client POSTs back through mcpwn. Harmless in streamable mode (no
    // such event is ever sent), so we also do it in "auto".
    this.rewriteEndpoint = this.mode === "sse" || this.mode === "auto";
    this.listenHost = opts.listenHost && opts.listenHost.length ? opts.listenHost : "127.0.0.1";
    this.ready = new Promise((r) => (this.readyResolve = r));
  }

  /** Resolves with the bound port once listening (ephemeral-port tests use it). */
  async port(): Promise<number> {
    return (await this.ready).port;
  }

  start(): Promise<number> {
    this.server = http.createServer((req, res) => {
      this.onRequest(req, res).catch((err) => {
        this.logger.error(`http request handler failed: ${(err as Error)?.message ?? err}`);
        if (!res.headersSent) {
          try {
            res.writeHead(502, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "mcpwn proxy error" }));
          } catch {
            /* client gone */
          }
        } else {
          try {
            res.end();
          } catch {
            /* client gone */
          }
        }
      });
    });
    // Malformed client requests must not take the server down.
    this.server.on("clientError", (_err, socket) => {
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
    });

    return new Promise<number>((resolve) => {
      this.server!.on("close", () => resolve(0));
      this.server!.listen(this.opts.listenPort, this.listenHost, () => {
        const addr = this.server!.address() as AddressInfo;
        this.boundPort = addr.port;
        const publicHost =
          this.listenHost === "0.0.0.0" || this.listenHost === "::" ? "127.0.0.1" : this.listenHost;
        this.publicOrigin = new URL(`http://${publicHost}:${this.boundPort}`);
        this.logger.info(
          `http proxy listening on ${this.listenHost}:${this.boundPort} -> ${this.opts.upstream} (mode: ${this.mode})`
        );
        this.logger.info("interactive intercept (-i) is disabled for HTTP in v2");
        this.readyResolve({ host: this.listenHost, port: this.boundPort });
      });
      this.installSignalHandlers();
    });
  }

  stop(): Promise<void> {
    this.closing = true;
    if (this.signalHandler) {
      process.off("SIGINT", this.signalHandler);
      process.off("SIGTERM", this.signalHandler);
      this.signalHandler = undefined;
    }
    return new Promise<void>((resolve) => {
      if (!this.server) return resolve();
      // Force-close keep-alive sockets so close() doesn't hang.
      (this.server as any).closeAllConnections?.();
      this.server.close(() => resolve());
    });
  }

  private installSignalHandlers(): void {
    this.signalHandler = (sig: NodeJS.Signals) => {
      this.logger.info(`received ${sig}, shutting down http proxy`);
      void this.stop();
    };
    process.on("SIGINT", this.signalHandler);
    process.on("SIGTERM", this.signalHandler);
  }

  // --- request path (client -> server) -------------------------------------

  private async onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    let outBody = Buffer.alloc(0);

    if (body.length > 0) {
      // One POST body = one JSON-RPC message (a batch array is relayed opaquely
      // by the pipeline). Process it as client->server so correlation + rules +
      // detectors see it exactly as stdio would.
      const { forward } = await this.pipeline.process(body.toString("utf8"), "client->server");
      if (forward === null) {
        // Dropped by a rule: do NOT reach upstream; acknowledge so the client
        // unblocks (the correlator already forgot the request).
        try {
          res.writeHead(202, { "content-type": "application/json" });
          res.end();
        } catch {
          /* client gone */
        }
        return;
      }
      outBody = Buffer.from(forward, "utf8");
    }

    this.proxyToUpstream(req, res, outBody);
  }

  private proxyToUpstream(req: IncomingMessage, res: ServerResponse, outBody: Buffer): void {
    const target = resolveTarget(this.upstreamUrl, req.url ?? "/");
    const isHttps = target.protocol === "https:";
    const mod = isHttps ? https : http;

    const headers = filterRequestHeaders(req.headers, target.host);
    if (outBody.length > 0) headers["content-length"] = String(outBody.byteLength);

    const upReq = mod.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        path: target.pathname + target.search,
        method: req.method,
        headers,
      },
      (upRes) => this.handleUpstreamResponse(upRes, res)
    );

    upReq.on("error", (err) => {
      this.logger.error(`upstream error: ${(err as Error).message}`);
      if (!res.headersSent) {
        try {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "upstream unreachable" }));
        } catch {
          /* client gone */
        }
      } else {
        try {
          res.end();
        } catch {
          /* client gone */
        }
      }
    });

    // Tear down the upstream request if the client disconnects.
    res.on("close", () => {
      try {
        upReq.destroy();
      } catch {
        /* already gone */
      }
    });

    if (outBody.length > 0) upReq.write(outBody);
    upReq.end();
  }

  // --- response path (server -> client) ------------------------------------

  private handleUpstreamResponse(upRes: IncomingMessage, res: ServerResponse): void {
    const status = upRes.statusCode ?? 502;
    const ct = String(upRes.headers["content-type"] ?? "");
    const enc = String(upRes.headers["content-encoding"] ?? "").toLowerCase();
    const compressed = enc.length > 0 && enc !== "identity";
    const isSse = ct.includes("text/event-stream");
    const isJson = ct.includes("application/json");

    if (isSse && !compressed) {
      this.streamSse(upRes, res, status);
      return;
    }

    // Buffered path: JSON responses go through the pipeline; anything else (and
    // anything compressed, which we can't tamper safely) is relayed unchanged.
    const chunks: Buffer[] = [];
    upRes.on("data", (c: Buffer) => chunks.push(c));
    upRes.on("error", () => {
      if (!res.headersSent) {
        try {
          res.writeHead(502);
        } catch {
          /* client gone */
        }
      }
      try {
        res.end();
      } catch {
        /* client gone */
      }
    });
    upRes.on("end", () => {
      void (async () => {
        const buf = Buffer.concat(chunks);
        const headers = filterResponseHeaders(upRes.headers);
        let outBuf = buf;
        if (isJson && !compressed && buf.length > 0) {
          try {
            const { forward } = await this.pipeline.process(buf.toString("utf8"), "server->client");
            outBuf = forward === null ? Buffer.alloc(0) : Buffer.from(forward, "utf8");
          } catch {
            // Never block the wire: forward the original bytes on any failure.
            outBuf = buf;
          }
        }
        headers["content-length"] = String(outBuf.byteLength);
        try {
          res.writeHead(status, headers);
          res.end(outBuf);
        } catch {
          /* client gone */
        }
      })();
    });
  }

  private streamSse(upRes: IncomingMessage, res: ServerResponse, status: number): void {
    const headers = filterResponseHeaders(upRes.headers);
    try {
      res.writeHead(status, headers);
    } catch {
      return; /* client gone */
    }

    const framer = new SseFramer();
    // Per-stream async chain preserves event order even though process() is async.
    let queue: Promise<void> = Promise.resolve();
    const enqueue = (block: string, sep: string) => {
      queue = queue.then(() => this.handleSseEvent(block, sep, res));
    };

    upRes.on("data", (chunk: Buffer) => {
      for (const ev of framer.push(chunk)) enqueue(ev.block, ev.sep);
    });
    const finish = () => {
      const rest = framer.flush();
      if (rest) enqueue(rest.block, rest.sep);
      queue.then(() => {
        try {
          res.end();
        } catch {
          /* client gone */
        }
      });
    };
    upRes.on("end", finish);
    upRes.on("error", finish);
  }

  /** Re-emit one SSE event, tampering only its JSON-RPC `data:` payload and
   *  preserving every other line (event:/id:/retry:/comments) byte-for-byte. */
  private async handleSseEvent(block: string, sep: string, res: ServerResponse): Promise<void> {
    try {
      const lines = block.split(/\r\n|\n|\r/);
      const dataLines: string[] = [];
      let eventType = "message";
      for (const line of lines) {
        if (line.startsWith("data:")) {
          dataLines.push(line);
        } else {
          const m = /^event: ?(.*)$/.exec(line);
          if (m) eventType = m[1].trim();
        }
      }

      // No data field (comment / keepalive / field-only event): pass through.
      if (dataLines.length === 0) {
        res.write(block + sep);
        return;
      }

      // SSE joins multiple data lines with "\n"; one leading space is stripped.
      const payload = dataLines.map((l) => l.replace(/^data: ?/, "")).join("\n");

      // Legacy SSE "endpoint" event carries a URL, not JSON-RPC: rewrite it so
      // the client POSTs back through mcpwn rather than straight to upstream.
      if (eventType === "endpoint" && this.rewriteEndpoint) {
        const rewritten = this.rewriteEndpointUrl(payload);
        if (rewritten === payload) res.write(block + sep);
        else res.write(rebuildEventBlock(lines, rewritten) + sep);
        return;
      }

      const { forward } = await this.pipeline.process(payload, "server->client");
      if (forward === null) return; // dropped: emit nothing for this event
      if (forward === payload) {
        res.write(block + sep); // unchanged: byte-for-byte frame
        return;
      }
      res.write(rebuildEventBlock(lines, forward) + sep);
    } catch {
      // Never block the wire: forward the original event frame unchanged.
      try {
        res.write(block + sep);
      } catch {
        /* client gone */
      }
    }
  }

  private rewriteEndpointUrl(url: string): string {
    const u = url.trim();
    if (/^https?:\/\//i.test(u)) {
      try {
        const parsed = new URL(u);
        parsed.protocol = this.publicOrigin.protocol;
        parsed.host = this.publicOrigin.host;
        return parsed.toString();
      } catch {
        return url;
      }
    }
    // A relative endpoint is already relative to the client's connection (us).
    return url;
  }
}

/** Collect a request/response body into a single Buffer. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** Resolve the upstream target for an incoming request path. When the client
 *  hits the proxy root (or the upstream's own path), the upstream path is used;
 *  otherwise the client path is forwarded under the upstream origin. Incoming
 *  query params win over the upstream's. */
function resolveTarget(base: URL, reqUrl: string): URL {
  const incoming = new URL(reqUrl, "http://proxy.invalid");
  const target = new URL(base.toString());
  target.pathname =
    incoming.pathname === "/" || incoming.pathname === base.pathname
      ? base.pathname
      : incoming.pathname;
  const params = new URLSearchParams(base.search);
  for (const [k, v] of incoming.searchParams) params.set(k, v);
  const q = params.toString();
  target.search = q ? `?${q}` : "";
  return target;
}

function filterRequestHeaders(
  headers: IncomingMessage["headers"],
  upstreamHost: string
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    // host is reset below; content-length is recomputed; accept-encoding is
    // dropped so upstream sends identity bytes we can tamper + diff.
    if (lk === "host" || lk === "content-length" || lk === "accept-encoding") continue;
    if (v !== undefined) out[k] = v;
  }
  out["host"] = upstreamHost;
  return out;
}

function filterResponseHeaders(
  headers: IncomingMessage["headers"]
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    // content-length is set per-body (JSON may change length; SSE is streamed).
    if (lk === "content-length") continue;
    if (v !== undefined) out[k] = v;
  }
  return out;
}

/** Rebuild an SSE event block with a new data payload, keeping all other lines
 *  verbatim. Collapses multiple data lines to one (only hit when tampered). */
function rebuildEventBlock(lines: string[], newPayload: string): string {
  const out: string[] = [];
  let emitted = false;
  for (const line of lines) {
    if (line.startsWith("data:")) {
      if (!emitted) {
        out.push("data: " + newPayload);
        emitted = true;
      }
    } else {
      out.push(line);
    }
  }
  if (!emitted) out.push("data: " + newPayload);
  return out.join("\n");
}

/**
 * Splits a byte stream into SSE event frames. An event ends at a blank line
 * (`\r\n\r\n`, `\n\n` or `\r\r`); each returned pair keeps the frame body and
 * its EXACT separator so idle frames can be re-emitted byte-for-byte.
 */
export class SseFramer {
  private buf = "";

  push(chunk: Buffer | string): Array<{ block: string; sep: string }> {
    this.buf += chunk.toString("utf8");
    const out: Array<{ block: string; sep: string }> = [];
    for (;;) {
      const m = /\r\n\r\n|\n\n|\r\r/.exec(this.buf);
      if (!m) break;
      out.push({ block: this.buf.slice(0, m.index), sep: m[0] });
      this.buf = this.buf.slice(m.index + m[0].length);
    }
    return out;
  }

  /** Any trailing partial frame (flushed when the upstream stream ends). */
  flush(): { block: string; sep: string } | null {
    if (this.buf.length === 0) return null;
    const block = this.buf;
    this.buf = "";
    return { block, sep: "" };
  }
}
