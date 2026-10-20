/**
 * Shared, zero-dependency stdio JSON-RPC 2.0 harness for the DVMCP servers.
 *
 * It is ONLY the transport plumbing — newline-delimited JSON-RPC over stdio,
 * the `initialize`/`ping` boilerplate, and a helper for a server to open a
 * server->client request (e.g. `sampling/createMessage`). Every DVMCP server
 * keeps its *vulnerability* self-contained and obvious by registering a handful
 * of method handlers here; none of the attack logic lives in this file.
 *
 * Matches examples/vulnerable-server.mjs: Node >=18, no runtime deps, stdout is
 * the clean JSON-RPC channel, stderr is for human notes only.
 *
 *   serve({
 *     name: "dvmcp-...",
 *     capabilities: { tools: {}, resources: {} },
 *     handlers: {
 *       "tools/list": (id, params, ctx) => ctx.ok(id, { tools: [...] }),
 *       "tools/call": (id, params, ctx) => { ... },
 *     },
 *   });
 */

export function serve({ name, version = "0.0.1", capabilities = { tools: {} }, handlers = {} }) {
  const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
  const ok = (id, result) => send({ jsonrpc: "2.0", id, result });
  const fail = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

  // Open a server->client request (the server driving the client — used by the
  // sampling-abuse server). Fire-and-forget: the harness never blocks on a
  // reply, and a client that declines the request simply sends back an error
  // (a response, which we ignore below).
  let nextServerId = 1;
  const request = (method, params) => {
    const id = `dvmcp-srv-${nextServerId++}`;
    send({ jsonrpc: "2.0", id, method, params });
    return id;
  };

  const note = (text) => process.stderr.write(`[${name}] ${text}\n`);
  const ctx = { send, ok, fail, request, note };

  function handle(msg) {
    if (!msg || typeof msg !== "object") return;
    // Ignore anything without a method: that's a *response* to one of our own
    // server-initiated requests (e.g. a client declining sampling). Never
    // reply to a reply.
    if (typeof msg.method !== "string") return;
    const { id, method, params } = msg;

    if (method === "initialize") {
      ok(id, {
        protocolVersion: "2024-11-05",
        capabilities,
        serverInfo: { name, version },
      });
      return;
    }
    if (method === "ping") {
      ok(id, {});
      return;
    }

    const h = handlers[method];
    if (h) {
      try {
        h(id, params ?? {}, ctx);
      } catch (e) {
        if (id !== undefined) fail(id, -32603, `handler error: ${e.message}`);
      }
      return;
    }

    if (method.startsWith("notifications/")) return; // unhandled notification: no reply
    if (id !== undefined) fail(id, -32601, `Method not found: ${method}`);
  }

  let buf = "";
  process.stdin.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).replace(/\r$/, "");
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        handle(JSON.parse(line));
      } catch {
        /* ignore malformed line */
      }
    }
  });
  process.stdin.on("end", () => process.exit(0));
}

/** Convenience: wrap a plain string as an MCP text content block array. */
export function text(s) {
  return [{ type: "text", text: s }];
}
