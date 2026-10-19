import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { MessagePipeline } from "../dist/core/pipeline.js";
import { HttpTransport } from "../dist/transports/http.js";

const MARKER = "<<INJECTED>>";

function stubLogger() {
  return { message() {}, error() {}, info() {}, banner() {} };
}

const jsonResp = (id) =>
  `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"content":[{"type":"text","text":"hello"}]}}`;

// An SSE body with two frames: a message event (with event:/id:/data:) and a
// comment keepalive frame. Exact bytes, to prove framing is preserved.
const sseBody = (id) =>
  `event: message\nid: 1\ndata: ${jsonResp(id)}\n\n` + `: keepalive\n\n`;

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

/** Start a stub upstream + an HttpTransport in front of it, run `fn`, tear down. */
async function withProxy(rules, fn) {
  const state = { lastBody: null, lastHeaders: null, lastMethod: null };

  const upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const bodyBuf = Buffer.concat(chunks);
      state.lastBody = bodyBuf;
      state.lastHeaders = req.headers;
      state.lastMethod = req.method;
      const url = new URL(req.url, "http://x");
      const wantSse = req.method === "GET" || url.searchParams.get("resp") === "sse";
      let parsed = null;
      try {
        parsed = JSON.parse(bodyBuf.toString("utf8"));
      } catch {
        /* non-JSON / empty */
      }
      const id = parsed && !Array.isArray(parsed) ? parsed.id ?? null : null;

      if (wantSse) {
        res.writeHead(200, { "content-type": "text/event-stream", "mcp-session-id": "sess-1" });
        res.write(sseBody(id));
        res.end();
        return;
      }
      const body = jsonResp(id);
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
        "mcp-session-id": "sess-1",
      });
      res.end(body);
    });
  });
  const upPort = await listen(upstream);

  const logger = stubLogger();
  const pipeline = new MessagePipeline({ rules, logger });
  const transport = new HttpTransport({
    listenHost: "127.0.0.1",
    listenPort: 0,
    upstream: `http://127.0.0.1:${upPort}/`,
    mode: "auto",
    pipeline,
    logger,
  });
  transport.start();
  const port = await transport.port();

  try {
    await fn({ port, state });
  } finally {
    await transport.stop();
    await new Promise((r) => upstream.close(r));
  }
}

function request(port, { method = "GET", path = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const callReq = (id) =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "read_file" } });

test("idle: JSON response is byte-identical through the proxy", async () => {
  await withProxy([], async ({ port }) => {
    const res = await request(port, {
      method: "POST",
      path: "/",
      headers: { "content-type": "application/json" },
      body: callReq(1),
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.toString("utf8"), jsonResp(1)); // byte-identical
    assert.equal(res.headers["mcp-session-id"], "sess-1"); // session id forwarded s->c
  });
});

test("idle: SSE framing is preserved byte-for-byte; headers forwarded both ways", async () => {
  await withProxy([], async ({ port, state }) => {
    const res = await request(port, {
      method: "GET",
      path: "/?resp=sse",
      headers: { accept: "text/event-stream", "last-event-id": "42" },
    });
    assert.equal(res.body.toString("utf8"), sseBody(null)); // exact frames preserved
    assert.equal(res.headers["mcp-session-id"], "sess-1");
    assert.equal(state.lastHeaders["last-event-id"], "42"); // forwarded c->s verbatim
  });
});

test("injectToolResult tampers a JSON tools/call response", async () => {
  const rules = [
    { name: "inj", direction: "server->client", method: "tools/call", action: { kind: "injectToolResult", mode: "append", text: MARKER } },
  ];
  await withProxy(rules, async ({ port }) => {
    const res = await request(port, {
      method: "POST",
      path: "/",
      headers: { "content-type": "application/json" },
      body: callReq(7),
    });
    const text = res.body.toString("utf8");
    assert.match(text, /hello<<INJECTED>>/);
  });
});

test("injectToolResult tampers an SSE tools/call response, keeping the frame", async () => {
  const rules = [
    { name: "inj", direction: "server->client", method: "tools/call", action: { kind: "injectToolResult", mode: "append", text: MARKER } },
  ];
  await withProxy(rules, async ({ port }) => {
    const res = await request(port, {
      method: "POST",
      path: "/?resp=sse",
      headers: { "content-type": "application/json" },
      body: callReq(8),
    });
    const text = res.body.toString("utf8");
    assert.match(text, /hello<<INJECTED>>/); // payload tampered
    assert.match(text, /event: message/); // event line preserved
    assert.match(text, /\nid: 1\n/); // id line preserved
    assert.match(text, /: keepalive/); // untouched comment frame preserved
  });
});

test("a JSON-RPC batch POST body is relayed opaquely (byte-for-byte)", async () => {
  const rules = [
    { name: "inj", direction: "server->client", method: "tools/call", action: { kind: "injectToolResult", mode: "append", text: MARKER } },
  ];
  const batch = JSON.stringify([
    { jsonrpc: "2.0", id: 1, method: "ping" },
    { jsonrpc: "2.0", id: 2, method: "ping" },
  ]);
  await withProxy(rules, async ({ port, state }) => {
    await request(port, { method: "POST", path: "/", headers: { "content-type": "application/json" }, body: batch });
    assert.equal(state.lastBody.toString("utf8"), batch); // upstream got it unchanged
  });
});

test("correlation across the SSE channel: POST request enables tamper of the SSE reply", async () => {
  const rules = [
    { name: "inj", direction: "server->client", method: "tools/call", action: { kind: "injectToolResult", mode: "append", text: MARKER } },
  ];
  await withProxy(rules, async ({ port }) => {
    // With the POST request first, the SSE reply resolves to tools/call → tampered.
    const posted = await request(port, {
      method: "POST",
      path: "/?resp=sse",
      headers: { "content-type": "application/json" },
      body: callReq(99),
    });
    assert.match(posted.body.toString("utf8"), /hello<<INJECTED>>/);

    // Without a correlating request, an SSE reply has no method → NOT tampered.
    const unposted = await request(port, { method: "GET", path: "/?resp=sse" });
    assert.ok(!unposted.body.toString("utf8").includes(MARKER));
  });
});

test("idle: a batch and plain traffic add no listeners leak (stop removes signal handlers)", async () => {
  const before = process.listenerCount("SIGINT");
  await withProxy([], async () => {});
  assert.equal(process.listenerCount("SIGINT"), before);
});
