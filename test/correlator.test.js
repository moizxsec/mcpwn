import test from "node:test";
import assert from "node:assert/strict";
import { Correlator } from "../dist/engine/correlator.js";
import { parseLine } from "../dist/engine/parser.js";

const req = (id, method) => parseLine(JSON.stringify({ jsonrpc: "2.0", id, method }));
const res = (id) => parseLine(JSON.stringify({ jsonrpc: "2.0", id, result: {} }));
const err = (id) => parseLine(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -1, message: "x" } }));

test("resolves a client->server request with its server->client response", () => {
  const c = new Correlator();
  c.noteRequest(req(1, "tools/call"), "client->server");
  assert.equal(c.resolve(res(1), "server->client"), "tools/call");
});

test("resolves a server->client request with its client->server response", () => {
  // MCP server-initiated requests (sampling/createMessage, roots/list, …)
  // flow S->C and their replies flow C->S.
  const c = new Correlator();
  c.noteRequest(req(1, "sampling/createMessage"), "server->client");
  assert.equal(c.resolve(res(1), "client->server"), "sampling/createMessage");
});

test("colliding ids in the two directions do not cross-resolve", () => {
  const c = new Correlator();
  // Both id-spaces start at 1 and collide.
  c.noteRequest(req(1, "tools/call"), "client->server");
  c.noteRequest(req(1, "sampling/createMessage"), "server->client");

  // Reply to the server's request travels C->S.
  assert.equal(c.resolve(res(1), "client->server"), "sampling/createMessage");
  // Reply to the client's request travels S->C.
  assert.equal(c.resolve(res(1), "server->client"), "tools/call");
});

test("resolve clears the entry so a repeat id is not misattributed", () => {
  const c = new Correlator();
  c.noteRequest(req(5, "tools/call"), "client->server");
  assert.equal(c.resolve(res(5), "server->client"), "tools/call");
  assert.equal(c.resolve(res(5), "server->client"), undefined);
});

test("resolve works for error responses too", () => {
  const c = new Correlator();
  c.noteRequest(req(9, "tools/list"), "client->server");
  assert.equal(c.resolve(err(9), "server->client"), "tools/list");
});

test("forget removes a noted request so a dropped request does not leak", () => {
  const c = new Correlator();
  const r = req(3, "tools/call");
  c.noteRequest(r, "client->server");
  c.forget(r, "client->server");
  assert.equal(c.resolve(res(3), "server->client"), undefined);
});

test("noteRequest ignores non-requests; resolve returns undefined when unknown", () => {
  const c = new Correlator();
  c.noteRequest(res(1), "server->client"); // not a request -> no-op
  assert.equal(c.resolve(res(1), "client->server"), undefined);
});

// --- bounded growth: TTL + LRU eviction (long-session safety) ---------------

test("normal request/response timing still correlates with TTL enabled", () => {
  // A response arriving well within the TTL must resolve exactly as before.
  const c = new Correlator({ ttlMs: 1000 });
  c.noteRequest(req(1, "tools/call"), "client->server", 0);
  assert.equal(c.resolve(res(1), "server->client", 500), "tools/call");
});

test("an unanswered request past its TTL is evicted, not leaked", () => {
  const c = new Correlator({ ttlMs: 1000 });
  c.noteRequest(req(1, "tools/call"), "client->server", 0);
  // A later request triggers lazy eviction of the expired entry.
  c.noteRequest(req(2, "tools/list"), "client->server", 5000);
  assert.equal(c.size(), 1, "expired entry should have been reaped");
  // The stale response can no longer misattribute.
  assert.equal(c.resolve(res(1), "server->client", 5000), undefined);
  // The fresh one still correlates.
  assert.equal(c.resolve(res(2), "server->client", 5000), "tools/list");
});

test("a response that itself arrives past the TTL is treated as absent", () => {
  const c = new Correlator({ ttlMs: 1000 });
  c.noteRequest(req(1, "tools/call"), "client->server", 0);
  assert.equal(c.resolve(res(1), "server->client", 2000), undefined);
});

test("maxEntries bounds the in-flight map; oldest requests evicted first", () => {
  const c = new Correlator({ ttlMs: 0, maxEntries: 3 }); // TTL off, size cap only
  for (let id = 1; id <= 5; id++) {
    c.noteRequest(req(id, `m/${id}`), "client->server", id);
  }
  assert.equal(c.size(), 3, "map should be capped at maxEntries");
  // The two oldest (1,2) were evicted; the newest three survive.
  assert.equal(c.resolve(res(1), "server->client"), undefined);
  assert.equal(c.resolve(res(2), "server->client"), undefined);
  assert.equal(c.resolve(res(3), "server->client"), "m/3");
  assert.equal(c.resolve(res(4), "server->client"), "m/4");
  assert.equal(c.resolve(res(5), "server->client"), "m/5");
});

test("eviction bounds are configurable and 0 disables them", () => {
  // TTL disabled (0) + no size cap (0): nothing is ever evicted.
  const c = new Correlator({ ttlMs: 0, maxEntries: 0 });
  for (let id = 1; id <= 100; id++) {
    c.noteRequest(req(id, `m/${id}`), "client->server", id * 10_000_000);
  }
  assert.equal(c.size(), 100);
  assert.equal(c.resolve(res(1), "server->client"), "m/1");
});

test("default correlator correlates a normal round trip (sane defaults)", () => {
  // With the shipped defaults, a message pair minutes apart still correlates.
  const c = new Correlator();
  c.noteRequest(req(7, "resources/read"), "client->server");
  assert.equal(c.resolve(res(7), "server->client"), "resources/read");
});
