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
