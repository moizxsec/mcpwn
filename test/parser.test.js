import test from "node:test";
import assert from "node:assert/strict";
import { parseLine, serialize, LineFramer } from "../dist/engine/parser.js";

// --- classify (exercised through parseLine) ------------------------------

test("parseLine classifies a request (method + id)", () => {
  const m = parseLine('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}');
  assert.equal(m.kind, "request");
  assert.equal(m.id, 1);
  assert.equal(m.method, "tools/call");
  assert.deepEqual(m.json.params, {});
});

test("parseLine classifies a notification (method, no id)", () => {
  const m = parseLine('{"jsonrpc":"2.0","method":"notifications/initialized"}');
  assert.equal(m.kind, "notification");
  assert.equal(m.id, undefined);
  assert.equal(m.method, "notifications/initialized");
});

test("parseLine classifies a response (id + result)", () => {
  const m = parseLine('{"jsonrpc":"2.0","id":7,"result":{"ok":true}}');
  assert.equal(m.kind, "response");
  assert.equal(m.id, 7);
  assert.equal(m.method, undefined); // responses carry no method on the wire
});

test("parseLine classifies an error (id + error)", () => {
  const m = parseLine('{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"nope"}}');
  assert.equal(m.kind, "error");
  assert.equal(m.id, 7);
});

test("parseLine preserves a null id on responses", () => {
  const m = parseLine('{"jsonrpc":"2.0","id":null,"result":{}}');
  assert.equal(m.kind, "response");
  assert.equal(m.id, null);
});

test("parseLine returns unknown + raw for invalid JSON (never throws)", () => {
  const raw = "this is not json {";
  const m = parseLine(raw);
  assert.equal(m.kind, "unknown");
  assert.equal(m.json, undefined);
  assert.equal(m.raw, raw);
});

test("parseLine treats a JSON-RPC batch array as unknown (opaque relay)", () => {
  const m = parseLine('[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]');
  assert.equal(m.kind, "unknown");
  assert.ok(Array.isArray(m.json)); // json is still parsed, just not classified
});

test("parseLine treats scalars and null as unknown", () => {
  assert.equal(parseLine("42").kind, "unknown");
  assert.equal(parseLine('"a string"').kind, "unknown");
  assert.equal(parseLine("null").kind, "unknown");
  assert.equal(parseLine("true").kind, "unknown");
});

test("serialize produces a single-line, embedded-newline-free string", () => {
  const out = serialize({ a: 1, b: "x\ny" });
  assert.ok(!out.includes("\n"));
  assert.deepEqual(JSON.parse(out), { a: 1, b: "x\ny" });
});

// --- LineFramer ----------------------------------------------------------

test("LineFramer buffers a partial line until the newline arrives", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push('{"a":1}'), []);
  assert.deepEqual(f.push("\n"), ['{"a":1}']);
});

test("LineFramer emits multiple complete lines from one chunk", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push("a\nb\nc\n"), ["a", "b", "c"]);
});

test("LineFramer strips trailing CR (CRLF framing)", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push("x\r\n"), ["x"]);
});

test("LineFramer handles a CRLF split across chunk boundaries", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push("x\r"), []);
  assert.deepEqual(f.push("\n"), ["x"]);
});

test("LineFramer skips empty lines", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push("\n\n"), []);
  assert.deepEqual(f.push("a\n\nb\n"), ["a", "b"]);
});

test("LineFramer reassembles a line split across chunks", () => {
  const f = new LineFramer();
  assert.deepEqual(f.push("he"), []);
  assert.deepEqual(f.push("ll"), []);
  assert.deepEqual(f.push("o\n"), ["hello"]);
});

test("LineFramer flush returns the unterminated remainder exactly once", () => {
  const f = new LineFramer();
  f.push("partial");
  assert.equal(f.flush(), "partial");
  assert.equal(f.flush(), null);
});

test("LineFramer flush returns null when nothing buffered", () => {
  const f = new LineFramer();
  assert.equal(f.flush(), null);
});
