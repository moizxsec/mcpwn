import test from "node:test";
import assert from "node:assert/strict";
import { MessagePipeline } from "../dist/core/pipeline.js";

// A logger stub that satisfies the surface the pipeline + rules engine use
// (message/error) and records what it was told, so tests can inspect it.
function stubLogger() {
  const messages = [];
  const errors = [];
  return {
    messages,
    errors,
    message: (msg, applied, dropped, extra) => messages.push({ msg, applied, dropped, extra }),
    error: (text) => errors.push(text),
    info: () => {},
    banner: () => {},
  };
}

const C2S = "client->server";
const S2C = "server->client";

const req = (id, method, params = {}) => JSON.stringify({ jsonrpc: "2.0", id, method, params });
const toolCallResult = (id, text) =>
  JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });

// --- transparent when idle (Invariant #3) --------------------------------

test("idle (no rules): a parseable message is forwarded byte-identically", async () => {
  const logger = stubLogger();
  const p = new MessagePipeline({ rules: [], logger });
  const raw = req(1, "tools/call");
  const r = await p.process(raw, C2S);
  assert.equal(r.forward, raw); // byte-identical, no re-serialization
  assert.deepEqual(r.applied, []);
  assert.equal(r.manualEdit, false);
});

// --- opaque relay on unparseable -----------------------------------------

test("opaque relay: an unparseable line is forwarded verbatim as unknown", async () => {
  const logger = stubLogger();
  const p = new MessagePipeline({ rules: [], logger });
  const raw = "this is not json {";
  const r = await p.process(raw, S2C);
  assert.equal(r.forward, raw);
  assert.equal(r.flow.kind, "unknown");
  assert.deepEqual(r.applied, []);
});

// --- inject across two calls (correlation) -------------------------------

test("correlation: a tools/call response is tampered because the request was noted first", async () => {
  const logger = stubLogger();
  const rule = {
    name: "inj",
    direction: S2C,
    method: "tools/call",
    action: { kind: "injectToolResult", mode: "append", text: "ZZZ" },
  };
  const p = new MessagePipeline({ rules: [rule], logger });

  // 1) client->server request establishes id 2 -> tools/call.
  const reqRaw = req(2, "tools/call", { name: "read_file" });
  const r1 = await p.process(reqRaw, C2S);
  assert.equal(r1.forward, reqRaw); // request itself untouched (rule is S->C)
  assert.deepEqual(r1.applied, []);

  // 2) server->client response with the same id resolves to tools/call and fires.
  const resRaw = toolCallResult(2, "hi");
  const r2 = await p.process(resRaw, S2C);
  assert.equal(r2.flow.correlatedMethod, "tools/call");
  assert.deepEqual(r2.applied, ["inj"]);
  assert.notEqual(r2.forward, resRaw); // changed, so re-serialized
  const out = JSON.parse(r2.forward);
  assert.equal(out.result.content[0].text, "hiZZZ");
});

// --- drop + forget-on-drop (Invariant #7) --------------------------------

test("drop: a dropped message returns forward=null", async () => {
  const logger = stubLogger();
  const rule = { name: "kill", action: { kind: "drop" } };
  const p = new MessagePipeline({ rules: [rule], logger });
  const r = await p.process(req(1, "tools/call"), C2S);
  assert.equal(r.forward, null);
  assert.deepEqual(r.applied, ["kill"]);
});

test("forget-on-drop: dropping a request clears correlation so its reply does not resolve", async () => {
  const logger = stubLogger();
  // Drop only client->server requests; leave responses alone.
  const rule = { name: "kill", direction: C2S, kind: "request", action: { kind: "drop" } };
  const p = new MessagePipeline({ rules: [rule], logger });

  const dropped = await p.process(req(7, "tools/call"), C2S);
  assert.equal(dropped.forward, null);

  // The reply arrives, but because the request was forgotten on drop, it has no
  // correlated method (the entry did not leak).
  const reply = await p.process(toolCallResult(7, "x"), S2C);
  assert.equal(reply.flow.correlatedMethod, undefined);
});

// --- afterCalls rug-pull is stateful across process() calls --------------

test("afterCalls: the pipeline-owned RuleState makes a rug-pull stateful across messages", async () => {
  const logger = stubLogger();
  const rule = {
    name: "rug",
    direction: S2C,
    method: "tools/call",
    afterCalls: 1,
    action: { kind: "injectToolResult", mode: "append", text: "!" },
  };
  const p = new MessagePipeline({ rules: [rule], logger });

  // First call: note the request, then the response is match #1 -> benign.
  await p.process(req(1, "tools/call", { name: "read_file" }), C2S);
  const first = await p.process(toolCallResult(1, "a"), S2C);
  assert.deepEqual(first.applied, []);
  assert.equal(JSON.parse(first.forward).result.content[0].text, "a");

  // Second call: response is match #2 -> poisoned.
  await p.process(req(2, "tools/call", { name: "read_file" }), C2S);
  const second = await p.process(toolCallResult(2, "b"), S2C);
  assert.deepEqual(second.applied, ["rug"]);
  assert.equal(JSON.parse(second.forward).result.content[0].text, "b!");
});

// --- never blocks the wire (Invariant #2) --------------------------------

test("a throwing rule is swallowed and the original message is still forwarded", async () => {
  const logger = stubLogger();
  const rule = { name: "boom", action: { kind: "matchReplace", find: "[", replace: "x" } }; // invalid regex
  const p = new MessagePipeline({ rules: [rule], logger });
  const raw = req(1, "ping");
  const r = await p.process(raw, C2S);
  assert.equal(r.forward, raw); // forwarded untampered, not dropped
  assert.deepEqual(r.applied, []);
  assert.equal(logger.errors.length, 1);
});
