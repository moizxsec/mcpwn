import test from "node:test";
import assert from "node:assert/strict";
import { MessagePipeline } from "../dist/core/pipeline.js";
import { Logger, formatSessionSummary } from "../dist/logger.js";

// The proxy prints a compact end-of-session tally on exit (§3.6). The counters
// live in the pipeline (fed by the same traffic it already processes); the
// formatter turns them + the findings into stderr lines. Both are pure/testable
// and NEVER touch the MCP stdout channel.

function stubLogger() {
  return { message: () => {}, error: () => {}, info: () => {}, banner: () => {} };
}

const C2S = "client->server";
const S2C = "server->client";
const req = (id, method, params = {}) => JSON.stringify({ jsonrpc: "2.0", id, method, params });
const toolResult = (id, text) =>
  JSON.stringify({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });

test("pipeline.summary() counts messages, tampered, dropped and tools seen", async () => {
  const rule = {
    name: "inj",
    direction: S2C,
    method: "tools/call",
    action: { kind: "injectToolResult", mode: "append", text: "ZZZ" },
  };
  const p = new MessagePipeline({ rules: [rule], logger: stubLogger() });

  await p.process(req(1, "initialize"), C2S);
  await p.process(toolResult(1, "ok"), S2C); // response, not tools/call -> untouched
  await p.process(req(2, "tools/call", { name: "read_file" }), C2S); // tool seen
  await p.process(toolResult(2, "hi"), S2C); // tampered (correlates to tools/call)
  await p.process(req(3, "tools/call", { name: "send_email" }), C2S); // another tool

  const s = p.summary();
  assert.equal(s.messages, 5);
  assert.equal(s.tampered, 1, "only the injected tools/call result was tampered");
  assert.equal(s.dropped, 0);
  assert.deepEqual(s.tools, ["read_file", "send_email"]); // sorted, de-duped
});

test("pipeline.summary() counts drops as tampered + dropped", async () => {
  const rule = { name: "kill", direction: C2S, kind: "request", action: { kind: "drop" } };
  const p = new MessagePipeline({ rules: [rule], logger: stubLogger() });
  await p.process(req(1, "tools/call", { name: "x" }), C2S); // dropped
  const s = p.summary();
  assert.equal(s.messages, 1);
  assert.equal(s.dropped, 1);
  assert.equal(s.tampered, 1, "a drop counts as tampered");
  assert.deepEqual(s.tools, ["x"]);
});

test("idle pipeline: everything forwarded, nothing tampered", async () => {
  const p = new MessagePipeline({ rules: [], logger: stubLogger() });
  await p.process(req(1, "ping"), C2S);
  await p.process("not json {", S2C); // opaque relay still counts as a message
  const s = p.summary();
  assert.equal(s.messages, 2);
  assert.equal(s.tampered, 0);
  assert.equal(s.dropped, 0);
  assert.deepEqual(s.tools, []);
});

test("formatSessionSummary renders the tally + findings-by-severity", () => {
  const summary = { messages: 12, tampered: 3, dropped: 1, tools: ["read_file", "send_email"] };
  const findings = [
    { id: "secret-exposure", title: "x", severity: "high" },
    { id: "tool-poisoning", title: "y", severity: "medium" },
    { id: "secret-exposure", title: "z", severity: "high" },
  ];
  const lines = formatSessionSummary(summary, findings);
  const text = lines.join("\n");
  assert.match(text, /mcpwn session summary/);
  assert.match(text, /messages: 12 total - tampered=3 dropped=1/);
  assert.match(text, /tools:\s+read_file, send_email/);
  assert.match(text, /findings: 3 total - critical=0 high=2 medium=1 low=0 info=0/);
});

test("formatSessionSummary handles the empty session gracefully", () => {
  const lines = formatSessionSummary({ messages: 0, tampered: 0, dropped: 0, tools: [] }, []);
  const text = lines.join("\n");
  assert.match(text, /tools:\s+\(none\)/);
  assert.match(text, /findings: 0 total/);
});

test("Logger.sessionSummary writes only to stderr (never stdout)", () => {
  const origErr = process.stderr.write.bind(process.stderr);
  const origOut = process.stdout.write.bind(process.stdout);
  let err = "";
  let out = "";
  process.stderr.write = (s) => {
    err += s;
    return true;
  };
  process.stdout.write = (s) => {
    out += s;
    return true;
  };
  try {
    new Logger().sessionSummary(
      { messages: 2, tampered: 1, dropped: 0, tools: ["t"] },
      [{ id: "a", title: "a", severity: "low" }]
    );
  } finally {
    process.stderr.write = origErr;
    process.stdout.write = origOut;
  }
  assert.match(err, /mcpwn session summary/);
  assert.match(err, /messages: 2 total/);
  assert.equal(out, "", "the MCP stdout channel must stay untouched");
});
