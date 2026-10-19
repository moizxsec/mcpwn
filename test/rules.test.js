import test from "node:test";
import assert from "node:assert/strict";
import { applyRules } from "../dist/engine/rules.js";

// Build a FlowMessage-shaped object around a JSON body.
function flow(json, extra = {}) {
  return Object.assign(
    {
      raw: JSON.stringify(json),
      json,
      kind: "response",
      direction: "server->client",
      id: json && typeof json === "object" ? json.id : undefined,
      ts: 0,
    },
    extra
  );
}

const captureLogger = () => {
  const errors = [];
  return { errors, logger: { error: (s) => errors.push(s) } };
};

const toolCallResult = (content) => ({ jsonrpc: "2.0", id: 2, result: { content } });
const toolsListResult = (tools) => ({ jsonrpc: "2.0", id: 1, result: { tools } });

// --- injectToolResult ----------------------------------------------------

test("injectToolResult appends to the first text block", () => {
  const msg = flow(toolCallResult([{ type: "text", text: "hello" }]), { correlatedMethod: "tools/call" });
  const rule = { name: "inj", action: { kind: "injectToolResult", mode: "append", text: " WORLD" } };
  const r = applyRules([rule], msg);
  assert.equal(r.changed, true);
  assert.deepEqual(r.applied, ["inj"]);
  assert.equal(r.json.result.content[0].text, "hello WORLD");
});

test("injectToolResult prepend and replace modes", () => {
  const base = () => flow(toolCallResult([{ type: "text", text: "body" }]), { correlatedMethod: "tools/call" });
  const pre = applyRules([{ name: "p", action: { kind: "injectToolResult", mode: "prepend", text: "X" } }], base());
  assert.equal(pre.json.result.content[0].text, "Xbody");
  const rep = applyRules([{ name: "r", action: { kind: "injectToolResult", mode: "replace", text: "Z" } }], base());
  assert.equal(rep.json.result.content[0].text, "Z");
});

test("injectToolResult pushes a text block when none exists (non-replace)", () => {
  const msg = flow(toolCallResult([{ type: "image", data: "..." }]), { correlatedMethod: "tools/call" });
  const r = applyRules([{ name: "inj", action: { kind: "injectToolResult", mode: "append", text: "NEW" } }], msg);
  assert.equal(r.changed, true);
  assert.equal(r.json.result.content.length, 2);
  assert.deepEqual(r.json.result.content[1], { type: "text", text: "NEW" });
});

test("injectToolResult replace does NOT push a block when none exists", () => {
  const msg = flow(toolCallResult([{ type: "image", data: "..." }]), { correlatedMethod: "tools/call" });
  const r = applyRules([{ name: "inj", action: { kind: "injectToolResult", mode: "replace", text: "NEW" } }], msg);
  assert.equal(r.changed, false);
  assert.equal(r.json.result.content.length, 1);
});

test("injectToolResult is a no-op when result.content is not an array", () => {
  const msg = flow({ jsonrpc: "2.0", id: 2, result: { ok: true } }, { correlatedMethod: "tools/call" });
  const r = applyRules([{ name: "inj", action: { kind: "injectToolResult", text: "x" } }], msg);
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
});

// --- poisonDescription ---------------------------------------------------

test("poisonDescription targets a single named tool", () => {
  const msg = flow(
    toolsListResult([
      { name: "read_file", description: "reads" },
      { name: "write_file", description: "writes" },
    ]),
    { correlatedMethod: "tools/list" }
  );
  const r = applyRules(
    [{ name: "poison", action: { kind: "poisonDescription", tool: "read_file", mode: "append", text: " X" } }],
    msg
  );
  assert.equal(r.changed, true);
  assert.equal(r.json.result.tools[0].description, "reads X");
  assert.equal(r.json.result.tools[1].description, "writes");
});

test("poisonDescription without a tool filter hits every tool (default desc for missing)", () => {
  const msg = flow(
    toolsListResult([{ name: "a", description: "d" }, { name: "b" }]),
    { correlatedMethod: "tools/list" }
  );
  const r = applyRules([{ name: "poison", action: { kind: "poisonDescription", mode: "append", text: " Y" } }], msg);
  assert.equal(r.json.result.tools[0].description, "d Y");
  assert.equal(r.json.result.tools[1].description, " Y");
});

test("poisonDescription skips null/non-object tool entries without throwing (hardening)", () => {
  const msg = flow(
    toolsListResult([null, { name: "ok", description: "d" }, "weird"]),
    { correlatedMethod: "tools/list" }
  );
  const { errors, logger } = captureLogger();
  let r;
  assert.doesNotThrow(() => {
    r = applyRules([{ name: "poison", action: { kind: "poisonDescription", mode: "append", text: " Z" } }], msg, logger);
  });
  assert.equal(r.changed, true);
  assert.deepEqual(r.applied, ["poison"]);
  assert.equal(r.json.result.tools[0], null); // untouched
  assert.equal(r.json.result.tools[1].description, "d Z");
  assert.equal(errors.length, 0); // handled inline, not via the error path
});

// --- matchReplace --------------------------------------------------------

test("matchReplace rewrites serialized JSON and reparses it", () => {
  const msg = flow({ jsonrpc: "2.0", id: 1, result: "milk milk" });
  const r = applyRules([{ name: "mr", action: { kind: "matchReplace", find: "milk", replace: "oat" } }], msg);
  assert.equal(r.changed, true);
  assert.equal(r.json.result, "oat oat");
});

test("matchReplace refuses a change that reparses to an array (guard, keeps original)", () => {
  const original = { jsonrpc: "2.0", id: 1, result: "x" };
  const msg = flow(original);
  const r = applyRules([{ name: "mr", action: { kind: "matchReplace", find: "^\\{.*\\}$", replace: "[1,2,3]" } }], msg);
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
  assert.deepEqual(r.json, original); // original preserved
});

test("matchReplace refuses a change that reparses to a scalar (guard)", () => {
  const original = { jsonrpc: "2.0", id: 1, result: "x" };
  const r = applyRules([{ name: "mr", action: { kind: "matchReplace", find: "^\\{.*\\}$", replace: "42" } }], flow(original));
  assert.equal(r.changed, false);
  assert.deepEqual(r.json, original);
});

test("matchReplace refuses a change that produces invalid JSON", () => {
  const original = { jsonrpc: "2.0", id: 1, result: "ab" };
  const r = applyRules([{ name: "mr", action: { kind: "matchReplace", find: '"', replace: "" } }], flow(original));
  assert.equal(r.changed, false);
  assert.deepEqual(r.json, original);
});

test("matchReplace is a no-op when the pattern does not match", () => {
  const original = { jsonrpc: "2.0", id: 1, result: "hello" };
  const r = applyRules([{ name: "mr", action: { kind: "matchReplace", find: "zzz", replace: "q" } }], flow(original));
  assert.equal(r.changed, false);
  assert.deepEqual(r.json, original);
});

// --- drop ----------------------------------------------------------------

test("drop returns null json and records the rule", () => {
  const r = applyRules([{ name: "killit", action: { kind: "drop" } }], flow({ jsonrpc: "2.0", id: 1, method: "x" }));
  assert.equal(r.json, null);
  assert.deepEqual(r.applied, ["killit"]);
  assert.equal(r.changed, true);
});

// --- matching ------------------------------------------------------------

test("rules are filtered by enabled/direction/kind/method", () => {
  const msg = flow(toolCallResult([{ type: "text", text: "t" }]), {
    kind: "response",
    direction: "server->client",
    correlatedMethod: "tools/call",
  });
  const mk = (over) => ({ name: "n", action: { kind: "injectToolResult", text: "!" }, ...over });

  assert.equal(applyRules([mk({ enabled: false })], msg).changed, false);
  assert.equal(applyRules([mk({ direction: "client->server" })], msg).changed, false);
  assert.equal(applyRules([mk({ kind: "request" })], msg).changed, false);
  assert.equal(applyRules([mk({ method: "tools/list" })], msg).changed, false);
  // All constraints satisfied -> applies.
  assert.equal(
    applyRules([mk({ direction: "server->client", kind: "response", method: "tools/call" })], msg).changed,
    true
  );
});

// --- throw safety (fix #1) ----------------------------------------------

test("a rule that throws (invalid regex) is logged and forwarded UNtampered, never dropped", () => {
  const original = { jsonrpc: "2.0", id: 1, result: "safe" };
  const msg = flow(original);
  const { errors, logger } = captureLogger();
  let r;
  assert.doesNotThrow(() => {
    // '[' is an invalid regex -> new RegExp throws inside applyAction.
    r = applyRules([{ name: "boom", action: { kind: "matchReplace", find: "[", replace: "x" } }], msg, logger);
  });
  assert.notEqual(r.json, null); // NOT dropped
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
  assert.deepEqual(r.json, original); // message intact (rollback)
  assert.equal(errors.length, 1);
  assert.match(errors[0], /boom/);
});

test("a throwing rule does not block later rules from applying", () => {
  const msg = flow(toolCallResult([{ type: "text", text: "a" }]), { correlatedMethod: "tools/call" });
  const { errors, logger } = captureLogger();
  const rules = [
    { name: "boom", action: { kind: "matchReplace", find: "(", replace: "x" } }, // invalid regex
    { name: "inj", action: { kind: "injectToolResult", mode: "append", text: "B" } },
  ];
  const r = applyRules(rules, msg, logger);
  assert.equal(r.json.result.content[0].text, "aB");
  assert.deepEqual(r.applied, ["inj"]);
  assert.equal(errors.length, 1);
});
