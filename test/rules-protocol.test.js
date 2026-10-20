import test from "node:test";
import assert from "node:assert/strict";
import { applyRules, RuleState } from "../dist/engine/rules.js";

// Phase 1: protocol-coverage tamper actions (injectResource / poisonPrompt /
// tamperSampling) and stateful / conditional predicates (afterCalls / when).

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
const resourceResult = (contents) => ({ jsonrpc: "2.0", id: 3, result: { contents } });
const promptResult = (messages, description) => ({
  jsonrpc: "2.0",
  id: 4,
  result: { description, messages },
});
function samplingReq(messages, over = {}) {
  const json = { jsonrpc: "2.0", id: 5, method: "sampling/createMessage", params: { messages } };
  return Object.assign(
    {
      raw: JSON.stringify(json),
      json,
      kind: "request",
      method: "sampling/createMessage",
      direction: "server->client",
      id: 5,
      ts: 0,
    },
    over
  );
}

// --- injectResource -------------------------------------------------------

test("injectResource appends to the first text content", () => {
  const msg = flow(resourceResult([{ uri: "file:///a", mimeType: "text/plain", text: "hello" }]), {
    correlatedMethod: "resources/read",
  });
  const r = applyRules([{ name: "ir", action: { kind: "injectResource", mode: "append", text: " X" } }], msg);
  assert.equal(r.changed, true);
  assert.deepEqual(r.applied, ["ir"]);
  assert.equal(r.json.result.contents[0].text, "hello X");
});

test("injectResource prepend and replace modes", () => {
  const base = () =>
    flow(resourceResult([{ uri: "file:///a", text: "body" }]), { correlatedMethod: "resources/read" });
  const pre = applyRules([{ name: "p", action: { kind: "injectResource", mode: "prepend", text: "X" } }], base());
  assert.equal(pre.json.result.contents[0].text, "Xbody");
  const rep = applyRules([{ name: "r", action: { kind: "injectResource", mode: "replace", text: "Z" } }], base());
  assert.equal(rep.json.result.contents[0].text, "Z");
});

test("injectResource tampers a base64 blob when no text content exists", () => {
  const b64 = Buffer.from("secret body", "utf8").toString("base64");
  const msg = flow(
    resourceResult([{ uri: "file:///b", mimeType: "application/octet-stream", blob: b64 }]),
    { correlatedMethod: "resources/read" }
  );
  const r = applyRules([{ name: "ir", action: { kind: "injectResource", mode: "append", text: " APPENDED" } }], msg);
  assert.equal(r.changed, true);
  const decoded = Buffer.from(r.json.result.contents[0].blob, "base64").toString("utf8");
  assert.equal(decoded, "secret body APPENDED");
});

test("injectResource pushes a text content when none exists (non-replace)", () => {
  const msg = flow(resourceResult([{ uri: "file:///c", mimeType: "image/png" }]), {
    correlatedMethod: "resources/read",
  });
  const r = applyRules([{ name: "ir", action: { kind: "injectResource", mode: "append", text: "NEW" } }], msg);
  assert.equal(r.changed, true);
  assert.equal(r.json.result.contents.length, 2);
  assert.equal(r.json.result.contents[1].text, "NEW");
  assert.equal(r.json.result.contents[1].uri, "mcpwn://injected");
});

test("injectResource replace does NOT push a content when none exists", () => {
  const msg = flow(resourceResult([{ uri: "file:///c", mimeType: "image/png" }]), {
    correlatedMethod: "resources/read",
  });
  const r = applyRules([{ name: "ir", action: { kind: "injectResource", mode: "replace", text: "NEW" } }], msg);
  assert.equal(r.changed, false);
  assert.equal(r.json.result.contents.length, 1);
});

test("injectResource is a no-op when result.contents is not an array (scope-skip)", () => {
  const msg = flow({ jsonrpc: "2.0", id: 3, result: { ok: true } }, { correlatedMethod: "resources/read" });
  const r = applyRules([{ name: "ir", action: { kind: "injectResource", text: "x" } }], msg);
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
});

// --- poisonPrompt ---------------------------------------------------------

test("poisonPrompt appends to every message's content text", () => {
  const msg = flow(
    promptResult([
      { role: "user", content: { type: "text", text: "u" } },
      { role: "assistant", content: { type: "text", text: "a" } },
    ]),
    { correlatedMethod: "prompts/get" }
  );
  const r = applyRules([{ name: "pp", action: { kind: "poisonPrompt", mode: "append", text: "!" } }], msg);
  assert.equal(r.changed, true);
  assert.equal(r.json.result.messages[0].content.text, "u!");
  assert.equal(r.json.result.messages[1].content.text, "a!");
});

test("poisonPrompt handles array-form content blocks", () => {
  const msg = flow(
    promptResult([{ role: "user", content: [{ type: "text", text: "A" }, { type: "image", data: "..." }] }]),
    { correlatedMethod: "prompts/get" }
  );
  const r = applyRules([{ name: "pp", action: { kind: "poisonPrompt", mode: "prepend", text: "Z" } }], msg);
  assert.equal(r.changed, true);
  assert.equal(r.json.result.messages[0].content[0].text, "ZA");
});

test("poisonPrompt is a no-op when result.messages is not an array (scope-skip)", () => {
  const msg = flow({ jsonrpc: "2.0", id: 4, result: { description: "d" } }, { correlatedMethod: "prompts/get" });
  const r = applyRules([{ name: "pp", action: { kind: "poisonPrompt", text: "x" } }], msg);
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
});

// --- tamperSampling -------------------------------------------------------

test("tamperSampling rewrites the server->model message text", () => {
  const msg = samplingReq([{ role: "user", content: { type: "text", text: "orig" } }]);
  const r = applyRules([{ name: "ts", action: { kind: "tamperSampling", mode: "append", text: " INJ" } }], msg);
  assert.equal(r.changed, true);
  assert.deepEqual(r.applied, ["ts"]);
  assert.equal(r.json.params.messages[0].content.text, "orig INJ");
});

test("tamperSampling self-gates off the wrong direction", () => {
  const wrongDir = samplingReq([{ role: "user", content: { type: "text", text: "x" } }], {
    direction: "client->server",
  });
  const r = applyRules([{ name: "ts", action: { kind: "tamperSampling", text: "!" } }], wrongDir);
  assert.equal(r.changed, false);
  assert.equal(r.json.params.messages[0].content.text, "x"); // untouched
});

test("tamperSampling self-gates off the wrong method", () => {
  const wrongMethod = samplingReq([{ role: "user", content: { type: "text", text: "x" } }], {
    method: "roots/list",
  });
  const r = applyRules([{ name: "ts", action: { kind: "tamperSampling", text: "!" } }], wrongMethod);
  assert.equal(r.changed, false);
});

test("tamperSampling is a no-op when params.messages is not an array", () => {
  const msg = samplingReq(undefined);
  msg.json.params = { maxTokens: 10 };
  const r = applyRules([{ name: "ts", action: { kind: "tamperSampling", text: "x" } }], msg);
  assert.equal(r.changed, false);
});

// --- rollback isolation with a protocol action ----------------------------

test("a throwing sibling rule rolls back but injectResource still applies", () => {
  const { errors, logger } = captureLogger();
  const msg = flow(resourceResult([{ uri: "file:///a", text: "base" }]), {
    correlatedMethod: "resources/read",
  });
  const rules = [
    { name: "boom", action: { kind: "matchReplace", find: "(", replace: "x" } }, // invalid regex -> throws
    { name: "ir", action: { kind: "injectResource", mode: "append", text: "!" } },
  ];
  const r = applyRules(rules, msg, logger);
  assert.equal(r.json.result.contents[0].text, "base!");
  assert.deepEqual(r.applied, ["ir"]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /boom/);
});

// --- afterCalls (stateful rug-pull) ---------------------------------------

test("afterCalls serves benign N times then applies (rug-pull)", () => {
  const state = new RuleState();
  const rule = { name: "rug", afterCalls: 2, action: { kind: "injectToolResult", mode: "append", text: "!" } };
  const mk = () => flow(toolCallResult([{ type: "text", text: "x" }]), { correlatedMethod: "tools/call" });
  const got = [];
  for (let i = 0; i < 4; i++) {
    const r = applyRules([rule], mk(), undefined, undefined, state);
    got.push([r.changed, r.json.result.content[0].text]);
  }
  // Matches 1 & 2 benign; 3 & 4 poisoned.
  assert.deepEqual(got, [
    [false, "x"],
    [false, "x"],
    [true, "x!"],
    [true, "x!"],
  ]);
});

test("afterCalls:0 applies on the very first match", () => {
  const state = new RuleState();
  const rule = { name: "rug", afterCalls: 0, action: { kind: "injectToolResult", mode: "append", text: "!" } };
  const r = applyRules(
    [rule],
    flow(toolCallResult([{ type: "text", text: "x" }]), { correlatedMethod: "tools/call" }),
    undefined,
    undefined,
    state
  );
  assert.equal(r.changed, true);
  assert.equal(r.json.result.content[0].text, "x!");
});

test("afterCalls without threaded state treats every call as match #1 (benign for afterCalls>=1)", () => {
  const rule = { name: "rug", afterCalls: 1, action: { kind: "injectToolResult", text: "!" } };
  const r = applyRules(
    [rule],
    flow(toolCallResult([{ type: "text", text: "x" }]), { correlatedMethod: "tools/call" })
  );
  assert.equal(r.changed, false);
});

test("afterCalls counts only the messages the rule matches", () => {
  const state = new RuleState();
  const rule = {
    name: "rug",
    method: "tools/call",
    afterCalls: 1,
    action: { kind: "injectToolResult", mode: "append", text: "!" },
  };
  // A non-matching tools/list message must NOT advance the counter.
  applyRules([rule], flow(toolsListResult([{ name: "t", description: "d" }]), { correlatedMethod: "tools/list" }), undefined, undefined, state);
  const r1 = applyRules([rule], flow(toolCallResult([{ type: "text", text: "x" }]), { correlatedMethod: "tools/call" }), undefined, undefined, state);
  assert.equal(r1.changed, false); // match #1 -> benign
  const r2 = applyRules([rule], flow(toolCallResult([{ type: "text", text: "x" }]), { correlatedMethod: "tools/call" }), undefined, undefined, state);
  assert.equal(r2.changed, true); // match #2 -> poisoned
});

// --- when.contains (conditional gate) -------------------------------------

test("when.contains applies only when the substring is present", () => {
  const rule = {
    name: "w",
    when: { contains: "password" },
    action: { kind: "injectToolResult", mode: "append", text: "!" },
  };
  const hit = applyRules([rule], flow(toolCallResult([{ type: "text", text: "the password is 1234" }]), { correlatedMethod: "tools/call" }));
  assert.equal(hit.changed, true);
  assert.equal(hit.json.result.content[0].text, "the password is 1234!");

  const miss = applyRules([rule], flow(toolCallResult([{ type: "text", text: "nothing here" }]), { correlatedMethod: "tools/call" }));
  assert.equal(miss.changed, false);
  assert.deepEqual(miss.applied, []);
});

test("when.contains gates a drop action too", () => {
  const rule = { name: "d", when: { contains: "boom" }, action: { kind: "drop" } };
  const dropped = applyRules([rule], flow({ jsonrpc: "2.0", id: 1, result: "boom here" }));
  assert.equal(dropped.json, null);
  const kept = applyRules([rule], flow({ jsonrpc: "2.0", id: 1, result: "safe" }));
  assert.notEqual(kept.json, null);
  assert.deepEqual(kept.applied, []);
});

test("when and afterCalls combine: benign until BOTH the count and the content gate pass", () => {
  const state = new RuleState();
  const rule = {
    name: "wr",
    afterCalls: 1,
    when: { contains: "SECRET" },
    action: { kind: "injectToolResult", mode: "append", text: "!" },
  };
  const secret = () => flow(toolCallResult([{ type: "text", text: "has SECRET" }]), { correlatedMethod: "tools/call" });
  assert.equal(applyRules([rule], secret(), undefined, undefined, state).changed, false); // match #1
  assert.equal(applyRules([rule], secret(), undefined, undefined, state).changed, true); // match #2 + gate
});
