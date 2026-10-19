import test from "node:test";
import assert from "node:assert/strict";
import { inScope } from "../dist/core/scope.js";

// Build a FlowMessage-shaped object for scope checks.
function flow(over = {}) {
  return Object.assign(
    {
      raw: "",
      json: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read_file" } },
      kind: "request",
      method: "tools/call",
      direction: "client->server",
      id: 1,
      ts: 0,
    },
    over
  );
}

test("no scope means everything is in scope (transparent)", () => {
  assert.equal(inScope(undefined, flow()), true);
});

// --- method globs ---------------------------------------------------------

test("method globs match with * and ?", () => {
  const f = flow({ method: "tools/call" });
  assert.equal(inScope({ methods: ["tools/*"] }, f), true);
  assert.equal(inScope({ methods: ["tools/call"] }, f), true);
  assert.equal(inScope({ methods: ["tools/ca??"] }, f), true);
  assert.equal(inScope({ methods: ["resources/*"] }, f), false);
  assert.equal(inScope({ methods: ["resources/*", "tools/*"] }, f), true); // any match
});

test("method glob matches the correlated method for responses (no method on wire)", () => {
  const resp = flow({ method: undefined, correlatedMethod: "tools/call", kind: "response", direction: "server->client" });
  assert.equal(inScope({ methods: ["tools/call"] }, resp), true);
});

// --- tool names -----------------------------------------------------------

test("tool filter matches params.name; unknown/absent tool is out of scope", () => {
  assert.equal(inScope({ tools: ["read_file"] }, flow()), true);
  assert.equal(inScope({ tools: ["write_file"] }, flow()), false);
  // A message without params.name cannot satisfy a tool filter.
  const noName = flow({ json: { jsonrpc: "2.0", id: 1, method: "ping" }, method: "ping" });
  assert.equal(inScope({ tools: ["read_file"] }, noName), false);
});

// --- direction ------------------------------------------------------------

test("direction narrows to a single direction", () => {
  assert.equal(inScope({ direction: "client->server" }, flow()), true);
  assert.equal(inScope({ direction: "server->client" }, flow()), false);
});

// --- onlyTampered ---------------------------------------------------------

test("onlyTampered requires a non-empty applied list", () => {
  assert.equal(inScope({ onlyTampered: true }, flow(), ["r1"]), true);
  assert.equal(inScope({ onlyTampered: true }, flow(), []), false);
  assert.equal(inScope({ onlyTampered: true }, flow()), false); // applied omitted
  // Without onlyTampered, applied is irrelevant.
  assert.equal(inScope({ methods: ["tools/*"] }, flow(), []), true);
});

// --- combined -------------------------------------------------------------

test("all specified criteria must hold together", () => {
  const scope = { methods: ["tools/*"], tools: ["read_file"], direction: "client->server" };
  assert.equal(inScope(scope, flow()), true);
  assert.equal(inScope(scope, flow({ direction: "server->client" })), false);
  assert.equal(inScope(scope, flow({ json: { method: "tools/call", params: { name: "other" } } })), false);
});
