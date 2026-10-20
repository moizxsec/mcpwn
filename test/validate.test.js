import test from "node:test";
import assert from "node:assert/strict";
import { validateRuleFile } from "../dist/engine/validate.js";

// One test per error class, plus a happy path. Each asserts ok=false and that
// the message is specific enough to point the operator at the exact problem.

const firstError = (data) => {
  const r = validateRuleFile(data);
  assert.equal(r.ok, false);
  return r.errors[0];
};

test("happy path: a well-formed rule file validates and returns the rules", () => {
  const data = {
    rules: [
      { name: "a", direction: "server->client", method: "tools/call", action: { kind: "injectToolResult", text: "x", mode: "append" } },
      { name: "b", action: { kind: "drop" } },
      { name: "c", action: { kind: "matchReplace", find: "a", replace: "b", flags: "g" } },
      { name: "d", action: { kind: "poisonDescription", tool: "t", text: "y" } },
    ],
  };
  const r = validateRuleFile(data);
  assert.equal(r.ok, true);
  assert.equal(r.rules.length, 4);
});

test("extra top-level keys (e.g. _comment) are ignored", () => {
  const data = { _comment: "notes", rules: [{ name: "a", action: { kind: "drop" } }] };
  assert.equal(validateRuleFile(data).ok, true);
});

test("non-object root is rejected", () => {
  assert.match(firstError([]), /must be a JSON object/);
  assert.match(firstError("nope"), /must be a JSON object/);
});

test("missing rules array is rejected", () => {
  assert.match(firstError({}), /missing required "rules"/);
});

test("rules that is not an array is rejected", () => {
  assert.match(firstError({ rules: {} }), /"rules" must be an array/);
});

test("rule missing name is rejected", () => {
  assert.match(firstError({ rules: [{ action: { kind: "drop" } }] }), /rules\[0\]: missing required "name"/);
});

test("rule name of the wrong type is rejected", () => {
  assert.match(firstError({ rules: [{ name: 7, action: { kind: "drop" } }] }), /rules\[0\]\.name: must be a string/);
});

test("rule missing action is rejected", () => {
  assert.match(firstError({ rules: [{ name: "a" }] }), /rules\[0\]: missing required "action"/);
});

test("unknown action kind yields a nearest-key suggestion", () => {
  const e = firstError({ rules: [{ name: "a", action: { kind: "injectToolResults", text: "x" } }] });
  assert.match(e, /unknown kind "injectToolResults" \(did you mean "injectToolResult"\?\)/);
});

test("action missing a required field is rejected", () => {
  assert.match(firstError({ rules: [{ name: "a", action: { kind: "matchReplace", find: "x" } }] }), /action: missing required "replace"/);
});

test("wrong-typed/invalid direction enum is rejected", () => {
  const e = firstError({ rules: [{ name: "a", direction: "up", action: { kind: "drop" } }] });
  assert.match(e, /direction: must be one of "client->server", "server->client"/);
});

test("invalid message-kind enum is rejected", () => {
  assert.match(firstError({ rules: [{ name: "a", kind: "reqest", action: { kind: "drop" } }] }), /\.kind: must be one of/);
});

test("invalid action mode enum is rejected", () => {
  assert.match(firstError({ rules: [{ name: "a", action: { kind: "injectToolResult", text: "x", mode: "overwrite" } }] }), /action\.mode: must be one of/);
});

test("typo'd rule-level field yields a suggestion", () => {
  assert.match(firstError({ rules: [{ name: "a", methd: "x", action: { kind: "drop" } }] }), /unknown field "methd" \(did you mean "method"\?\)/);
});

test("typo'd action-level field yields a kind-scoped suggestion", () => {
  assert.match(firstError({ rules: [{ name: "a", action: { kind: "injectToolResult", text: "x", mde: "append" } }] }), /unknown field "mde" for kind "injectToolResult" \(did you mean "mode"\?\)/);
});

test("all errors are collected, not just the first", () => {
  const r = validateRuleFile({ rules: [{ action: { kind: "nope" } }, { name: 9, action: {} }] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.length >= 3, `expected multiple errors, got ${r.errors.length}`);
});

// --- argument-tampering action kinds (§3.2) -------------------------------

test("setArg: valid rule with any-typed value validates", () => {
  const r = validateRuleFile({
    rules: [{ name: "a", action: { kind: "setArg", path: "a.b", value: { any: ["json", 1, null] } } }],
  });
  assert.equal(r.ok, true);
});

test("setArg: missing required value (present-but-any) is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "setArg", path: "a" } }] }),
    /action: missing required "value"/
  );
});

test("rewriteArgs: args must be an object", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "rewriteArgs", args: ["not", "obj"] } }] }),
    /action\.args: must be an object \(got array\)/
  );
});

test("rewriteArgs: invalid mode enum is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "rewriteArgs", args: {}, mode: "overwrite" } }] }),
    /action\.mode: must be one of "replace", "merge"/
  );
});

test("fuzzArgs: payload-library name (string) and inline array both validate", () => {
  assert.equal(
    validateRuleFile({ rules: [{ name: "a", action: { kind: "fuzzArgs", path: "p", payloads: "sqli" } }] }).ok,
    true
  );
  assert.equal(
    validateRuleFile({ rules: [{ name: "b", action: { kind: "fuzzArgs", path: "p", payloads: ["x", "y"] } }] }).ok,
    true
  );
});

test("fuzzArgs: payloads of a wrong type is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "fuzzArgs", path: "p", payloads: 123 } }] }),
    /action\.payloads: must be a string .* or an array of strings/
  );
});

test("fuzzArgs: missing payloads is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "fuzzArgs", path: "p" } }] }),
    /action: missing required "payloads"/
  );
});

test("enabled of the wrong type is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", enabled: "yes", action: { kind: "drop" } }] }),
    /\.enabled: must be a boolean/
  );
});

// --- protocol-coverage action kinds (Phase 1) -----------------------------

test("injectResource / poisonPrompt / tamperSampling validate with text + mode", () => {
  for (const kind of ["injectResource", "poisonPrompt", "tamperSampling"]) {
    const r = validateRuleFile({
      rules: [{ name: "a", action: { kind, text: "x", mode: "append" } }],
    });
    assert.equal(r.ok, true, `${kind} should validate`);
  }
});

test("injectResource missing required text is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "injectResource" } }] }),
    /action: missing required "text"/
  );
});

test("poisonPrompt rejects the tool field (not allowed for this kind)", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "poisonPrompt", text: "x", tool: "t" } }] }),
    /unknown field "tool" for kind "poisonPrompt"/
  );
});

test("tamperSampling invalid mode enum is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", action: { kind: "tamperSampling", text: "x", mode: "overwrite" } }] }),
    /action\.mode: must be one of/
  );
});

// --- stateful / conditional predicates (Phase 1) --------------------------

test("afterCalls: a non-negative integer validates", () => {
  assert.equal(
    validateRuleFile({ rules: [{ name: "a", afterCalls: 3, action: { kind: "drop" } }] }).ok,
    true
  );
});

test("afterCalls of the wrong type is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", afterCalls: "soon", action: { kind: "drop" } }] }),
    /\.afterCalls: must be a non-negative integer/
  );
});

test("afterCalls that is negative or fractional is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", afterCalls: -1, action: { kind: "drop" } }] }),
    /\.afterCalls: must be a non-negative integer/
  );
  assert.match(
    firstError({ rules: [{ name: "a", afterCalls: 1.5, action: { kind: "drop" } }] }),
    /\.afterCalls: must be a non-negative integer/
  );
});

test("when.contains validates and a non-string is rejected", () => {
  assert.equal(
    validateRuleFile({ rules: [{ name: "a", when: { contains: "pw" }, action: { kind: "drop" } }] }).ok,
    true
  );
  assert.match(
    firstError({ rules: [{ name: "a", when: { contains: 7 }, action: { kind: "drop" } }] }),
    /\.when\.contains: must be a string/
  );
});

test("when that is not an object is rejected", () => {
  assert.match(
    firstError({ rules: [{ name: "a", when: "pw", action: { kind: "drop" } }] }),
    /\.when: must be an object/
  );
});

test("unknown field inside when yields a suggestion", () => {
  assert.match(
    firstError({ rules: [{ name: "a", when: { contain: "pw" }, action: { kind: "drop" } }] }),
    /\.when: unknown field "contain" \(did you mean "contains"\?\)/
  );
});
