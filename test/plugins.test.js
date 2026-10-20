import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadDetectorPlugin,
  loadRuleActionPlugin,
  buildActionRegistry,
} from "../dist/plugins/index.js";
import { applyRules } from "../dist/engine/rules.js";
import { validateRuleFile } from "../dist/engine/validate.js";
import { ArrayFindingsSink } from "../dist/findings.js";
import { MessagePipeline } from "../dist/core/pipeline.js";

// Plugin loading (§3.11). Loads fixture detector + rule-action plugins from
// test-fixtures/ and proves: they fire / tamper; a throwing plugin is isolated
// (never crashes the pipeline or the rules engine); a bogus/invalid plugin
// errors cleanly; and a registered custom kind passes validation.

const here = fileURLToPath(new URL(".", import.meta.url));
const fx = (f) => join(here, "..", "test-fixtures", f);

const S2C = "server->client";
function s2cFlow(json, method) {
  return {
    raw: JSON.stringify(json),
    json,
    kind: json.error ? "error" : "response",
    id: json.id,
    direction: S2C,
    method,
    correlatedMethod: method,
    ts: 1,
  };
}

// A no-op logger so the pipeline / engine stay quiet and we can assert on errors.
function fakeLogger() {
  const errors = [];
  return { errors, message() {}, error(t) { errors.push(t); }, info() {} };
}

// --- detector plugins ------------------------------------------------------

test("loadDetectorPlugin loads a named-export detector that fires on its marker", async () => {
  const d = await loadDetectorPlugin(fx("detector-fixture.mjs"));
  assert.equal(d.name, "fixture-detector");
  const sink = new ArrayFindingsSink();
  const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "x FIXTURE_MARKER y" }] } };
  d.inspect(s2cFlow(json, "tools/call"), sink);
  assert.equal(sink.all().length, 1);
  assert.equal(sink.all()[0].id, "fixture-finding");
});

test("loadDetectorPlugin accepts a default export using a visit() method", async () => {
  const d = await loadDetectorPlugin(fx("detector-visit.mjs"));
  assert.equal(d.name, "fixture-visitor");
  const sink = new ArrayFindingsSink();
  d.inspect(s2cFlow({ jsonrpc: "2.0", id: 1, result: {} }, "tools/list"), sink);
  assert.equal(sink.all()[0].id, "visit-finding");
});

test("a throwing detector plugin is isolated: the pipeline still forwards and other detectors fire", async () => {
  const bad = await loadDetectorPlugin(fx("throwing-detector.mjs"));
  const good = await loadDetectorPlugin(fx("detector-fixture.mjs"));
  const findings = new ArrayFindingsSink();
  const logger = fakeLogger();
  const pipeline = new MessagePipeline({ rules: [], logger, detectors: [bad, good], findings });

  const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "FIXTURE_MARKER" }] } };
  const line = JSON.stringify(json);
  const result = await pipeline.process(line, S2C);

  // No rules → forwarded byte-for-byte, the throwing detector never blocked it.
  assert.equal(result.forward, line);
  // The good detector still recorded its finding despite the throwing one.
  assert.ok(findings.all().some((f) => f.id === "fixture-finding"));
  // The throw was logged, not swallowed into the void.
  assert.ok(logger.errors.some((e) => /detector threw/.test(e)));
});

test("loadDetectorPlugin rejects a module that is not a detector", async () => {
  await assert.rejects(loadDetectorPlugin(fx("not-a-detector.mjs")), /inspect\(flow, sink\) or visit/);
});

test("loadDetectorPlugin rejects a bogus path cleanly", async () => {
  await assert.rejects(loadDetectorPlugin(fx("does-not-exist.mjs")), /could not load plugin/);
});

// --- rule-action plugins ---------------------------------------------------

test("a --rule-plugin kind is applied via applyRules and tampers (deep-clone safe)", async () => {
  const plugin = await loadRuleActionPlugin(fx("rule-plugin-fixture.mjs"));
  assert.equal(plugin.kind, "fixtureUppercase");
  const registry = buildActionRegistry([plugin]);

  const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "hello" }] } };
  const msg = s2cFlow(json, "tools/call");
  const rules = [
    { name: "up", direction: S2C, method: "tools/call", action: { kind: "fixtureUppercase" } },
  ];
  const res = applyRules(rules, msg, undefined, undefined, undefined, registry);

  assert.deepEqual(res.applied, ["up"]);
  assert.equal(res.changed, true);
  assert.equal(res.json.result.content[0].text, "HELLO");
  // The raw record is never mutated in place.
  assert.equal(msg.json.result.content[0].text, "hello");
});

test("a throwing rule-plugin rolls back; the message is forwarded untampered", async () => {
  const plugin = await loadRuleActionPlugin(fx("throwing-rule-plugin.mjs"));
  const registry = buildActionRegistry([plugin]);
  const logger = fakeLogger();

  const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "hello" }] } };
  const msg = s2cFlow(json, "tools/call");
  const rules = [
    { name: "boom", direction: S2C, method: "tools/call", action: { kind: "fixtureThrow" } },
  ];
  const res = applyRules(rules, msg, logger, undefined, undefined, registry);

  assert.deepEqual(res.applied, []);
  assert.equal(res.changed, false);
  assert.equal(res.json.result.content[0].text, "hello");
  assert.ok(logger.errors.some((e) => /rule plugin boom/.test(e)));
});

test("an unknown action kind with no plugin registered still fails loud (rolled back)", () => {
  const logger = fakeLogger();
  const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "hi" }] } };
  const msg = s2cFlow(json, "tools/call");
  const rules = [{ name: "x", direction: S2C, method: "tools/call", action: { kind: "noSuchKind" } }];
  const res = applyRules(rules, msg, logger); // no registry
  assert.deepEqual(res.applied, []);
  assert.ok(logger.errors.some((e) => /unknown action kind: noSuchKind/.test(e)));
});

test("loadRuleActionPlugin rejects a bogus path cleanly", async () => {
  await assert.rejects(loadRuleActionPlugin(fx("does-not-exist.mjs")), /could not load plugin/);
});

// --- validation of registered kinds ---------------------------------------

test("validateRuleFile accepts a registered plugin kind but still rejects unknown kinds", () => {
  const rule = { name: "a", action: { kind: "fixtureUppercase", anything: true } };
  // Registered: accepted, extra fields allowed (the plugin owns its schema).
  assert.equal(validateRuleFile({ rules: [rule] }, { actionKinds: ["fixtureUppercase"] }).ok, true);
  // Not registered: still an error.
  const r = validateRuleFile({ rules: [rule] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /unknown kind "fixtureUppercase"/.test(e)));
});
