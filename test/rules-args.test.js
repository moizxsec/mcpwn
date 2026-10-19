import test from "node:test";
import assert from "node:assert/strict";
import { applyRules, FuzzState } from "../dist/engine/rules.js";

// Argument tampering (§3.2): setArg / rewriteArgs / fuzzArgs apply ONLY to a
// client->server tools/call. These build the flow shape the pipeline would.

function toolCall(name, args = {}, over = {}) {
  const json = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } };
  return Object.assign(
    { raw: JSON.stringify(json), json, kind: "request", method: "tools/call", direction: "client->server", id: 1, ts: 0 },
    over
  );
}

const captureLogger = () => {
  const errors = [];
  return { errors, logger: { error: (s) => errors.push(s) } };
};

// --- setArg ---------------------------------------------------------------

test("setArg creates a missing argument", () => {
  const msg = toolCall("read_file", {});
  const r = applyRules([{ name: "s", action: { kind: "setArg", path: "path", value: "/etc/passwd" } }], msg);
  assert.equal(r.changed, true);
  assert.deepEqual(r.applied, ["s"]);
  assert.equal(r.json.params.arguments.path, "/etc/passwd");
});

test("setArg overwrites an existing argument (and supports nested paths)", () => {
  const msg = toolCall("read_file", { path: "old", opts: { depth: 1 } });
  const r = applyRules(
    [
      { name: "s1", action: { kind: "setArg", path: "path", value: "new" } },
      { name: "s2", action: { kind: "setArg", path: "opts.depth", value: 9 } },
    ],
    msg
  );
  assert.equal(r.json.params.arguments.path, "new");
  assert.equal(r.json.params.arguments.opts.depth, 9);
  assert.deepEqual(r.applied, ["s1", "s2"]);
});

// --- rewriteArgs ----------------------------------------------------------

test("rewriteArgs replaces the whole arguments object by default", () => {
  const msg = toolCall("send_email", { to: "a@b.c", body: "hi" });
  const r = applyRules([{ name: "rw", action: { kind: "rewriteArgs", args: { to: "x@y.z" } } }], msg);
  assert.equal(r.changed, true);
  assert.deepEqual(r.json.params.arguments, { to: "x@y.z" });
});

test("rewriteArgs merge mode keeps untouched keys", () => {
  const msg = toolCall("send_email", { to: "a@b.c", body: "hi" });
  const r = applyRules([{ name: "rw", action: { kind: "rewriteArgs", mode: "merge", args: { to: "x@y.z" } } }], msg);
  assert.deepEqual(r.json.params.arguments, { to: "x@y.z", body: "hi" });
});

// --- fuzzArgs cursor ------------------------------------------------------

test("fuzzArgs advances a per-rule cursor, one payload per matching call", () => {
  const fuzz = new FuzzState();
  const rule = { name: "fz", action: { kind: "fuzzArgs", path: "path", payloads: ["P0", "P1", "P2"] } };
  const got = [];
  for (let i = 0; i < 4; i++) {
    const r = applyRules([rule], toolCall("read_file", {}), undefined, fuzz);
    got.push(r.json.params.arguments.path);
  }
  // Cycles and wraps: P0, P1, P2, then back to P0.
  assert.deepEqual(got, ["P0", "P1", "P2", "P0"]);
});

test("fuzzArgs can resolve a bundled payload library by name", () => {
  const fuzz = new FuzzState();
  const r = applyRules(
    [{ name: "fz", action: { kind: "fuzzArgs", path: "path", payloads: "path-traversal" } }],
    toolCall("read_file", {}),
    undefined,
    fuzz
  );
  assert.equal(r.changed, true);
  assert.equal(typeof r.json.params.arguments.path, "string");
  assert.ok(r.json.params.arguments.path.length > 0);
});

// --- tool filter ----------------------------------------------------------

test("the tool filter restricts an arg action to one tool by name", () => {
  const msg = toolCall("write_file", { path: "x" });
  const r = applyRules([{ name: "s", action: { kind: "setArg", tool: "read_file", path: "path", value: "y" } }], msg);
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
  assert.equal(r.json.params.arguments.path, "x"); // untouched
});

// --- gating: non-tools/call is untouched ----------------------------------

test("arg actions are a silent no-op outside client->server tools/call", () => {
  // A tools/list request: right direction, wrong method.
  const listReq = toolCall("read_file", {}, { method: "tools/list" });
  const r1 = applyRules([{ name: "s", action: { kind: "setArg", path: "path", value: "z" } }], listReq);
  assert.equal(r1.changed, false);

  // A server->client message with method tools/call (a response): wrong direction.
  const resp = toolCall("read_file", {}, { direction: "server->client", kind: "response" });
  const r2 = applyRules([{ name: "s", action: { kind: "setArg", path: "path", value: "z" } }], resp);
  assert.equal(r2.changed, false);
});

// --- unknown payload library throws -> logged, forwarded untampered --------

test("fuzzArgs with an unknown payload library is logged and forwarded untampered", () => {
  const { errors, logger } = captureLogger();
  const fuzz = new FuzzState();
  const msg = toolCall("read_file", { path: "keep" });
  let r;
  assert.doesNotThrow(() => {
    r = applyRules([{ name: "fz", action: { kind: "fuzzArgs", path: "path", payloads: "no-such-library" } }], msg, logger, fuzz);
  });
  assert.notEqual(r.json, null); // NOT dropped — wire never blocked
  assert.equal(r.changed, false);
  assert.deepEqual(r.applied, []);
  assert.equal(r.json.params.arguments.path, "keep"); // rolled back
  assert.equal(errors.length, 1);
  assert.match(errors[0], /fz/);
  assert.match(errors[0], /no-such-library/);
});
