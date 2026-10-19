import test from "node:test";
import assert from "node:assert/strict";
import { parseArgs, ArgError } from "../dist/cli.js";

test("parses the command and its args after --", () => {
  const p = parseArgs(["--", "npx", "-y", "@some/server"]);
  assert.equal(p.command, "npx");
  assert.deepEqual(p.commandArgs, ["-y", "@some/server"]);
});

test("parses options then the command, including repeatable -r", () => {
  const p = parseArgs(["-v", "-r", "a.json", "-r", "b.json", "-l", "log.jsonl", "--", "node", "s.js"]);
  assert.equal(p.verbose, true);
  assert.deepEqual(p.ruleFiles, ["a.json", "b.json"]);
  assert.equal(p.logFile, "log.jsonl");
  assert.equal(p.command, "node");
  assert.deepEqual(p.commandArgs, ["s.js"]);
});

test("treats the first bare non-flag as the command start (no -- needed)", () => {
  const p = parseArgs(["npx", "-y", "foo"]);
  assert.equal(p.command, "npx");
  assert.deepEqual(p.commandArgs, ["-y", "foo"]);
});

test("-i enables intercept", () => {
  const p = parseArgs(["-i", "--", "x"]);
  assert.equal(p.intercept, true);
});

test("-h/--help and --version are recognized", () => {
  assert.equal(parseArgs(["-h"]), "help");
  assert.equal(parseArgs(["--help"]), "help");
  assert.equal(parseArgs(["--version"]), "version");
});

test("-r as the last token errors instead of pushing undefined", () => {
  assert.throws(() => parseArgs(["-r"]), ArgError);
  assert.throws(() => parseArgs(["-v", "--rule"]), ArgError);
});

test("-l as the last token errors instead of setting undefined", () => {
  assert.throws(() => parseArgs(["-l"]), ArgError);
  assert.throws(() => parseArgs(["--log"]), ArgError);
});

test("unknown --flags are rejected, not treated as the command", () => {
  assert.throws(() => parseArgs(["--bogus", "--", "node"]), ArgError);
  assert.throws(() => parseArgs(["-x"]), ArgError);
});

test("a valid -r value is still consumed correctly before the command", () => {
  const p = parseArgs(["-r", "rules.json", "node", "server.js"]);
  assert.deepEqual(p.ruleFiles, ["rules.json"]);
  assert.equal(p.command, "node");
  assert.deepEqual(p.commandArgs, ["server.js"]);
});
