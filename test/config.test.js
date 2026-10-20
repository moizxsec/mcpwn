import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  validateConfig,
  loadConfig,
  ConfigError,
  resolveConfigPath,
  findDefaultConfig,
  preScanConfigFlags,
  DEFAULT_CONFIG_FILENAME,
} from "../dist/config.js";
import { parseArgs, parseHttpArgs, sharedFromConfig } from "../dist/cli.js";
import { parseScanArgs } from "../dist/core/scan.js";

function withTempConfig(contents) {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-cfg-"));
  const path = join(dir, DEFAULT_CONFIG_FILENAME);
  writeFileSync(path, typeof contents === "string" ? contents : JSON.stringify(contents));
  return { dir, path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// --- validation -------------------------------------------------------------

test("validateConfig accepts a full, well-formed config", () => {
  const cfg = {
    rules: ["a.json", "b.json"],
    templates: ["tool-poisoning"],
    scope: { methods: ["tools/*"], tools: ["read_file"], direction: "s2c" },
    redact: true,
    redactFile: "patterns.txt",
    findingsOut: "./out",
    failOn: "medium",
    log: "session.jsonl",
    verbose: true,
  };
  assert.deepEqual(validateConfig(cfg), cfg);
});

test("validateConfig ignores a $schema hint", () => {
  const out = validateConfig({ $schema: "./schema/config.schema.json", redact: true });
  assert.deepEqual(out, { redact: true });
});

test("validateConfig rejects unknown top-level + scope keys", () => {
  assert.throws(() => validateConfig({ bogus: 1 }), ConfigError);
  assert.throws(() => validateConfig({ scope: { nope: 1 } }), ConfigError);
});

test("validateConfig type-checks each field", () => {
  assert.throws(() => validateConfig({ rules: "a.json" }), ConfigError); // not array
  assert.throws(() => validateConfig({ rules: [1, 2] }), ConfigError); // not strings
  assert.throws(() => validateConfig({ redact: "yes" }), ConfigError); // not boolean
  assert.throws(() => validateConfig({ failOn: "catastrophic" }), ConfigError); // bad enum
  assert.throws(() => validateConfig({ scope: { direction: "both" } }), ConfigError);
  assert.throws(() => validateConfig([]), ConfigError); // not an object
});

// --- loadConfig -------------------------------------------------------------

test("loadConfig reads + validates a file", () => {
  const t = withTempConfig({ rules: ["x.json"], failOn: "low" });
  try {
    assert.deepEqual(loadConfig(t.path), { rules: ["x.json"], failOn: "low" });
  } finally {
    t.cleanup();
  }
});

test("loadConfig throws ConfigError on missing file + bad JSON", () => {
  assert.throws(() => loadConfig("/no/such/mcpwn.config.json"), ConfigError);
  const t = withTempConfig("{ not json ");
  try {
    assert.throws(() => loadConfig(t.path), ConfigError);
  } finally {
    t.cleanup();
  }
});

// --- discovery / precedence of the file itself ------------------------------

test("findDefaultConfig finds ./mcpwn.config.json only when present", () => {
  const t = withTempConfig({ redact: true });
  try {
    assert.equal(findDefaultConfig(t.dir), t.path);
    assert.equal(findDefaultConfig(mkdtempSync(join(tmpdir(), "empty-"))), undefined);
  } finally {
    t.cleanup();
  }
});

test("resolveConfigPath: explicit wins, --no-auto-config opts out, auto is flagged", () => {
  const t = withTempConfig({ redact: true });
  try {
    assert.deepEqual(resolveConfigPath({ explicit: t.path }), { path: t.path, auto: false });
    assert.equal(resolveConfigPath({ noAuto: true, cwd: t.dir }), undefined);
    assert.deepEqual(resolveConfigPath({ cwd: t.dir }), { path: t.path, auto: true });
  } finally {
    t.cleanup();
  }
});

test("preScanConfigFlags extracts --config / --no-auto-config and stops at --", () => {
  assert.deepEqual(preScanConfigFlags(["--config", "c.json", "--", "node", "s.js"]), {
    configFile: "c.json",
    noAuto: false,
  });
  assert.deepEqual(preScanConfigFlags(["--no-auto-config", "node"]), {
    configFile: undefined,
    noAuto: true,
  });
  // A --config AFTER -- belongs to the server, not mcpwn.
  assert.deepEqual(preScanConfigFlags(["--", "node", "--config", "x"]), {
    configFile: undefined,
    noAuto: false,
  });
});

// --- seeding SharedArgs -----------------------------------------------------

test("sharedFromConfig maps config onto SharedArgs defaults", () => {
  const s = sharedFromConfig({
    rules: ["a.json"],
    templates: ["t1"],
    scope: { methods: ["tools/*"], tools: ["read_file"], direction: "c2s" },
    redact: true,
    redactFile: "p.txt",
    findingsOut: "./out",
    log: "s.jsonl",
    verbose: true,
  });
  assert.deepEqual(s.ruleFiles, ["a.json"]);
  assert.deepEqual(s.templateIds, ["t1"]);
  assert.deepEqual(s.scopeMethods, ["tools/*"]);
  assert.deepEqual(s.scopeTools, ["read_file"]);
  assert.equal(s.scopeDirection, "client->server");
  assert.equal(s.redact, true);
  assert.equal(s.redactFile, "p.txt");
  assert.equal(s.findingsOut, "./out");
  assert.equal(s.logFile, "s.jsonl");
  assert.equal(s.verbose, true);
});

test("sharedFromConfig(undefined) is the empty default", () => {
  const s = sharedFromConfig(undefined);
  assert.deepEqual(s.ruleFiles, []);
  assert.equal(s.findingsOut, undefined);
  assert.equal(s.verbose, false);
});

// --- precedence: defaults < config < CLI flags ------------------------------

test("CLI flags override config; list flags append to the config's list", () => {
  const seed = sharedFromConfig({
    rules: ["from-config.json"],
    scope: { direction: "s2c" },
    findingsOut: "./config-out",
  });
  const p = parseArgs(
    ["-r", "from-flag.json", "--scope-direction", "c2s", "--findings-out", "./flag-out", "--", "node", "s.js"],
    seed
  );
  // rules: config's rule is kept, the CLI rule is appended (both apply).
  assert.deepEqual(p.ruleFiles, ["from-config.json", "from-flag.json"]);
  // scalars: the CLI value overrides the config value.
  assert.equal(p.scopeDirection, "client->server");
  assert.equal(p.findingsOut, "./flag-out");
  assert.equal(p.command, "node");
});

test("config seeds values that no flag overrides", () => {
  const seed = sharedFromConfig({ findingsOut: "./out", verbose: true, redact: true });
  const p = parseArgs(["--", "node", "s.js"], seed);
  assert.equal(p.findingsOut, "./out");
  assert.equal(p.verbose, true);
  assert.equal(p.redact, true);
});

test("--config and --no-auto-config are consumed, not treated as the command", () => {
  const p = parseArgs(["--config", "c.json", "--no-auto-config", "--", "node", "s.js"]);
  assert.equal(p.command, "node");
  assert.deepEqual(p.commandArgs, ["s.js"]);
});

test("parseArgs with no seed is backward-compatible (empty defaults)", () => {
  const p = parseArgs(["--", "node", "s.js"]);
  assert.deepEqual(p.ruleFiles, []);
  assert.equal(p.findingsOut, undefined);
});

test("scan honors config (failOn/findingsOut/scope); CLI flags override", () => {
  const t = withTempConfig({
    failOn: "low",
    findingsOut: "./cfg-out",
    scope: { tools: ["t1"] },
  });
  try {
    const a = parseScanArgs([
      "--config",
      t.path,
      "--fail-on",
      "critical",
      "--scope-tool",
      "t2",
      "--",
      "node",
      "s.js",
    ]);
    assert.equal(a.failOn, "critical"); // CLI overrides config
    assert.equal(a.findingsOut, "./cfg-out"); // config seeds the default
    assert.deepEqual(a.scopeTools, ["t1", "t2"]); // config seeds, CLI appends
    assert.equal(a.command, "node");
  } finally {
    t.cleanup();
  }
});

test("scan rejects an invalid config with a clear error", () => {
  const t = withTempConfig({ failOn: "nope" });
  try {
    assert.throws(() => parseScanArgs(["--config", t.path, "--http", "http://x"]), /failOn/);
  } finally {
    t.cleanup();
  }
});

test("the http parser also accepts a config seed", () => {
  const seed = sharedFromConfig({ rules: ["c.json"], findingsOut: "./out" });
  const h = parseHttpArgs(
    ["--listen", "127.0.0.1:8900", "--upstream", "https://x/mcp", "-r", "f.json"],
    seed
  );
  assert.deepEqual(h.ruleFiles, ["c.json", "f.json"]);
  assert.equal(h.findingsOut, "./out");
  assert.equal(h.upstream, "https://x/mcp");
});
