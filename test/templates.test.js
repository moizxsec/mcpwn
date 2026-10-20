import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadTemplate,
  listTemplates,
  findTemplate,
  lintTemplates,
  validateTemplate,
  templatesDir,
} from "../dist/templates/index.js";
import { applyRules } from "../dist/engine/rules.js";
import { builtinLinters } from "../dist/detect/linter.js";
import { ArrayFindingsSink } from "../dist/findings.js";

// Community template gallery (§3.12): every shipped template validates + runs;
// the `templates list|show|lint` CLI works; and a template applied to the real
// vulnerable server's response yields the expected (detectable) finding.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const server = join(root, "examples", "vulnerable-server.mjs");

const SKIP_E2E = process.platform === "win32" ? "server-spawn e2e is not run on Windows CI" : false;

function goodInfo() {
  return {
    name: "n",
    author: "a",
    severity: "high",
    attackClass: "c",
    description: "d",
  };
}

function s2cFlow(json, method) {
  return {
    raw: JSON.stringify(json),
    json,
    kind: json.error ? "error" : "response",
    id: json.id,
    direction: "server->client",
    method,
    correlatedMethod: method,
    ts: Date.now(),
  };
}

function detect(flow) {
  const sink = new ArrayFindingsSink();
  for (const d of builtinLinters()) d.inspect(flow, sink);
  return sink.all();
}

// --- schema / validation ---------------------------------------------------

test("every shipped template validates against the template schema (lint the gallery)", () => {
  const results = lintTemplates(); // bundled templates/ dir
  assert.ok(results.length >= 4, `expected >=4 templates, got ${results.length}`);
  for (const r of results) {
    assert.ok(r.ok, `${r.file} failed: ${r.errors.join("; ")}`);
  }
});

test("listTemplates returns the gallery sorted by id and carries full metadata", () => {
  const items = listTemplates();
  const ids = items.map((t) => t.id);
  for (const want of [
    "tool-poisoning",
    "indirect-injection-via-resource",
    "prompt-poisoning",
    "sampling-abuse",
    "rug-pull-after-calls",
    "exfil-url",
  ]) {
    assert.ok(ids.includes(want), `missing template "${want}"`);
  }
  assert.deepEqual(ids, [...ids].sort(), "ids should be sorted");
  for (const t of items) {
    assert.ok(t.info.name && t.info.author && t.info.attackClass && t.info.description, t.id);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(t.info.severity), t.id);
    assert.ok(Array.isArray(t.rules) && t.rules.length > 0, `${t.id} has no rules`);
  }
});

test("findTemplate resolves by id; unknown returns undefined", () => {
  assert.equal(findTemplate("exfil-url")?.id, "exfil-url");
  assert.equal(findTemplate("does-not-exist"), undefined);
});

test("validateTemplate rejects a missing info block", () => {
  const r = validateTemplate({ id: "x", rules: [{ name: "a", action: { kind: "drop" } }] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /missing required "info"/.test(e)));
});

test("validateTemplate surfaces rule errors under template.rules[...]", () => {
  const r = validateTemplate({
    id: "x",
    info: goodInfo(),
    rules: [{ name: "a", action: { kind: "nope" } }],
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /template\.rules\[0\]/.test(e)), r.errors.join("; "));
});

test("validateTemplate rejects an invalid severity enum", () => {
  const info = { ...goodInfo(), severity: "spicy" };
  const r = validateTemplate({ id: "x", info, rules: [{ name: "a", action: { kind: "drop" } }] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /info\.severity: must be one of/.test(e)));
});

// --- the rules actually load as a rule file ---------------------------------

test("a template loads as a rule file (its extra id/info keys are ignored by the rule loader)", () => {
  // loadTemplate validates the metadata + rules; this proves the rules survive.
  const t = loadTemplate(join(templatesDir(), "tool-poisoning.json"));
  assert.equal(t.rules[0].action.kind, "poisonDescription");
});

// --- template run against the real vulnerable server -> expected finding ----

/** Spawn the vulnerable server, handshake, send one request, resolve its reply. */
function captureResponse(method, params) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [server], { stdio: ["pipe", "pipe", "ignore"] });
    let buf = "";
    let phase = "init";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("vulnerable server timed out"));
    }, 10000);
    const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
    child.stdout.on("data", (c) => {
      buf += c.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (phase === "init" && msg.id === 1) {
          send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
          send({ jsonrpc: "2.0", id: 2, method, params });
          phase = "req";
        } else if (phase === "req" && msg.id === 2) {
          clearTimeout(timer);
          child.kill("SIGTERM");
          resolve(msg);
        }
      }
    });
    child.on("error", reject);
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    });
  });
}

test(
  "exfil-url template, applied to the real server's read_file result, yields a high embedded-url finding",
  { skip: SKIP_E2E },
  async () => {
    const work = mkdtempSync(join(tmpdir(), "mcpwn-tmpl-"));
    const notes = join(work, "notes.txt");
    writeFileSync(notes, "synthetic test content line one\n");
    try {
      const resp = await captureResponse("tools/call", { name: "read_file", arguments: { path: notes } });
      // A genuine server result carrying the file's contents.
      assert.match(JSON.stringify(resp), /synthetic test content/);

      const t = loadTemplate(join(templatesDir(), "exfil-url.json"));
      const { json: tampered, applied } = applyRules(t.rules, s2cFlow(resp, "tools/call"));
      assert.deepEqual(applied, ["inject-exfil-url"]);
      assert.match(JSON.stringify(tampered), /oast\.live/, "exfil URL should be injected");

      const findings = detect(s2cFlow(tampered, "tools/call"));
      assert.ok(
        findings.some((f) => f.id === "embedded-url" && f.severity === "high"),
        "injected collaborator URL should be flagged high"
      );
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
);

test(
  "tool-poisoning template, applied to the real server's tools/list, yields a high tool-poisoning finding",
  { skip: SKIP_E2E },
  async () => {
    const resp = await captureResponse("tools/list", {});
    assert.match(JSON.stringify(resp), /read_file/, "real tools/list should enumerate read_file");

    const t = loadTemplate(join(templatesDir(), "tool-poisoning.json"));
    const { json: tampered, applied } = applyRules(t.rules, s2cFlow(resp, "tools/list"));
    assert.ok(applied.length > 0, "poison rule should fire");

    const findings = detect(s2cFlow(tampered, "tools/list"));
    assert.ok(
      findings.some((f) => f.id === "tool-poisoning" && f.severity === "high"),
      "injected instruction text should be flagged as tool-poisoning"
    );
  }
);

// --- CLI surface ------------------------------------------------------------

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("templates CLI: list, show <id>, show <unknown>, lint", { skip: SKIP_E2E }, async () => {
  const list = await runCli(["templates", "list"]);
  assert.equal(list.code, 0);
  assert.match(list.stdout, /tool-poisoning/);
  assert.match(list.stdout, /ATTACK CLASS/);

  const show = await runCli(["templates", "show", "exfil-url"]);
  assert.equal(show.code, 0);
  assert.match(show.stdout, /data-exfiltration/);
  assert.match(show.stdout, /injectToolResult/);

  const bad = await runCli(["templates", "show", "nope"]);
  assert.equal(bad.code, 2);

  const lint = await runCli(["templates", "lint"]);
  assert.equal(lint.code, 0, lint.stdout + lint.stderr);
  assert.match(lint.stderr, /\d+\/\d+ ok/);
});
