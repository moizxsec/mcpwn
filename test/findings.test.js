import test from "node:test";
import assert from "node:assert/strict";
import {
  ArrayFindingsSink,
  writeJson,
  writeMarkdown,
  writeSarif,
  sarifLevel,
  fingerprint,
  FINGERPRINT_KEY,
} from "../dist/findings.js";

const sample = [
  { id: "secret-exposure", title: "AWS key in result", severity: "high", method: "tools/call", evidence: "«redacted:aws-access-key»", ts: 1000 },
  { id: "tool-poisoning", title: "Poisoned description", severity: "medium", method: "tools/list", tool: "read_file", evidence: "ignore previous instructions", ts: 1001 },
  { id: "secret-exposure", title: "Second key leak", severity: "critical", method: "tools/call", ts: 1002 },
  { id: "dangerous-tool", title: "exec tool", severity: "info", tool: "exec_shell", ts: 1003 },
];

test("findings JSON round-trips exactly", () => {
  const sink = new ArrayFindingsSink();
  for (const f of sample) sink.add(f);
  const parsed = JSON.parse(writeJson(sink.all()));
  assert.deepEqual(parsed, sample);
});

test("ArrayFindingsSink preserves insertion order", () => {
  const sink = new ArrayFindingsSink();
  sink.add(sample[0]);
  sink.add(sample[1]);
  assert.equal(sink.all().length, 2);
  assert.equal(sink.all()[0].id, "secret-exposure");
  assert.equal(sink.all()[1].id, "tool-poisoning");
});

test("sarifLevel maps severities per spec", () => {
  assert.equal(sarifLevel("critical"), "error");
  assert.equal(sarifLevel("high"), "error");
  assert.equal(sarifLevel("medium"), "warning");
  assert.equal(sarifLevel("low"), "note");
  assert.equal(sarifLevel("info"), "note");
});

test("SARIF emits one rule per distinct id and maps result levels", () => {
  const sarif = JSON.parse(writeSarif(sample));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];

  // Rule dedupe: 3 distinct ids (secret-exposure, tool-poisoning, dangerous-tool).
  const rules = run.tool.driver.rules;
  const ids = rules.map((r) => r.id).sort();
  assert.deepEqual(ids, ["dangerous-tool", "secret-exposure", "tool-poisoning"]);

  // One result per finding (4), with mapped levels in order.
  assert.equal(run.results.length, 4);
  assert.deepEqual(
    run.results.map((r) => r.level),
    ["error", "warning", "error", "note"]
  );

  // logicalLocations carry method/tool.
  const poison = run.results[1];
  const names = poison.logicalLocations.map((l) => l.name);
  assert.ok(names.includes("tools/list"));
  assert.ok(names.includes("read_file"));
});

test("SARIF results carry a stable partialFingerprint on every result", () => {
  const sarif = JSON.parse(writeSarif(sample));
  const results = sarif.runs[0].results;
  assert.equal(results.length, 4);
  for (const r of results) {
    const fp = r.partialFingerprints?.[FINGERPRINT_KEY];
    assert.ok(fp, "every result must carry a partialFingerprint");
    assert.match(fp, /^[0-9a-f]{64}$/, "fingerprint is a sha256 hex digest");
  }
});

test("SARIF fingerprints are identical across two runs of identical input", () => {
  const a = JSON.parse(writeSarif(sample)).runs[0].results.map(
    (r) => r.partialFingerprints[FINGERPRINT_KEY]
  );
  const b = JSON.parse(writeSarif(sample)).runs[0].results.map(
    (r) => r.partialFingerprints[FINGERPRINT_KEY]
  );
  assert.deepEqual(a, b, "same findings -> same fingerprints (no CI alert churn)");
});

test("fingerprint keys on id+method+tool+evidence, differing when those differ", () => {
  const base = { id: "x", title: "t", severity: "high", method: "tools/call", tool: "a", evidence: "e" };
  const same = { ...base, title: "DIFFERENT TITLE", severity: "low" }; // non-keyed fields
  assert.equal(fingerprint(base), fingerprint(same), "title/severity do not affect the fingerprint");
  assert.notEqual(fingerprint(base), fingerprint({ ...base, evidence: "other" }));
  assert.notEqual(fingerprint(base), fingerprint({ ...base, tool: "b" }));
  assert.notEqual(fingerprint(base), fingerprint({ ...base, method: "tools/list" }));
  assert.notEqual(fingerprint(base), fingerprint({ ...base, id: "y" }));
});

test("Markdown includes title, severity and evidence", () => {
  const md = writeMarkdown(sample);
  assert.match(md, /# mcpwn findings/);
  assert.match(md, /## AWS key in result/); // title as heading
  assert.match(md, /\*\*Severity:\*\* high/); // severity line
  assert.match(md, /«redacted:aws-access-key»/); // evidence block
  assert.match(md, /### Evidence/);
});

test("SARIF rules carry additive CWE/CVSS metadata (code-scanning conventions)", () => {
  const sarif = JSON.parse(writeSarif(sample));
  const rules = sarif.runs[0].tool.driver.rules;
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));

  // secret-exposure is a mapped id -> CWE-200 + CVSS properties present.
  const sec = byId["secret-exposure"].properties;
  assert.ok(sec, "mapped rule carries properties");
  assert.equal(sec.cwe, "CWE-200");
  assert.match(sec["security-severity"], /^\d+\.\d$/, "GitHub security-severity is a numeric string");
  assert.match(sec.cvssVector, /^CVSS:3\.1\//);
  assert.ok(sec.tags.includes("external/cwe/cwe-200"), "carries the external/cwe tag");

  // tool-poisoning -> CWE-1427.
  assert.equal(byId["tool-poisoning"].properties.cwe, "CWE-1427");
});

test("empty findings still produce valid outputs", () => {
  assert.deepEqual(JSON.parse(writeJson([])), []);
  assert.match(writeMarkdown([]), /No findings recorded/);
  const sarif = JSON.parse(writeSarif([]));
  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});
