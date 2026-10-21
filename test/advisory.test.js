import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  advisoryFor,
  ADVISORY_TABLE,
  cvssQualitative,
  renderAdvisory,
  renderAdvisorySet,
  advisorySlug,
  parseAdvisoryArgs,
  AdvisoryArgError,
} from "../dist/advisory.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const cli = join(here, "..", "dist", "cli.js");

// A valid CVSS v3.1 base vector (all eight base metrics, in canonical order).
const CVSS_RE =
  /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/;
const CWE_RE = /^CWE-\d+$/;

// Every finding id emitted by the built-in detectors + the opt-in pin/taint
// detectors + the guard firewall. The mapping MUST cover all of them.
const BUILTIN_IDS = [
  // src/detect/linter.ts (the 8 passive linters)
  "secret-exposure",
  "tool-poisoning",
  "invisible-unicode",
  "embedded-url",
  "tool-shadowing",
  "annotation-mismatch",
  "dangerous-tool",
  "sampling-abuse",
  // src/detect/baseline.ts
  "tool-added",
  "tool-definition-changed",
  "tool-removed",
  // src/detect/pin.ts
  "pin-drift",
  // src/detect/taint.ts
  "provenance-taint",
  // src/guard/guard.ts (guard-<action>)
  "guard-block",
  "guard-sanitize",
  "guard-warn",
];

test("mapping covers every builtin finding id + guard/pin/taint ids", () => {
  for (const id of BUILTIN_IDS) {
    const a = advisoryFor(id);
    assert.ok(a, `no advisory mapping for builtin id "${id}"`);
    assert.match(a.cwe, CWE_RE, `${id}: invalid CWE "${a.cwe}"`);
    assert.match(a.cvssVector, CVSS_RE, `${id}: invalid CVSS vector "${a.cvssVector}"`);
    assert.ok(a.cweName && a.cweName.length > 0, `${id}: missing cweName`);
    assert.ok(a.attackClass && a.attackClass.length > 0, `${id}: missing attackClass`);
    assert.ok(Array.isArray(a.references) && a.references.length > 0, `${id}: no references`);
    assert.ok(a.cvssScore >= 0 && a.cvssScore <= 10, `${id}: score out of range`);
  }
});

test("every table entry has a valid vector/CWE and a consistent qualitative rating", () => {
  for (const [id, a] of Object.entries(ADVISORY_TABLE)) {
    assert.match(a.cvssVector, CVSS_RE, `${id}: vector`);
    assert.match(a.cwe, CWE_RE, `${id}: cwe`);
    assert.equal(
      a.cvssSeverity,
      cvssQualitative(a.cvssScore),
      `${id}: cvssSeverity must match the score band`
    );
  }
});

test("dvmcp/template attack classes resolve to the expected CWEs", () => {
  assert.equal(advisoryFor("path-traversal").cwe, "CWE-22");
  assert.equal(advisoryFor("ssrf").cwe, "CWE-918");
  assert.equal(advisoryFor("command-injection").cwe, "CWE-78");
  assert.equal(advisoryFor("indirect-prompt-injection").cwe, "CWE-74");
  assert.equal(advisoryFor("rug-pull").cwe, "CWE-494");
});

test("cvssQualitative maps score bands per CVSS v3.1", () => {
  assert.equal(cvssQualitative(0), "None");
  assert.equal(cvssQualitative(3.1), "Low");
  assert.equal(cvssQualitative(6.1), "Medium");
  assert.equal(cvssQualitative(8.2), "High");
  assert.equal(cvssQualitative(9.8), "Critical");
});

test("renderAdvisory fills CVSS vector + CWE for a mapped finding", () => {
  const f = {
    id: "tool-poisoning",
    title: "Poisoned description",
    severity: "high",
    method: "tools/list",
    tool: "search",
    evidence: "ignore all previous instructions",
    description: "Instruction-like content in a tool description.",
    remediation: "Treat the server as untrusted.",
    ts: 1000,
  };
  const md = renderAdvisory(f);
  assert.match(md, /# Security advisory -/);
  assert.match(md, /\*\*CVSS v3\.1:\*\* 8\.2 \(High\)/);
  assert.match(md, /CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:R\/S:C\/C:L\/I:H\/A:N/);
  assert.match(md, /CWE-1427/);
  assert.match(md, /## Reproduction with mcpwn/);
  assert.match(md, /mcpwn scan/);
  assert.match(md, /ignore all previous instructions/); // evidence block
  assert.match(md, /## Suggested remediation/);
  assert.match(md, /Treat the server as untrusted\./);
  // The vector embedded in the doc must itself be a valid CVSS v3.1 base vector.
  const vector = md.match(/`(CVSS:3\.1\/[^`]+)`/)[1];
  assert.match(vector, CVSS_RE);
});

test("renderAdvisory degrades gracefully for an unmapped id", () => {
  const f = { id: "custom-detector-xyz", title: "Something custom", severity: "medium" };
  assert.equal(advisoryFor(f.id), undefined, "unknown id has no mapping");
  const md = renderAdvisory(f); // must not throw
  assert.match(md, /# Security advisory - Something custom/);
  assert.match(md, /not mapped for this id/);
  assert.doesNotMatch(md, /CWE-\d+/, "no fabricated CWE for an unmapped id");
});

test("renderAdvisorySet builds a combined doc with a CVSS/CWE summary table", () => {
  const findings = [
    { id: "tool-poisoning", title: "Poison", severity: "high", method: "tools/list", tool: "a" },
    { id: "secret-exposure", title: "Leak", severity: "critical", method: "tools/call" },
    { id: "custom-xyz", title: "Unmapped thing", severity: "low" },
  ];
  const doc = renderAdvisorySet(findings, { generatedAt: 0, source: "./out" });
  assert.match(doc, /# mcpwn security advisories/);
  assert.match(doc, /\| Severity \| ID \| CVSS \| CWE \| Title \|/);
  // Critical is sorted first.
  const critIdx = doc.indexOf("secret-exposure");
  const highIdx = doc.indexOf("tool-poisoning");
  assert.ok(critIdx > -1 && highIdx > -1 && critIdx < highIdx, "sorted most-severe first");
  // Mapped rows show CVSS + CWE; the unmapped row degrades to a dash.
  assert.match(doc, /CWE-200/);
  assert.match(doc, /CWE-1427/);
  assert.match(doc, /\| low \| custom-xyz \| - \| - \|/);
});

test("renderAdvisorySet with no findings is still valid", () => {
  const doc = renderAdvisorySet([], { generatedAt: 0 });
  assert.match(doc, /# mcpwn security advisories/);
  assert.match(doc, /No findings to report/);
});

test("advisorySlug is filesystem-safe and stable", () => {
  const f = { id: "tool-poisoning", title: "x", severity: "high", method: "tools/list", tool: "a" };
  const slug = advisorySlug(f, 0);
  assert.match(slug, /^advisory-01-tool-poisoning-[0-9a-f]{8}\.md$/);
});

test("parseAdvisoryArgs parses path + -o + --session, rejects stray flags", () => {
  const a = parseAdvisoryArgs(["./out", "-o", "advisories", "--session", "s.jsonl"]);
  assert.equal(a.findingsPath, "./out");
  assert.equal(a.out, "advisories");
  assert.equal(a.sessionFile, "s.jsonl");
  assert.throws(() => parseAdvisoryArgs(["--bogus"]), AdvisoryArgError);
  assert.throws(() => parseAdvisoryArgs(["a", "b"]), AdvisoryArgError);
});

// --- CLI end-to-end --------------------------------------------------------

function runAdvisoryCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "advisory", ...extraArgs], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("advisory cli timed out"));
    }, 20000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function writeFindingsDir(dir) {
  mkdirSync(dir, { recursive: true });
  const findings = [
    { id: "tool-poisoning", title: "Poisoned search", severity: "high", method: "tools/list", tool: "search", evidence: "ignore all previous instructions" },
    { id: "secret-exposure", title: "AWS key", severity: "critical", method: "tools/call", evidence: "«redacted»" },
    { id: "mystery-id", title: "Unmapped", severity: "low" },
  ];
  writeFileSync(join(dir, "findings.json"), JSON.stringify(findings));
}

test("CLI: `mcpwn advisory <dir> -o <dir>` writes one advisory per finding", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcpwn-adv-"));
  try {
    const findingsDir = join(tmp, "out");
    writeFindingsDir(findingsDir);
    const advDir = join(tmp, "advisories");
    const { code, stderr } = await runAdvisoryCli([findingsDir, "-o", advDir]);
    assert.equal(code, 0, stderr);
    const files = readdirSync(advDir).filter((f) => f.endsWith(".md"));
    assert.equal(files.length, 3, "one advisory per finding");
    // The mapped findings carry a filled CVSS/CWE; the unmapped one degrades.
    const all = files.map((f) => readFileSync(join(advDir, f), "utf8")).join("\n");
    assert.match(all, /CVSS:3\.1\//);
    assert.match(all, /CWE-1427/);
    assert.match(all, /CWE-200/);
    assert.match(all, /not mapped for this id/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("CLI: `mcpwn advisory <dir> -o <file.md>` writes a combined document", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcpwn-adv-"));
  try {
    const findingsDir = join(tmp, "out");
    writeFindingsDir(findingsDir);
    const outFile = join(tmp, "advisories.md");
    const { code, stderr } = await runAdvisoryCli([findingsDir, "-o", outFile]);
    assert.equal(code, 0, stderr);
    const doc = readFileSync(outFile, "utf8");
    assert.match(doc, /# mcpwn security advisories/);
    assert.match(doc, /\| Severity \| ID \| CVSS \| CWE \| Title \|/);
    assert.match(doc, /CVSS:3\.1\//);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("CLI: writes the combined doc to stdout when -o is omitted", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcpwn-adv-"));
  try {
    const findingsDir = join(tmp, "out");
    writeFindingsDir(findingsDir);
    const { code, stdout } = await runAdvisoryCli([findingsDir]);
    assert.equal(code, 0);
    assert.match(stdout, /# mcpwn security advisories/);
    assert.match(stdout, /CWE-1427/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("CLI: accepts a direct findings.json file too", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mcpwn-adv-"));
  try {
    const findingsDir = join(tmp, "out");
    writeFindingsDir(findingsDir);
    const { code, stdout } = await runAdvisoryCli([join(findingsDir, "findings.json")]);
    assert.equal(code, 0);
    assert.match(stdout, /# mcpwn security advisories/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("CLI: missing findings path fails with a clear error", async () => {
  const { code, stderr } = await runAdvisoryCli([]);
  assert.equal(code, 2);
  assert.match(stderr, /missing <findings-dir\|findings\.json>/);
});

test("CLI: a non-existent findings path fails gracefully", async () => {
  const { code, stderr } = await runAdvisoryCli(["/no/such/path/xyz"]);
  assert.equal(code, 2);
  assert.match(stderr, /findings path not found/);
});
