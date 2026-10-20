import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  renderReport,
  parseSession,
  escapeHtml,
  escapeJsonForScript,
} from "../dist/report.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const cli = join(here, "..", "dist", "cli.js");

// --- attacker-controlled fixture content -----------------------------------
// The whole point: session + finding content IS the traffic under test, so it
// is adversarial. These probes must come out HTML-escaped, never live markup.
const XSS = `<script>alert(1)</script><img src=x onerror=alert(1)>"quoted'`;
const BREAKOUT = `</script><script>alert(2)</script>`;

/** A representative session: handshake (serverInfo), a tampered tools/call
 *  result that injects the XSS payload, an untampered message whose raw content
 *  also carries XSS, and a dropped message. */
function fixtureRecords() {
  const line = (obj) => JSON.stringify(obj);
  const initReq = line({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  const initRes = line({
    jsonrpc: "2.0",
    id: 1,
    result: { serverInfo: { name: "fixture-server", version: "9.9" } },
  });
  // tools/call result: the tampered `forwarded` appends the attacker payload.
  const callRaw = line({
    jsonrpc: "2.0",
    id: 2,
    result: { content: [{ type: "text", text: "benign file body" }] },
  });
  const callFwd = line({
    jsonrpc: "2.0",
    id: 2,
    result: {
      content: [
        { type: "text", text: `benign file body\n\n<INJECTED by mcpwn> ${XSS} ${BREAKOUT} </INJECTED>` },
      ],
    },
  });
  // The client request that named the tool (so the response gets a tool label).
  const callReq = line({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "/tmp/x" } },
  });
  // Untampered server line whose raw already contains XSS (timeline escaping).
  const listRes = line({
    jsonrpc: "2.0",
    id: 3,
    result: { tools: [{ name: "evil", description: XSS }] },
  });
  // A dropped message.
  const dropRaw = line({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "x" } });

  return [
    { ts: 1, direction: "client->server", kind: "request", method: "initialize", id: 1, applied: [], dropped: false, manualEdit: false, raw: initReq, forwarded: initReq },
    { ts: 2, direction: "server->client", kind: "response", method: "initialize", id: 1, applied: [], dropped: false, manualEdit: false, raw: initRes, forwarded: initRes },
    { ts: 3, direction: "client->server", kind: "request", method: "tools/call", id: 2, applied: [], dropped: false, manualEdit: false, raw: callReq, forwarded: callReq },
    { ts: 4, direction: "server->client", kind: "response", method: "tools/call", id: 2, applied: ["inject-tool-result"], dropped: false, manualEdit: false, raw: callRaw, forwarded: callFwd },
    { ts: 5, direction: "server->client", kind: "response", method: "tools/list", id: 3, applied: [], dropped: false, manualEdit: false, raw: listRes, forwarded: listRes },
    { ts: 6, direction: "client->server", kind: "request", method: "tools/call", id: 4, applied: ["drop-rule"], dropped: true, manualEdit: false, raw: dropRaw, forwarded: null },
  ];
}

/** Findings deliberately out of severity order, with XSS in evidence/title. */
function fixtureFindings() {
  return [
    { id: "dangerous-tool", title: "exec tool", severity: "info", tool: "exec_shell", ts: 100 },
    { id: "tool-poisoning", title: "Poisoned description", severity: "high", method: "tools/list", tool: "evil", evidence: XSS, ts: 101 },
    { id: "secret-exposure", title: `AWS key ${XSS}`, severity: "critical", method: "tools/call", evidence: "«redacted:aws-access-key»", ts: 102 },
    { id: "weak-thing", title: "low thing", severity: "low", ts: 103 },
    { id: "secret-exposure", title: "medium leak", severity: "medium", method: "tools/call", ts: 104 },
  ];
}

function render(extra = {}) {
  return renderReport({
    sessionFile: "fixture.jsonl",
    records: fixtureRecords(),
    findings: fixtureFindings(),
    toolVersion: "1.2.3",
    generatedAt: 0,
    ...extra,
  });
}

test("escapeHtml neutralises every markup-significant character", () => {
  assert.equal(escapeHtml(`<a href="x" onclick='y'>&</a>`),
    "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
});

test("escapeJsonForScript prevents </script> breakout", () => {
  const out = escapeJsonForScript(JSON.stringify({ x: "</script><b>" }));
  assert.ok(!out.includes("</script>"), "no raw closing script tag may survive");
  assert.ok(out.includes("\\u003c/script"), "< is unicode-escaped");
});

test("output is a single, well-formed HTML document", () => {
  const html = render();
  assert.ok(html.startsWith("<!DOCTYPE html>"), "has doctype");
  assert.equal((html.match(/<html/g) || []).length, 1, "exactly one <html> root");
  assert.ok(html.trim().endsWith("</html>"), "closes html");
  assert.match(html, /<style>/);
  // Exactly two <script> elements: the embedded JSON blob + the filter JS.
  assert.equal((html.match(/<script/g) || []).length, 2);
  assert.equal((html.match(/<\/script>/g) || []).length, 2);
});

test("header shows tool version, session, counts and severity chips", () => {
  const html = render();
  assert.match(html, /mcpwn <span class="ver">v1\.2\.3<\/span>/);
  assert.match(html, /fixture\.jsonl/);
  assert.match(html, /<b>6<\/b> messages/);
  assert.match(html, /<b>2<\/b> tampered/); // inject-tool-result + drop-rule
  assert.match(html, /chip sev-critical">critical: 1/);
  assert.match(html, /chip sev-high">high: 1/);
});

test("findings are grouped and sorted by severity (critical first)", () => {
  const html = render();
  const order = ["critical", "high", "medium", "low", "info"];
  const idx = order.map((s) => html.indexOf(`data-sev="${s}"`));
  for (let i = 1; i < idx.length; i++) {
    assert.ok(idx[i - 1] !== -1 && idx[i] !== -1, `${order[i]} present`);
    assert.ok(idx[i - 1] < idx[i], `${order[i - 1]} must precede ${order[i]}`);
  }
});

test("severity filter buttons exist and the page is usable without JS", () => {
  const html = render();
  // One filter per severity + "all".
  for (const s of ["all", "critical", "high", "medium", "low", "info"]) {
    assert.match(html, new RegExp(`data-filter="${s}"`));
  }
  // Expand/collapse is native <details> (works JS-disabled); all findings are
  // rendered in the document, not injected by script.
  assert.equal((html.match(/<details class="finding"/g) || []).length, 5);
});

test("tamper diffs render side-by-side with highlighted changed regions", () => {
  const html = render();
  assert.match(html, /Tamper diffs/);
  // The injected result (changed bytes) + the dropped message = 2 diff blocks.
  assert.equal((html.match(/<details class="diff"/g) || []).length, 2);
  assert.match(html, /Original \(received\)/);
  assert.match(html, /Tampered \(forwarded\)/);
  assert.ok((html.match(/<mark class="add">/g) || []).length >= 1, "added region highlighted");
  assert.ok((html.match(/<mark class="del">/g) || []).length >= 1, "removed region highlighted");
  // The INJECTED marker lands inside the highlighted (added) span.
  assert.match(html, /<mark class="add">[\s\S]*INJECTED by mcpwn/);
  // The dropped message is shown as dropped.
  assert.match(html, /was dropped by a rule/);
});

test("session timeline lists every message with direction + correlated tool", () => {
  const html = render();
  assert.match(html, /Session timeline/);
  assert.equal((html.match(/<details class="msg"/g) || []).length, 6);
  assert.match(html, /dir-c2s">C→S/);
  assert.match(html, /dir-s2c">S→C/);
  // The tools/call response is labelled with the tool from its request.
  assert.match(html, /class="tool mono">read_file/);
});

test("attack narrative summarises server, tampering and findings", () => {
  const html = render();
  assert.match(html, /fixture-server v9\.9/);
  assert.match(html, /tampered 2 message\(s\)/);
  assert.match(html, /most severe rated critical/);
});

test("CRITICAL: all attacker content is HTML-escaped — no script execution vector", () => {
  const html = render();
  // The raw XSS payload must never appear as live markup anywhere.
  assert.ok(!html.includes("<script>alert(1)</script>"), "no raw <script> payload");
  assert.ok(!html.includes("<img src=x onerror=alert(1)>"), "no raw onerror <img>");
  assert.ok(!html.includes("<script>alert(2)</script>"), "no breakout <script>");
  // It must appear ESCAPED instead.
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  // Only the two legitimate </script> tags survive; attacker's are escaped
  // (in markup) or unicode-escaped (in the embedded JSON blob).
  assert.equal((html.match(/<\/script>/g) || []).length, 2);
  // The embedded JSON data block does not let the payload break out.
  assert.match(html, /\\u003c\/script/);
});

test("finding cards show additive CWE + CVSS for mapped ids (no URLs)", () => {
  const html = render();
  // tool-poisoning (CWE-1427) + secret-exposure (CWE-200) are in the fixture.
  assert.match(html, /<dt>CWE<\/dt>/);
  assert.match(html, /<dt>CVSS<\/dt>/);
  assert.match(html, /CWE-1427/);
  assert.match(html, /CWE-200/);
  assert.match(html, /CVSS:3\.1\//);
  // The enrichment must not smuggle a reference URL into the self-contained page
  // (covered more strictly by the "no external URL" test below).
  assert.ok(!/https?:\/\//.test(html), "CWE/CVSS enrichment adds no URL");
});

test("self-contained: references no external URL / CDN / font", () => {
  const html = render();
  assert.ok(!/https?:\/\//.test(html), "no absolute http(s) URL anywhere");
  assert.ok(!/<link\b/i.test(html), "no <link> (stylesheet/font)");
  assert.ok(!/@import/.test(html), "no CSS @import");
  assert.ok(!/src=["']?https?:/i.test(html), "no external script/img src");
});

test("parseSession tolerates blank and corrupt lines", () => {
  const recs = fixtureRecords();
  const body = recs.map((r) => JSON.stringify(r)).join("\n") + "\n\nnot-json-garbage\n{bad\n";
  const parsed = parseSession(body);
  assert.equal(parsed.length, recs.length, "garbage lines skipped, good lines kept");
});

test("empty session + no findings still renders a valid report", () => {
  const html = renderReport({
    sessionFile: "empty.jsonl",
    records: [],
    findings: [],
    toolVersion: "0.0.0",
    generatedAt: 0,
  });
  assert.ok(html.startsWith("<!DOCTYPE html>") && html.trim().endsWith("</html>"));
  assert.match(html, /No findings recorded/);
  assert.match(html, /No messages were modified/);
});

// --- CLI end-to-end --------------------------------------------------------

function runReportCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "report", ...extraArgs], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("report cli timed out"));
    }, 20000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test("CLI: `mcpwn report <session> --findings <dir> -o <file>` writes a report", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-report-"));
  try {
    const session = join(dir, "session.jsonl");
    writeFileSync(session, fixtureRecords().map((r) => JSON.stringify(r)).join("\n") + "\n");
    const findingsDir = join(dir, "out");
    mkdirSync(findingsDir, { recursive: true });
    writeFileSync(join(findingsDir, "findings.json"), JSON.stringify(fixtureFindings()));
    const outFile = join(dir, "report.html");

    const { code, stderr } = await runReportCli([session, "--findings", findingsDir, "-o", outFile]);
    assert.equal(code, 0, stderr);
    const html = readFileSync(outFile, "utf8");
    assert.ok(html.startsWith("<!DOCTYPE html>"));
    assert.match(html, /Tamper diffs/);
    assert.ok(!html.includes("<script>alert(1)</script>"), "escaped through the CLI too");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: missing session argument fails with a clear error", async () => {
  const { code, stderr } = await runReportCli([]);
  assert.equal(code, 2);
  assert.match(stderr, /missing <session\.jsonl>/);
});

test("CLI: writes to stdout when -o is omitted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-report-"));
  try {
    const session = join(dir, "session.jsonl");
    writeFileSync(session, fixtureRecords().map((r) => JSON.stringify(r)).join("\n") + "\n");
    const { code, stdout } = await runReportCli([session]);
    assert.equal(code, 0);
    assert.ok(stdout.startsWith("<!DOCTYPE html>"));
    assert.ok(stdout.trim().endsWith("</html>"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
