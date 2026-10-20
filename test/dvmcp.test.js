import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { captureBaseline, loadBaseline, BaselineDetector } from "../dist/detect/baseline.js";

// DVMCP suite (examples/dvmcp): one intentionally-vulnerable MCP server per
// attack class. For each, run the exact scoreboard command (a real `mcpwn scan`
// process, or the baseline-diff workflow) and assert the expected finding fires.
// Every spawned child is bounded by a timeout and always killed; a hang trips
// the node:test timeout. Spawn e2e is skipped on Windows, mirroring the other
// spawn-based suites.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const dvmcp = (file) => join(root, "examples", "dvmcp", file);

const SKIP_E2E =
  process.platform === "win32" ? "dvmcp spawn e2e is not run on Windows CI" : false;

/** Run `mcpwn scan <extraArgs>`, killing the process if it ever hangs. */
function runScanCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "scan", ...extraArgs], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("dvmcp scan timed out (possible hang)"));
    }, 40000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stderr });
    });
  });
}

function readFindings(dir) {
  return JSON.parse(readFileSync(join(dir, "findings.json"), "utf8"));
}

/** Scan one server and return its findings array (temp findings dir cleaned up). */
async function scanFindings(file, { fuzz }) {
  const out = mkdtempSync(join(tmpdir(), "mcpwn-dvmcp-"));
  try {
    const args = [];
    if (fuzz) args.push("--fuzz");
    args.push("--budget", "25000", "--timeout", "5000", "--findings-out", out, "--", process.execPath, dvmcp(file));
    await runScanCli(args);
    return readFindings(out);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

const has = (findings, id, severity) =>
  findings.some((f) => f.id === id && (severity ? f.severity === severity : true));

// --- one test per scan-owned server ----------------------------------------

const SCAN_CASES = [
  {
    name: "path-traversal: --fuzz leaks a planted secret (secret-exposure high)",
    file: "path-traversal.mjs",
    fuzz: true,
    check: (f) => assert.ok(has(f, "secret-exposure", "high"), "expected secret-exposure high"),
  },
  {
    name: "ssrf: --fuzz echoes a metadata URL (embedded-url high)",
    file: "ssrf.mjs",
    fuzz: true,
    check: (f) => assert.ok(has(f, "embedded-url", "high"), "expected embedded-url high"),
  },
  {
    name: "command-injection: dangerous-tool + --fuzz secret leak (secret-exposure high)",
    file: "command-injection.mjs",
    fuzz: true,
    check: (f) => {
      assert.ok(has(f, "dangerous-tool"), "expected dangerous-tool on run_shell");
      assert.ok(has(f, "secret-exposure", "high"), "expected secret-exposure high from injection");
    },
  },
  {
    name: "tool-poisoning: poisoned description (tool-poisoning high)",
    file: "tool-poisoning.mjs",
    fuzz: false,
    check: (f) => assert.ok(has(f, "tool-poisoning", "high"), "expected tool-poisoning high"),
  },
  {
    name: "indirect-injection-via-resource: poisoned resource body (tool-poisoning + embedded-url high)",
    file: "indirect-injection-via-resource.mjs",
    fuzz: false,
    check: (f) => {
      assert.ok(has(f, "tool-poisoning", "high"), "expected tool-poisoning high in resource");
      assert.ok(has(f, "embedded-url", "high"), "expected embedded-url high (oast.live)");
    },
  },
  {
    name: "sampling-abuse: unsolicited sampling request (sampling-abuse + tool-poisoning high)",
    file: "sampling-abuse.mjs",
    fuzz: false,
    check: (f) => {
      assert.ok(has(f, "sampling-abuse"), "expected sampling-abuse");
      assert.ok(has(f, "tool-poisoning", "high"), "expected tool-poisoning high in sampling prompt");
    },
  },
  {
    name: "exfil-url: result embeds a collaborator URL (embedded-url high)",
    file: "exfil-url.mjs",
    fuzz: true,
    check: (f) => assert.ok(has(f, "embedded-url", "high"), "expected embedded-url high"),
  },
];

for (const c of SCAN_CASES) {
  test(`dvmcp scan — ${c.name}`, { skip: SKIP_E2E }, async () => {
    const findings = await scanFindings(c.file, { fuzz: c.fuzz });
    c.check(findings);
  });
}

// --- rug-pull: baseline-diff workflow ---------------------------------------

/** Spawn the rug-pull server (sharing `state`) and return its tools/list reply. */
function captureToolsList(stateFile) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [dvmcp("rug-pull.mjs"), "--state", stateFile], {
      stdio: ["pipe", "pipe", "ignore"],
    });
    let buf = "";
    let phase = "init";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("rug-pull server timed out"));
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
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
          phase = "list";
        } else if (phase === "list" && msg.id === 2) {
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
  "dvmcp baseline — rug-pull: later tools/list drifts from the captured baseline",
  { skip: SKIP_E2E },
  async () => {
    const work = mkdtempSync(join(tmpdir(), "mcpwn-dvmcp-rp-"));
    const state = join(work, "rug.count");
    const base = join(work, "base.json");
    const silent = { info: () => {}, error: () => {} };
    try {
      // 1) Capture the trusted (benign) baseline — the server's first listing.
      const code = await captureBaseline(
        process.execPath,
        [dvmcp("rug-pull.mjs"), "--state", state],
        base,
        silent
      );
      assert.equal(code, 0, "baseline capture should succeed");
      const baseline = loadBaseline(base);
      assert.deepEqual(
        baseline.tools.map((t) => t.name),
        ["search"],
        "baseline should be the benign single-tool set"
      );

      // 2) A later listing is poisoned; diff it against the baseline.
      const resp = await captureToolsList(state);
      assert.deepEqual(
        resp.result.tools.map((t) => t.name),
        ["search", "send_email"],
        "later listing should have rug-pulled in a privileged tool"
      );

      const findings = [];
      new BaselineDetector(baseline).inspect(
        {
          direction: "server->client",
          method: "tools/list",
          correlatedMethod: "tools/list",
          json: resp,
          kind: "response",
          id: 2,
          ts: Date.now(),
        },
        { add: (f) => findings.push(f) }
      );

      assert.ok(
        has(findings, "tool-added", "high"),
        "send_email added after baseline should be tool-added high"
      );
      assert.ok(
        has(findings, "tool-definition-changed", "medium"),
        "poisoned search description should be tool-definition-changed medium"
      );
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
);
