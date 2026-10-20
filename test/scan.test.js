import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// End-to-end for the self-driving scanner: spawn a real `mcpwn scan` process,
// point it at the bundled vulnerable servers (stdio + HTTP), and prove the
// handshake completes, surfaces are enumerated, the passive detectors fire, the
// --fuzz path produces high findings, scope limits active probing, and the exit
// code gates on severity (CI-usable). The process must exit cleanly on its own
// (killing the spawned target); a hang trips the test timeout.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const server = join(root, "examples", "vulnerable-server.mjs");
const httpServer = join(root, "examples", "vulnerable-server-http.mjs");

// The stdio/HTTP spawn e2e is run on POSIX CI; skipped on Windows (no console to
// drive the spawn/teardown). Unit coverage still runs there.
const SKIP_E2E = process.platform === "win32" ? "scan spawn e2e is not run on Windows CI" : false;

/** Run `mcpwn scan <extraArgs>`, capturing the exit code + stderr. stdout is the
 *  empty (scan talks to the target over pipes); the summary + logs go to stderr. */
function runScanCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "scan", ...extraArgs], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("scan timed out (possible hang)"));
    }, 60000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stderr });
    });
  });
}

/** An ephemeral free TCP port on loopback. */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
  });
}

/** Spawn the HTTP vulnerable server on `port`; resolve once it is listening. */
function startHttpServer(port) {
  return new Promise((resolve, reject) => {
    const srv = spawn(process.execPath, [httpServer, "--port", String(port)], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let buf = "";
    const timer = setTimeout(() => {
      srv.kill("SIGKILL");
      reject(new Error("http vulnerable server did not start"));
    }, 10000);
    srv.stderr.on("data", (c) => {
      buf += c.toString("utf8");
      if (buf.includes("listening on")) {
        clearTimeout(timer);
        resolve(srv);
      }
    });
    srv.on("error", reject);
  });
}

function readFindings(dir) {
  return JSON.parse(readFileSync(join(dir, "findings.json"), "utf8"));
}

test(
  "scan (stdio): handshake + enumerates surfaces + passive findings, exits 0 below threshold",
  { skip: SKIP_E2E },
  async () => {
    const out = mkdtempSync(join(tmpdir(), "mcpwn-scan-"));
    try {
      const { code, stderr } = await runScanCli([
        "--findings-out",
        out,
        "--",
        process.execPath,
        server,
      ]);

      // Handshake completed and all three surfaces were enumerated.
      assert.match(stderr, /handshake ok/, "handshake should complete");
      assert.match(stderr, /tools=2 resources=0 prompts=0/, "surfaces should be enumerated");

      // Passive detectors fired on the enumerated tools/list (send_email is a
      // dangerous-tool). No high finding here, so the CI gate leaves exit 0.
      const findings = readFindings(out);
      assert.ok(
        findings.some((f) => f.id === "dangerous-tool" && f.tool === "send_email"),
        "dangerous-tool should fire on send_email"
      );
      assert.equal(code, 0, "no high findings → clean exit 0");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }
);

test(
  "scan --fuzz (stdio): produces high findings and exits nonzero at --fail-on high",
  { skip: SKIP_E2E },
  async () => {
    const out = mkdtempSync(join(tmpdir(), "mcpwn-scan-"));
    try {
      const { code } = await runScanCli([
        "--fuzz",
        "--fail-on",
        "high",
        "--findings-out",
        out,
        "--",
        process.execPath,
        server,
      ]);

      const findings = readFindings(out);
      // Fuzzing read_file echoes the payload back in its ENOENT error; the
      // detectors flag the injection markers / metadata URLs as high.
      assert.ok(
        findings.some((f) => f.severity === "high"),
        "fuzzing should surface at least one high finding"
      );
      assert.equal(code, 1, "a high finding meets --fail-on high → nonzero exit");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }
);

test(
  "scan --fuzz (stdio): --scope-tool limits active probing to the named tool",
  { skip: SKIP_E2E },
  async () => {
    const out = mkdtempSync(join(tmpdir(), "mcpwn-scan-"));
    try {
      const { code, stderr } = await runScanCli([
        "--fuzz",
        "--scope-tool",
        "read_file",
        "--findings-out",
        out,
        "--",
        process.execPath,
        server,
      ]);

      // read_file is still fuzzed (so we still get a high finding + exit 1), but
      // send_email is out of scope and must never be invoked — the vulnerable
      // server prints "send_email CALLED" to stderr whenever it is.
      assert.doesNotMatch(
        stderr,
        /send_email CALLED/,
        "out-of-scope send_email must not be fuzzed"
      );
      assert.ok(readFindings(out).some((f) => f.severity === "high"));
      assert.equal(code, 1);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }
);

test(
  "scan --http: handshake + enumerates surfaces + passive findings over HTTP",
  { skip: SKIP_E2E },
  async () => {
    const out = mkdtempSync(join(tmpdir(), "mcpwn-scan-"));
    const port = await freePort();
    const srv = await startHttpServer(port);
    try {
      const { code, stderr } = await runScanCli([
        "--http",
        `http://127.0.0.1:${port}/mcp`,
        "--findings-out",
        out,
      ]);

      assert.match(stderr, /handshake ok/, "HTTP handshake should complete");
      assert.match(stderr, /tools=3/, "all three tools should be enumerated over HTTP");

      // read_file's poisoned description trips the injection detector (high).
      const findings = readFindings(out);
      assert.ok(
        findings.some((f) => f.id === "tool-poisoning" && f.severity === "high"),
        "injection marker in read_file description should be flagged high"
      );
      assert.equal(code, 1, "a high finding meets the default --fail-on high → nonzero exit");
    } finally {
      srv.kill("SIGKILL");
      rmSync(out, { recursive: true, force: true });
    }
  }
);
