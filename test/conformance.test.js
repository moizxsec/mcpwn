import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

// End-to-end for the MCP spec conformance checker: spawn a real
// `mcpwn conformance` process against (a) a compliant example server, which must
// pass with a clean exit, and (b) a deliberately non-compliant fixture, where the
// matching checks FAIL and the process exits nonzero. The checker must exit on
// its own (killing the spawned target); a hang trips the test timeout.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const compliant = join(root, "examples", "dvmcp", "tool-poisoning.mjs");
const noncompliant = join(root, "test-fixtures", "noncompliant-server.mjs");

const SKIP_E2E =
  process.platform === "win32" ? "conformance spawn e2e is not run on Windows CI" : false;

/** Run `mcpwn conformance -- node <server>`, capturing exit code + stdout. */
function runConformanceCli(server) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [cli, "conformance", "--", process.execPath, server],
      { stdio: ["ignore", "pipe", "ignore"] }
    );
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("conformance timed out (possible hang)"));
    }, 30000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout });
    });
  });
}

test(
  "conformance: a compliant server passes every check and exits 0",
  { skip: SKIP_E2E },
  async () => {
    const { code, stdout } = await runConformanceCli(compliant);
    assert.match(stdout, /\[PASS\] initialize:/, "initialize check should pass");
    assert.match(stdout, /\[PASS\] ping:/, "ping should be answered");
    assert.match(stdout, /\[PASS\] unknown-method:/, "unknown method should return -32601");
    assert.match(stdout, /\[PASS\] stdout-clean:/, "no non-JSON-RPC output on stdout");
    assert.doesNotMatch(stdout, /\[FAIL\]/, "a compliant server has no FAIL checks");
    assert.equal(code, 0, "compliant server → clean exit 0");
  }
);

test(
  "conformance: a non-compliant fixture FAILs the matching checks and exits nonzero",
  { skip: SKIP_E2E },
  async () => {
    const { code, stdout } = await runConformanceCli(noncompliant);
    // The fixture answers ping + handshake correctly (proving the checker works),
    // but prints a non-JSON banner to stdout and returns the wrong unknown-method
    // code — both must be flagged FAIL.
    assert.match(stdout, /\[PASS\] ping:/, "fixture still answers ping");
    assert.match(stdout, /\[FAIL\] stdout-clean:/, "non-JSON stdout line must FAIL");
    assert.match(stdout, /\[FAIL\] unknown-method:/, "wrong error code must FAIL");
    assert.equal(code, 1, "any FAIL → nonzero exit");
  }
);
