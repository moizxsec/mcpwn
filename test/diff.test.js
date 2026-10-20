import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// End-to-end for the differential record/replay command. We record a golden
// session (via `mcpwn scan --log`, the shipped recorder) against a DVMCP server,
// then: (1) diff vs the SAME server → no drift, exit 0; (2) diff vs a DIFFERENT
// server → drift, nonzero exit; (3) diff a benign golden vs a server that has
// since poisoned a tool description → the new injection surface is reported and
// the exit is nonzero. Each child is killed; a hang trips the test timeout.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const toolPoisoning = join(root, "examples", "dvmcp", "tool-poisoning.mjs");
const rugPull = join(root, "examples", "dvmcp", "rug-pull.mjs");

const SKIP_E2E = process.platform === "win32" ? "diff spawn e2e is not run on Windows CI" : false;

/** Record a golden session by running `mcpwn scan --log` against a server. */
function recordGolden(goldenPath, serverArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [cli, "scan", "--log", goldenPath, "--", process.execPath, ...serverArgs],
      { stdio: ["ignore", "ignore", "ignore"] }
    );
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("golden recording timed out"));
    }, 30000);
    child.on("error", reject);
    child.on("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

/** Run `mcpwn diff <golden> -- node <serverArgs...>`, capturing exit + stdout. */
function runDiffCli(goldenPath, serverArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [cli, "diff", goldenPath, "--", process.execPath, ...serverArgs],
      { stdio: ["ignore", "pipe", "ignore"] }
    );
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("diff timed out (possible hang)"));
    }, 30000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout });
    });
  });
}

test(
  "diff: no drift against the same server → clean exit 0",
  { skip: SKIP_E2E },
  async () => {
    const work = mkdtempSync(join(tmpdir(), "mcpwn-diff-"));
    const golden = join(work, "golden.jsonl");
    try {
      await recordGolden(golden, [toolPoisoning]);
      const { code, stdout } = await runDiffCli(golden, [toolPoisoning]);
      assert.match(stdout, /DRIFT: none/, "identical server should show no drift");
      assert.match(stdout, /NEW INJECTION SURFACES: none/, "no new injection surfaces");
      assert.equal(code, 0, "no drift → exit 0");
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
);

test(
  "diff: a different server drifts → nonzero exit",
  { skip: SKIP_E2E },
  async () => {
    const work = mkdtempSync(join(tmpdir(), "mcpwn-diff-"));
    const golden = join(work, "golden.jsonl");
    const state = join(work, "rug.count");
    try {
      await recordGolden(golden, [toolPoisoning]);
      // rug-pull serves a different tool set + serverInfo than tool-poisoning.
      const { code, stdout } = await runDiffCli(golden, [rugPull, "--reset", "--state", state]);
      assert.match(stdout, /DRIFT \(\d+ change\(s\)\)/, "a different server should drift");
      assert.equal(code, 1, "drift at/above the threshold → nonzero exit");
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
);

test(
  "diff: a newly-poisoned description is reported as a new injection surface",
  { skip: SKIP_E2E },
  async () => {
    const work = mkdtempSync(join(tmpdir(), "mcpwn-diff-"));
    const golden = join(work, "golden.jsonl");
    const state = join(work, "rug.count");
    try {
      // Record the golden from rug-pull's FIRST (benign) listing...
      await recordGolden(golden, [rugPull, "--reset", "--state", state]);
      // ...then diff against the SAME server, whose next listing is poisoned.
      const { code, stdout } = await runDiffCli(golden, [rugPull, "--state", state]);
      assert.match(
        stdout,
        /NEW INJECTION SURFACES \(\d+\)/,
        "a freshly-poisoned description is a new injection surface"
      );
      assert.match(stdout, /tool-poisoning/, "the poisoned description trips tool-poisoning");
      assert.equal(code, 1, "a new high-severity injection surface → nonzero exit");
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
);
