import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// End-to-end: act as the MCP host, speak stdio through a real mcpwn process
// wrapping the bundled vulnerable server, and prove (a) the injected marker
// reaches the host in the forwarded tools/call result and (b) the JSONL log
// records raw != forwarded with the firing rule in `applied`.

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const server = join(root, "examples", "vulnerable-server.mjs");
const ruleFile = join(root, "examples", "attack-inject.json");

const MARKER = "<INJECTED by mcpwn>";

// This full stdio-spawn e2e (host → mcpwn → real server over real pipes) is run
// on the POSIX CI runners; it is skipped on Windows, where the spawn/teardown
// e2e has no real controlling console to drive it (unit tests still run there).
const SKIP_E2E = process.platform === "win32" ? "stdio-spawn e2e is not run on Windows CI" : false;

test(
  "integration: injects into the forwarded tools/call result and logs raw != forwarded",
  { skip: SKIP_E2E },
  async () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-it-"));
  const notesPath = join(work, "notes.txt");
  const logPath = join(work, "session.jsonl");
  // Synthetic, non-sensitive content — this is a test fixture, not real data.
  writeFileSync(notesPath, "synthetic test content line one\nline two\n");

  // stdio[2]='ignore' discards the banner + the child server's stderr so the
  // test output stays clean; stdin/stdout are the MCP channel we drive.
  const child = spawn(
    process.execPath,
    [cli, "-r", ruleFile, "-l", logPath, "--", process.execPath, server],
    { stdio: ["pipe", "pipe", "ignore"] }
  );

  const pending = new Map();
  let nextId = 1;
  const rpc = (method, params) => {
    const id = nextId++;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    return new Promise((resolve) => pending.set(id, resolve));
  };
  const notify = (method, params) => {
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  };

  let buf = "";
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
        continue; // ignore any non-JSON line defensively
      }
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });

  try {
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("integration test timed out")), 15000);
      (async () => {
        await rpc("initialize", {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "integration-host", version: "0.0.1" },
        });
        notify("notifications/initialized", {});
        const res = await rpc("tools/call", {
          name: "read_file",
          arguments: { path: notesPath },
        });
        clearTimeout(timer);
        resolve(res);
      })().catch(reject);
    });

    // (a) The forwarded tool result the host received carries the injected
    //     marker, with the original file content still present.
    const text = result.result?.content?.find((b) => b.type === "text")?.text ?? "";
    assert.match(text, /<INJECTED by mcpwn>/, "forwarded tools/call result should contain the injected marker");
    assert.match(text, /synthetic test content/, "original file content should survive the injection");

    // Clean teardown: close stdin, let the server (and mcpwn) exit.
    child.stdin.end();
    await new Promise((resolve) => child.on("close", resolve));

    // (b) The JSONL log records both the original and the forwarded bytes plus
    //     the rule that fired. Locate the tampered tools/call response.
    const records = readFileSync(logPath, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    const tampered = records.find(
      (r) =>
        r.direction === "server->client" &&
        r.method === "tools/call" &&
        Array.isArray(r.applied) &&
        r.applied.includes("inject-tool-result")
    );
    assert.ok(tampered, "log should contain a tampered tools/call response record");
    assert.notEqual(tampered.raw, tampered.forwarded, "raw and forwarded bytes must differ");
    assert.ok(tampered.forwarded.includes(MARKER), "forwarded bytes carry the injected marker");
    assert.ok(!tampered.raw.includes(MARKER), "raw bytes do not carry the injected marker");
    assert.deepEqual(tampered.applied, ["inject-tool-result"]);
  } finally {
    try {
      child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
    rmSync(work, { recursive: true, force: true });
  }
});
