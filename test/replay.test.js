import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");
const server = join(root, "examples", "vulnerable-server.mjs");

// Record a client->server line the way the Logger would, so replay's JSONL
// filter (direction + kind + raw) accepts it.
function record(json) {
  return JSON.stringify({
    direction: "client->server",
    kind: json.id !== undefined ? "request" : "notification",
    method: json.method,
    raw: JSON.stringify(json),
  });
}

// Run `mcpwn replay ...`, collect stdout lines (the printed responses).
function runReplay(extraArgs, work) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [cli, "replay", ...extraArgs, "--", process.execPath, server],
      { stdio: ["ignore", "pipe", "ignore"], cwd: work }
    );
    let buf = "";
    const lines = [];
    child.stdout.on("data", (c) => {
      buf += c.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim()) lines.push(line);
      }
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("replay timed out"));
    }, 15000);
    child.on("close", () => {
      clearTimeout(timer);
      resolve(lines);
    });
    child.on("error", reject);
  });
}

test("replay: replays a recorded tools/call and prints the server response", async () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-replay-"));
  const notes = join(work, "notes.txt");
  writeFileSync(notes, "synthetic replay content\n");
  const session = join(work, "session.jsonl");
  writeFileSync(
    session,
    [
      record({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {} } }),
      record({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }),
      record({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { path: notes } } }),
    ].join("\n") + "\n"
  );

  try {
    const lines = await runReplay([session], work);
    const texts = lines
      .map((l) => JSON.parse(l))
      .flatMap((m) => (m.result?.content ?? []).map((b) => b.text ?? ""));
    assert.ok(texts.some((t) => t.includes("synthetic replay content")), "server response should carry the file content");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("replay: fuzzArgs + --repeat 3 sends 3 distinct payloads", async () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-replay-"));
  const session = join(work, "session.jsonl");
  writeFileSync(
    session,
    record({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read_file", arguments: { path: "orig" } } }) + "\n"
  );

  // fuzzArgs cycles three distinct, non-existent paths into read_file.path; the
  // vulnerable server echoes the attempted path in its ENOENT error, so we can
  // confirm three distinct payloads actually reached the server.
  const tokens = ["MCPWN_FUZZ_AAA", "MCPWN_FUZZ_BBB", "MCPWN_FUZZ_CCC"];
  const rules = join(work, "fuzz.json");
  writeFileSync(
    rules,
    JSON.stringify({
      rules: [
        {
          name: "fuzz-path",
          direction: "client->server",
          method: "tools/call",
          action: { kind: "fuzzArgs", tool: "read_file", path: "path", payloads: tokens },
        },
      ],
    })
  );

  try {
    const lines = await runReplay([session, "-r", rules, "--only-method", "tools/call", "--repeat", "3"], work);
    assert.equal(lines.length, 3, "three tools/call responses expected");
    const blob = lines.join("\n");
    const seen = tokens.filter((t) => blob.includes(t));
    assert.deepEqual(seen.sort(), [...tokens].sort(), "all three distinct payloads should have reached the server");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
