import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Transparency-when-idle assertion for the STDIO transport (Invariant #3): with
// no rules/detectors, the proxy must relay traffic byte-for-byte in order. We
// wrap a child that pipes stdin→stdout verbatim, so a line sent by the "host"
// travels client->server through mcpwn, is echoed by the child, and travels
// server->client back — exercising idle passthrough in BOTH directions.

const here = fileURLToPath(new URL(".", import.meta.url));
const cli = join(here, "..", "dist", "cli.js");

const LINES = [
  '{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}', // deliberate spacing
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":2}}}',
  '{"b": 2, "a": 1}', // non-RPC object → opaque relay, still byte-identical
  "not even json {", // unparseable → opaque relay verbatim
];

test("stdio idle: no rules → byte-for-byte, order-preserving relay in both directions", async () => {
  const child = spawn(
    process.execPath,
    [cli, "--", process.execPath, "-e", "process.stdin.pipe(process.stdout)"],
    { stdio: ["pipe", "pipe", "ignore"] }
  );

  let received = "";
  child.stdout.on("data", (c) => (received += c.toString("utf8")));

  const sent = LINES.map((l) => l + "\n").join("");
  child.stdin.write(sent);
  child.stdin.end();

  await new Promise((resolve) => child.on("close", resolve));

  // Byte-for-byte and order-preserving.
  assert.equal(received, sent);
});
