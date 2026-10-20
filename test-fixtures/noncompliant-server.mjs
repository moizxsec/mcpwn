#!/usr/bin/env node
/**
 * DELIBERATELY NON-COMPLIANT MCP stdio server — a test fixture for
 * `mcpwn conformance`. It speaks just enough JSON-RPC to complete a handshake
 * and answer ping (so those checks PASS and prove the checker works), but it
 * trips two conformance checks on purpose:
 *
 *   1. It prints a plain-text banner to STDOUT at startup — the classic MCP
 *      stdio footgun (stdout must carry ONLY JSON-RPC). => stdout-clean FAILs.
 *   2. It returns the WRONG error code (-1) for an unknown method instead of the
 *      JSON-RPC "method not found" code -32601.           => unknown-method FAILs.
 *
 * It is intentionally NOT built on the compliant examples/dvmcp/_harness.mjs.
 * Lives under test-fixtures/ so `node --test` never discovers it as a test.
 */

// (1) The footgun: non-JSON-RPC text on the stdout message channel.
process.stdout.write("noncompliant-server starting up (this line should be on stderr)\n");

const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

function handle(msg) {
  if (!msg || typeof msg !== "object" || typeof msg.method !== "string") return;
  const { id, method } = msg;
  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "noncompliant-server", version: "0.0.1" },
      },
    });
    return;
  }
  if (method === "ping") {
    send({ jsonrpc: "2.0", id, result: {} });
    return;
  }
  if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: [] } });
    return;
  }
  if (method.startsWith("notifications/")) return; // notification: no reply (correct)
  // (2) Wrong error code for an unknown method (should be -32601).
  if (id !== undefined) send({ jsonrpc: "2.0", id, error: { code: -1, message: "nope" } });
}

let buf = "";
process.stdin.on("data", (chunk) => {
  buf += chunk.toString("utf8");
  let nl;
  while ((nl = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, nl).replace(/\r$/, "");
    buf = buf.slice(nl + 1);
    if (!line) continue;
    try {
      handle(JSON.parse(line));
    } catch {
      /* ignore malformed line (no reply) */
    }
  }
});
process.stdin.on("end", () => process.exit(0));
