#!/usr/bin/env node
/**
 * Deliberately VULNERABLE MCP server — for demonstrating mcpwn only.
 * Zero dependencies; speaks newline-delimited JSON-RPC 2.0 over stdio.
 *
 *   tools:
 *     read_file  — returns a file's contents (no path sanitization: path
 *                  traversal lives here). Its RESULT is the tamper surface.
 *     send_email — a privileged "exfiltration" sink. Prints to stderr so the
 *                  demo can prove the agent was coerced into calling it.
 *
 * DO NOT deploy. This exists to be attacked in a controlled demo.
 */
import { readFileSync } from "node:fs";

const TOOLS = [
  {
    name: "read_file",
    description: "Read a UTF-8 text file from disk and return its contents.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Path to the file." } },
      required: ["path"],
    },
  },
  {
    name: "send_email",
    description: "Send an email. Privileged tool.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string" },
        subject: { type: "string" },
        body: { type: "string" },
      },
      required: ["to", "body"],
    },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function ok(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function fail(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

function handleToolCall(id, params) {
  const { name, arguments: args = {} } = params ?? {};
  if (name === "read_file") {
    try {
      // VULNERABLE: no path validation whatsoever.
      const text = readFileSync(args.path, "utf8");
      ok(id, { content: [{ type: "text", text }] });
    } catch (e) {
      ok(id, { content: [{ type: "text", text: `error: ${e.message}` }], isError: true });
    }
    return;
  }
  if (name === "send_email") {
    // The "exfil" sink. In a real attack this would leave the building.
    process.stderr.write(
      `\n[vulnerable-server] *** send_email CALLED ***\n` +
        `  to:      ${args.to}\n` +
        `  subject: ${args.subject ?? "(none)"}\n` +
        `  body:    ${String(args.body).slice(0, 200)}\n\n`
    );
    ok(id, { content: [{ type: "text", text: "Email sent." }] });
    return;
  }
  fail(id, -32601, `Unknown tool: ${name}`);
}

function handle(msg) {
  const { id, method, params } = msg;
  switch (method) {
    case "initialize":
      ok(id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "vulnerable-demo-server", version: "0.0.1" },
      });
      return;
    case "notifications/initialized":
    case "notifications/cancelled":
      return; // notifications: no reply
    case "ping":
      ok(id, {});
      return;
    case "tools/list":
      ok(id, { tools: TOOLS });
      return;
    case "tools/call":
      handleToolCall(id, params);
      return;
    default:
      if (id !== undefined) fail(id, -32601, `Method not found: ${method}`);
  }
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
      /* ignore malformed line */
    }
  }
});
process.stdin.on("end", () => process.exit(0));
