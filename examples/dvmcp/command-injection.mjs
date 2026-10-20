#!/usr/bin/env node
/**
 * DVMCP — OS COMMAND INJECTION  (CWE-78)
 *
 * Real-world analogue: a "devops"/"shell" MCP server exposing run_shell(cmd)
 * (or a narrower tool like ping(host)) that interpolates caller input into a
 * string passed to a shell. Shell metacharacters in the input (`;`, `|`, `&&`,
 * `$( )`, backticks) break out and run attacker commands with the server's
 * privileges.
 *
 * ── SAFE SIMULATION ──────────────────────────────────────────────────────
 * This server NEVER spawns a shell. It builds the command string the way a
 * vulnerable server would (`sh -c "<cmd>"`) and echoes it back. When the input
 * contains shell metacharacters it treats the injection as "successful" and
 * returns canned output for a representative injected command
 * (`$(cat .env)` -> the AWS doc-placeholder key), demonstrating real impact —
 * secret disclosure — without executing anything or deleting a single file.
 *
 * mcpwn owns it:
 *   mcpwn scan -- node examples/dvmcp/command-injection.mjs          # passive
 *   mcpwn scan --fuzz -- node examples/dvmcp/command-injection.mjs   # active
 * Expected findings:
 *   dangerous-tool (info)  — run_shell matches the exec/shell keyword set.
 *   secret-exposure (high) — a metacharacter payload "leaks" the planted key.
 */
import { serve, text } from "./_harness.mjs";

const TOOLS = [
  {
    name: "run_shell",
    description: "Run a shell command on the host and return its stdout.",
    inputSchema: {
      type: "object",
      properties: { cmd: { type: "string", description: "Command to run." } },
      required: ["cmd"],
    },
  },
];

// AWS's own public documentation placeholder — safe, not a live secret.
const FAKE_KEY = "AKIA" + "IOSFODNN7EXAMPLE";

/** Shell metacharacters that let an argument break out into a new command. */
const METACHARS = /[;&|`]|\$\(|\n/;

serve({
  name: "dvmcp-command-injection",
  capabilities: { tools: {} },
  handlers: {
    "tools/list": (id, _params, ctx) => ctx.ok(id, { tools: TOOLS }),
    "tools/call": (id, params, ctx) => {
      if (params?.name !== "run_shell") return ctx.fail(id, -32601, `Unknown tool: ${params?.name}`);
      const cmd = String(params?.arguments?.cmd ?? "");
      // VULNERABLE: raw interpolation into a shell string, no quoting/allowlist.
      const constructed = `sh -c "${cmd}"`;
      if (METACHARS.test(cmd)) {
        ctx.note(`command injection via metacharacters: ${cmd}`);
        return ctx.ok(id, {
          content: text(
            `[dvmcp] would execute: ${constructed}\n` +
              `Shell metacharacters broke out — a chained \`$(cat .env)\` runs too.\n` +
              `Simulated leaked output:\nAWS_ACCESS_KEY_ID=${FAKE_KEY}\n`
          ),
        });
      }
      ctx.ok(id, { content: text(`[dvmcp] would execute: ${constructed}\n(no metacharacters)`) });
    },
  },
});
