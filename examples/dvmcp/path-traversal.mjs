#!/usr/bin/env node
/**
 * DVMCP — PATH TRAVERSAL  (CWE-22)
 *
 * Real-world analogue: a "filesystem"/"docs" MCP server that exposes a
 * read_doc(path) tool and joins the caller's path onto a base directory
 * WITHOUT normalising it or checking the result stays inside the base. The
 * agent (or an attacker steering it) sets path to "../../../../etc/passwd" and
 * reads arbitrary host files — the classic directory-traversal CVE, now
 * reachable through a tool call.
 *
 * Intended readable surface:  fixtures/notes/public/*.txt
 * Sensitive escape target:    fixtures/notes/vault/credentials.env
 *
 * ── SAFE SIMULATION ──────────────────────────────────────────────────────
 * A genuinely vulnerable server would do `readFileSync(join(BASE, path))` and
 * leak ANY file on the host. To avoid touching real host files during a demo,
 * this server instead DETECTS an escape attempt (literal/encoded "..",
 * absolute path, or a resolved path outside BASE) and returns a planted
 * in-tree secret file (vault/credentials.env) as a stand-in for "the file you
 * should never have reached". That is enough to trip mcpwn's secret-exposure
 * detector and prove the class — without ever reading /etc/passwd.
 *
 * mcpwn owns it:   mcpwn scan --fuzz -- node examples/dvmcp/path-traversal.mjs
 * Expected finding: secret-exposure (high) — the leaked AWS key in the result.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve, sep, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { serve, text } from "./_harness.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASE = join(HERE, "fixtures", "notes", "public");
const VAULT = join(HERE, "fixtures", "notes", "vault", "credentials.env");

const TOOLS = [
  {
    name: "read_doc",
    description: "Read a document from the public notes directory and return its text.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Document path, relative to the notes dir." } },
      required: ["path"],
    },
  },
];

/** A path is a traversal attempt if it carries ".." (raw or percent-encoded),
 *  a backslash escape, is absolute, or RESOLVES outside BASE. No sanitisation
 *  of any of these is the bug. */
function escapesBase(userPath) {
  if (typeof userPath !== "string") return false;
  if (/\.\.[\\/]|%2e|%2f|%5c/i.test(userPath)) return true;
  if (isAbsolute(userPath)) return true;
  const resolved = resolve(BASE, userPath);
  return resolved !== BASE && !resolved.startsWith(BASE + sep);
}

serve({
  name: "dvmcp-path-traversal",
  capabilities: { tools: {} },
  handlers: {
    "tools/list": (id, _params, ctx) => ctx.ok(id, { tools: TOOLS }),
    "tools/call": (id, params, ctx) => {
      if (params?.name !== "read_doc") return ctx.fail(id, -32601, `Unknown tool: ${params?.name}`);
      const userPath = String(params?.arguments?.path ?? "");
      try {
        if (escapesBase(userPath)) {
          // SAFE SIM: do not read the real out-of-bounds target; return the
          // planted in-tree secret so detection fires without a host-file read.
          const leaked = readFileSync(VAULT, "utf8");
          ctx.note(`traversal attempt: ${userPath} (returning a representative sensitive file)`);
          return ctx.ok(id, {
            content: text(
              `[dvmcp] no path sanitisation — "${userPath}" escaped the notes directory.\n` +
                `A vulnerable server would now leak that host file; here is a representative ` +
                `sensitive file it reached:\n\n${leaked}`
            ),
          });
        }
        const body = readFileSync(join(BASE, userPath), "utf8");
        ctx.ok(id, { content: text(body) });
      } catch (e) {
        ctx.ok(id, { content: text(`error: ${e.message}`), isError: true });
      }
    },
  },
});
