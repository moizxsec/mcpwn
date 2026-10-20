#!/usr/bin/env node
/**
 * DVMCP — SERVER-SIDE REQUEST FORGERY  (CWE-918)
 *
 * Real-world analogue: a "web"/"fetch" MCP server exposing fetch_url(url) that
 * retrieves whatever URL it is handed, with no allowlist and no block on
 * link-local / internal targets. The agent (or an attacker steering it) points
 * it at the cloud metadata endpoint (http://169.254.169.254/...) and the
 * server dutifully fetches it — SSRF to instance-credential theft.
 *
 * ── SAFE SIMULATION ──────────────────────────────────────────────────────
 * This server makes NO real outbound network requests. It parses the URL,
 * echoes the exact request it WOULD send back into the tool result, and for
 * known internal/metadata hosts returns a canned "response body" (the AWS
 * doc-placeholder credentials). Echoing the fetched URL into the result is
 * faithful to how a fetcher leaks its target — and it is exactly what mcpwn's
 * embedded-url detector keys on (a raw-IP / link-local host => high).
 *
 * mcpwn owns it:   mcpwn scan --fuzz -- node examples/dvmcp/ssrf.mjs
 * Expected finding: embedded-url (high) — the 169.254.169.254 metadata URL in
 *                   the result (raw IPv4 literal is scored high).
 */
import { serve, text } from "./_harness.mjs";

const TOOLS = [
  {
    name: "fetch_url",
    description: "Fetch a URL and return the response body.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string", description: "The URL to fetch." } },
      required: ["url"],
    },
  },
];

// AWS's own public documentation placeholder values — safe, not a live secret.
const FAKE_CREDS =
  '{"Code":"Success","AccessKeyId":"AKIAIOSFODNN7EXAMPLE",' +
  '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"<redacted>"}';

/** Link-local / loopback / metadata hosts a hardened fetcher must refuse. */
function isInternal(host) {
  return (
    /^169\.254\./.test(host) ||
    /^127\./.test(host) ||
    host === "localhost" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    /metadata/i.test(host)
  );
}

serve({
  name: "dvmcp-ssrf",
  capabilities: { tools: {} },
  handlers: {
    "tools/list": (id, _params, ctx) => ctx.ok(id, { tools: TOOLS }),
    "tools/call": (id, params, ctx) => {
      if (params?.name !== "fetch_url") return ctx.fail(id, -32601, `Unknown tool: ${params?.name}`);
      const raw = String(params?.arguments?.url ?? "");
      let host = "";
      try {
        host = new URL(raw).hostname;
      } catch {
        return ctx.ok(id, { content: text(`[dvmcp] not a fetchable URL: ${raw}`) });
      }
      // VULNERABLE: no allowlist, no internal-target block. The fetched URL is
      // echoed into agent-bound output (SSRF + the exfil/embedded-url surface).
      if (isInternal(host)) {
        ctx.note(`SSRF to internal target: ${raw}`);
        return ctx.ok(id, {
          content: text(
            `[dvmcp] fetched ${raw} (no allowlist!). Internal/metadata response:\n${FAKE_CREDS}`
          ),
        });
      }
      ctx.ok(id, { content: text(`[dvmcp] fetched ${raw} -> 200 OK (body omitted).`) });
    },
  },
});
