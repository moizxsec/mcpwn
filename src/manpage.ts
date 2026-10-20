import { createRequire } from "node:module";
import { SUBCOMMANDS } from "./completions.js";

/**
 * Generated man page (§Phase-8/F1). `mcpwn man` prints a simple roff(7) `.1`
 * page to stdout; `npm run man` writes it to docs/mcpwn.1. Derived from the same
 * HELP surface — kept intentionally small (synopsis, the subcommand list, a few
 * key options) rather than duplicating the whole HELP block.
 *
 * Pure string builder, zero deps.
 */

function esc(s: string): string {
  // Escape the two troff specials we might emit (leading dot, backslash).
  return s.replace(/\\/g, "\\\\").replace(/^\./gm, "\\&.");
}

export function generateManPage(version: string, date = new Date()): string {
  const d = date.toISOString().slice(0, 10);
  const subs = SUBCOMMANDS.join(", ");
  const lines: string[] = [];
  lines.push(`.TH MCPWN 1 "${d}" "mcpwn ${esc(version)}" "mcpwn Manual"`);
  lines.push(".SH NAME");
  lines.push("mcpwn \\- intercept & tamper proxy for MCP (Model Context Protocol) traffic");
  lines.push(".SH SYNOPSIS");
  lines.push(".B mcpwn");
  lines.push("[\\fIoptions\\fR] \\-\\- \\fIcommand\\fR [\\fIargs...\\fR]");
  lines.push(".br");
  lines.push(".B mcpwn");
  lines.push("\\fIsubcommand\\fR [\\fIoptions\\fR]");
  lines.push(".SH DESCRIPTION");
  lines.push("mcpwn is a man-in-the-middle proxy for the JSON-RPC traffic between an AI agent");
  lines.push("and its MCP servers \\- watch every message, tamper the tool results the server");
  lines.push("sends back, and run passive detectors over the stream. Burp Suite for AI agents.");
  lines.push(".PP");
  lines.push("AUTHORIZED TESTING ONLY. Use it only on agents and servers you own or are");
  lines.push("explicitly authorized to assess.");
  lines.push(".SH SUBCOMMANDS");
  lines.push(`The available subcommands are: ${esc(subs)}.`);
  lines.push(".TP");
  lines.push(".B scan");
  lines.push("Self-driving active scanner (no agent in the loop); emits JSON/Markdown/SARIF.");
  lines.push(".TP");
  lines.push(".B http");
  lines.push("Reverse-proxy a remote Streamable HTTP + SSE MCP server.");
  lines.push(".TP");
  lines.push(".B wrap \\fR/\\fB unwrap");
  lines.push("Route (or un-route) a client's configured MCP servers through mcpwn.");
  lines.push(".TP");
  lines.push(".B init");
  lines.push("Detect installed MCP clients and offer to wrap one; write starter config/policy.");
  lines.push(".TP");
  lines.push(".B completions \\fR<bash|zsh|fish>");
  lines.push("Print a shell completion script.");
  lines.push(".TP");
  lines.push(".B badge");
  lines.push("Emit a static SVG findings badge.");
  lines.push(".SH OPTIONS");
  lines.push(".TP");
  lines.push(".BR \\-i ", " \\-\\-intercept");
  lines.push("Interactively hold each message for review (stdio only; needs a terminal).");
  lines.push(".TP");
  lines.push('.BR \\-r " \\fIfile\\fR, " \\-\\-rule " \\fIfile\\fR"');
  lines.push("Load a JSON tamper-rule file (repeatable).");
  lines.push(".TP");
  lines.push('.BR \\-l " \\fIfile\\fR, " \\-\\-log " \\fIfile\\fR"');
  lines.push("Append a JSONL session log of all traffic.");
  lines.push(".TP");
  lines.push('.B \\-\\-findings\\-out " \\fIdir\\fR"');
  lines.push("Write findings.json + findings.md + findings.sarif on exit.");
  lines.push(".TP");
  lines.push(".B \\-\\-guard");
  lines.push("Run as a defensive firewall: sanitise/block malicious agent-bound content.");
  lines.push(".TP");
  lines.push('.BR \\-h ", " \\-\\-help');
  lines.push("Show help.");
  lines.push(".TP");
  lines.push(".B \\-\\-version");
  lines.push("Print the version.");
  lines.push(".SH EXIT STATUS");
  lines.push(
    "0 on success. A nonzero status from \\fBscan\\fR means a finding met \\-\\-fail\\-on."
  );
  lines.push(".SH SEE ALSO");
  lines.push("Full documentation at https://github.com/moizxsec/mcpwn");
  return lines.join("\n") + "\n";
}

/** Resolve the package version (from package.json next to dist/). */
function packageVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json");
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** `mcpwn man` — print the generated man page to stdout. */
export function runMan(): number {
  process.stdout.write(generateManPage(packageVersion()));
  return 0;
}
