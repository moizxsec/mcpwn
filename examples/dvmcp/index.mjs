#!/usr/bin/env node
/**
 * DVMCP runner — the "Damn Vulnerable MCP" index.
 *
 *   node examples/dvmcp/index.mjs                 # list the servers + commands
 *   node examples/dvmcp/index.mjs <class>         # run one server over stdio
 *   npm run dvmcp -- <class>                       # same, via npm
 *
 * Running a class imports that server module in-process, so it behaves exactly
 * like `node examples/dvmcp/<class>.mjs` — e.g. point mcpwn at it:
 *
 *   mcpwn scan --fuzz -- node examples/dvmcp/index.mjs ssrf
 *
 * AUTHORIZED / EDUCATIONAL USE ONLY. Every server here is intentionally
 * vulnerable. They run entirely locally, make no real outbound network
 * requests, and never read real host files or run real shell commands — see
 * each file's SAFE SIMULATION note. Do not deploy them.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** class -> { file, cmd, finding } for the listing. */
export const SERVERS = {
  "path-traversal": {
    file: "path-traversal.mjs",
    cmd: "mcpwn scan --fuzz -- node examples/dvmcp/path-traversal.mjs",
    finding: "secret-exposure (high)",
  },
  ssrf: {
    file: "ssrf.mjs",
    cmd: "mcpwn scan --fuzz -- node examples/dvmcp/ssrf.mjs",
    finding: "embedded-url (high)",
  },
  "command-injection": {
    file: "command-injection.mjs",
    cmd: "mcpwn scan --fuzz -- node examples/dvmcp/command-injection.mjs",
    finding: "secret-exposure (high) + dangerous-tool (info)",
  },
  "tool-poisoning": {
    file: "tool-poisoning.mjs",
    cmd: "mcpwn scan -- node examples/dvmcp/tool-poisoning.mjs",
    finding: "tool-poisoning (high)",
  },
  "rug-pull": {
    file: "rug-pull.mjs",
    cmd: "mcpwn baseline capture --out base.json -- node examples/dvmcp/rug-pull.mjs --reset; mcpwn --baseline base.json --findings-out out -- node examples/dvmcp/rug-pull.mjs",
    finding: "tool-added (high) + tool-definition-changed (medium)",
  },
  "indirect-injection-via-resource": {
    file: "indirect-injection-via-resource.mjs",
    cmd: "mcpwn scan -- node examples/dvmcp/indirect-injection-via-resource.mjs",
    finding: "tool-poisoning (high) + embedded-url (high)",
  },
  "sampling-abuse": {
    file: "sampling-abuse.mjs",
    cmd: "mcpwn scan -- node examples/dvmcp/sampling-abuse.mjs",
    finding: "sampling-abuse (info) + tool-poisoning (high)",
  },
  "exfil-url": {
    file: "exfil-url.mjs",
    cmd: "mcpwn scan --fuzz -- node examples/dvmcp/exfil-url.mjs",
    finding: "embedded-url (high)",
  },
};

function printList() {
  process.stderr.write("DVMCP — intentionally-vulnerable MCP servers (authorized/educational use only)\n\n");
  for (const [cls, s] of Object.entries(SERVERS)) {
    process.stderr.write(`  ${cls.padEnd(32)} -> ${s.finding}\n      ${s.cmd}\n`);
  }
  process.stderr.write(
    "\nRun one:  node examples/dvmcp/index.mjs <class>   (or: npm run dvmcp -- <class>)\n"
  );
}

const cls = process.argv[2];
if (!cls || cls === "--help" || cls === "-h" || cls === "list") {
  printList();
  process.exit(cls ? 0 : 1);
} else if (!SERVERS[cls]) {
  process.stderr.write(`dvmcp: unknown class "${cls}"\n\n`);
  printList();
  process.exit(2);
} else {
  // Import the server module; it starts serving on stdio immediately.
  await import(join(HERE, SERVERS[cls].file));
}
