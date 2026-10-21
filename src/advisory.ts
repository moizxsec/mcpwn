import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { bySeverity, fingerprint, type Finding } from "./findings.js";

/**
 * Auto-advisory engine (§3.5 / Phase-9 C2) — CVSS v3.1 + CWE per finding.
 *
 * Every detector in mcpwn emits a stable finding `id` (see src/detect/*.ts and
 * src/guard/guard.ts). This module is the single canonical place that maps each
 * known id — and each dvmcp/template attack class — to a defensible CWE and a
 * CVSS v3.1 base vector/score, and renders a filled GHSA-style advisory document
 * mirroring docs/ADVISORY_TEMPLATE.md.
 *
 * It is a pure, zero-dependency string/data module (node:* only, nothing here):
 *  - {@link advisoryFor} is a read-only lookup that degrades gracefully (returns
 *    undefined) for an unknown id, so an unmapped/custom-detector finding never
 *    throws and the rest of the pipeline is unaffected.
 *  - {@link renderAdvisory} / {@link renderAdvisorySet} are pure builders, so the
 *    markdown is trivially unit-testable (like findings.ts / report.ts).
 *  - Enrichment is ADDITIVE: it never mutates a Finding and findings.json stays a
 *    byte-exact round-trip. The SARIF writer and HTML report read this table to
 *    annotate their output; the advisory command renders full documents from it.
 *
 * CVSS rationale (threat model): the attacker is a malicious or compromised MCP
 * server (or attacker-controlled content flowing through one); the victim is the
 * AI agent and its host. Content crosses a trust boundary over the MCP channel,
 * so the vector is Network (AV:N) unless noted. Classes that only bite once the
 * agent/host acts on the content carry UI:R and, where the blast radius reaches
 * beyond the server (the agent/host), Scope:Changed. Scores are the standard
 * CVSS v3.1 base scores for the chosen vectors; see FIRST's calculator.
 */

/** A canonical CWE + CVSS mapping for one finding class. */
export interface AdvisoryEntry {
  /** Primary CWE id, e.g. "CWE-1427". */
  cwe: string;
  /** Human CWE name. */
  cweName: string;
  /** CVSS v3.1 base vector string. */
  cvssVector: string;
  /** CVSS v3.1 base score (0.0–10.0). */
  cvssScore: number;
  /** CVSS qualitative rating derived from the score (None/Low/Medium/High/Critical). */
  cvssSeverity: string;
  /** The mcpwn attack class this id belongs to. */
  attackClass: string;
  /** Background references (CWE, OWASP LLM Top 10, MCP spec, …). */
  references: string[];
}

/** The CVSS v3.1 qualitative band for a base score. */
export function cvssQualitative(score: number): string {
  if (score <= 0) return "None";
  if (score < 4.0) return "Low";
  if (score < 7.0) return "Medium";
  if (score < 9.0) return "High";
  return "Critical";
}

/** A table row before the qualitative rating is derived from the score. */
type RawEntry = Omit<AdvisoryEntry, "cvssSeverity">;

/** Common references reused across many entries. */
const REF_MCP_SPEC = "https://modelcontextprotocol.io/specification";
const REF_CVSS_CALC = "https://www.first.org/cvss/calculator/3.1";
const REF_OWASP_LLM01 =
  "https://genai.owasp.org/llmrisk/llm01-prompt-injection/ (OWASP LLM01: Prompt Injection)";
const cweUrl = (n: number): string => `https://cwe.mitre.org/data/definitions/${n}.html`;

/**
 * The canonical id -> CWE/CVSS table. Keyed by every finding id emitted by the
 * built-in detectors (src/detect/linter.ts), the baseline detector
 * (src/detect/baseline.ts), the opt-in pin/taint detectors, and the guard
 * firewall (src/guard/guard.ts) — PLUS the dvmcp/template attack-class keys
 * (examples/dvmcp, templates/*.json) so the advisory command and THREATS.md
 * resolve a class name too. Each vector has a one-line rationale.
 */
const RAW_TABLE: Record<string, RawEntry> = {
  // --- passive linters (src/detect/linter.ts) -------------------------------

  // A live credential reaches the agent: pure confidentiality loss, no user
  // interaction needed once it is in the stream.
  "secret-exposure": {
    cwe: "CWE-200",
    cweName: "Exposure of Sensitive Information to an Unauthorized Actor",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    attackClass: "secret-exposure",
    references: [cweUrl(200), cweUrl(522), REF_MCP_SPEC, REF_CVSS_CALC],
  },

  // Instruction-like content in agent-bound text = prompt injection into the
  // model. The agent is steered to act (integrity) beyond the server's scope.
  "tool-poisoning": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Prompt Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "tool-poisoning",
    references: [cweUrl(1427), cweUrl(74), REF_OWASP_LLM01, REF_MCP_SPEC],
  },

  // Detector name alias (the id it emits is "tool-poisoning"); mapped so a
  // caller that keys on the detector name still resolves.
  "injection-marker-in-description": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Prompt Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "tool-poisoning",
    references: [cweUrl(1427), cweUrl(74), REF_OWASP_LLM01, REF_MCP_SPEC],
  },

  // Hidden/zero-width/Unicode-Tag smuggling: invisible to a human reviewer but
  // read by the model — a stealth prompt-injection carrier.
  "invisible-unicode": {
    cwe: "CWE-1427",
    cweName:
      "Improper Neutralization of Input Used for LLM Prompting (Hidden-Instruction Smuggling)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "unicode-smuggling",
    references: [cweUrl(1427), cweUrl(150), REF_OWASP_LLM01],
  },

  // A URL in a tool result/resource an auto-fetching agent may follow: SSRF /
  // out-of-band data-exfiltration channel (confidentiality of what gets sent).
  "embedded-url": {
    cwe: "CWE-918",
    cweName: "Server-Side Request Forgery (SSRF)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    cvssScore: 7.4,
    attackClass: "ssrf-exfiltration",
    references: [cweUrl(918), cweUrl(200), REF_MCP_SPEC],
  },

  // Two tools share a name, or a name collides with a trusted client built-in:
  // the agent resolves the wrong reference and routes a call to the impostor.
  "tool-shadowing": {
    cwe: "CWE-706",
    cweName: "Use of Incorrectly-Resolved Name or Reference",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
    cvssScore: 7.4,
    attackClass: "tool-shadowing",
    references: [cweUrl(706), cweUrl(441), REF_MCP_SPEC],
  },

  // A mutating tool advertised readOnlyHint:true: the client's auto-approve of
  // "read-only" tools becomes a security decision based on untrusted input.
  "annotation-mismatch": {
    cwe: "CWE-807",
    cweName: "Reliance on Untrusted Inputs in a Security Decision",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    cvssScore: 7.5,
    attackClass: "capability-misdeclaration",
    references: [cweUrl(807), cweUrl(862), REF_MCP_SPEC],
  },

  // Advisory: a tool advertises a high-impact capability (exec/shell/delete/
  // email/http). Not a flaw by itself — informational, low CVSS.
  "dangerous-tool": {
    cwe: "CWE-250",
    cweName: "Execution with Unnecessary Privileges",
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    cvssScore: 3.1,
    attackClass: "excessive-capability",
    references: [cweUrl(250), cweUrl(269), REF_MCP_SPEC],
  },

  // A server asking the client to run a model completion on its behalf — the
  // server steers the user's LLM (confused deputy / server-driven injection).
  "sampling-abuse": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Sampling Abuse)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    cvssScore: 6.1,
    attackClass: "sampling-abuse",
    references: [cweUrl(1427), cweUrl(441), REF_MCP_SPEC],
  },

  // --- baseline / rug-pull (src/detect/baseline.ts) -------------------------

  // A tool not in the trusted baseline appeared after the client built trust.
  "tool-added": {
    cwe: "CWE-494",
    cweName: "Download of Code Without Integrity Check",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "rug-pull",
    references: [cweUrl(494), cweUrl(1427), REF_MCP_SPEC],
  },

  // A tool's description/schema changed after the baseline — classic rug pull.
  "tool-definition-changed": {
    cwe: "CWE-494",
    cweName: "Download of Code Without Integrity Check",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
    cvssScore: 7.4,
    attackClass: "rug-pull",
    references: [cweUrl(494), cweUrl(1427), REF_MCP_SPEC],
  },

  // A baselined tool disappeared — informational drift.
  "tool-removed": {
    cwe: "CWE-494",
    cweName: "Download of Code Without Integrity Check",
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
    cvssScore: 3.1,
    attackClass: "rug-pull",
    references: [cweUrl(494), REF_MCP_SPEC],
  },

  // --- cross-session pinning (src/detect/pin.ts) ----------------------------

  // The committed pin lock and the live advertised surface diverged: a
  // cross-session rug pull on metadata the user already approved.
  "pin-drift": {
    cwe: "CWE-494",
    cweName: "Download of Code Without Integrity Check",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "rug-pull",
    references: [cweUrl(494), cweUrl(1427), REF_MCP_SPEC],
  },

  // --- provenance taint (src/detect/taint.ts) -------------------------------

  // Untrusted server output reused verbatim inside a later tools/call argument:
  // the injection -> action kill chain (indirect prompt injection realised).
  "provenance-taint": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Indirect Prompt Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "indirect-prompt-injection",
    references: [cweUrl(1427), cweUrl(77), REF_OWASP_LLM01, REF_MCP_SPEC],
  },

  // --- guard firewall (src/guard/guard.ts) ----------------------------------
  // The guard records `guard-<action>` when it enforces the policy on content
  // it recognised (injection / secret / exfil-url / invisible-unicode). The
  // underlying risk is the content class caught; prompt injection is the
  // dominant one, so these carry CWE-1427 with a note. Scores track the guard's
  // own severity mapping (block=high, sanitize=medium, warn=low).

  "guard-block": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Guard: blocked)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "guard-enforcement",
    references: [cweUrl(1427), REF_OWASP_LLM01, REF_MCP_SPEC],
  },
  "guard-sanitize": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Guard: sanitized)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    cvssScore: 6.1,
    attackClass: "guard-enforcement",
    references: [cweUrl(1427), REF_OWASP_LLM01, REF_MCP_SPEC],
  },
  "guard-warn": {
    cwe: "CWE-1427",
    cweName: "Improper Neutralization of Input Used for LLM Prompting (Guard: warned)",
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    cvssScore: 3.1,
    attackClass: "guard-enforcement",
    references: [cweUrl(1427), REF_OWASP_LLM01, REF_MCP_SPEC],
  },

  // --- dvmcp / template attack classes (examples/dvmcp, templates/*.json) ---
  // Keyed by attackClass so `mcpwn advisory` and THREATS.md can resolve a class
  // name, and the template gallery's attackClass values line up.

  "path-traversal": {
    cwe: "CWE-22",
    cweName: "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    attackClass: "path-traversal",
    references: [cweUrl(22), REF_MCP_SPEC],
  },
  ssrf: {
    cwe: "CWE-918",
    cweName: "Server-Side Request Forgery (SSRF)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    cvssScore: 8.6,
    attackClass: "ssrf",
    references: [cweUrl(918), REF_MCP_SPEC],
  },
  "command-injection": {
    cwe: "CWE-78",
    cweName:
      "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    attackClass: "command-injection",
    references: [cweUrl(78), REF_MCP_SPEC],
  },
  sqli: {
    cwe: "CWE-89",
    cweName: "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    attackClass: "sql-injection",
    references: [cweUrl(89), REF_MCP_SPEC],
  },
  "data-exfiltration": {
    cwe: "CWE-200",
    cweName: "Exposure of Sensitive Information to an Unauthorized Actor",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    cvssScore: 7.4,
    attackClass: "data-exfiltration",
    references: [cweUrl(200), cweUrl(918), REF_MCP_SPEC],
  },
  "indirect-prompt-injection": {
    cwe: "CWE-74",
    cweName:
      "Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "indirect-prompt-injection",
    references: [cweUrl(74), cweUrl(1427), REF_OWASP_LLM01, REF_MCP_SPEC],
  },
  "prompt-injection": {
    cwe: "CWE-74",
    cweName:
      "Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "prompt-injection",
    references: [cweUrl(74), cweUrl(1427), REF_OWASP_LLM01, REF_MCP_SPEC],
  },
  "rug-pull": {
    cwe: "CWE-494",
    cweName: "Download of Code Without Integrity Check",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    cvssScore: 8.2,
    attackClass: "rug-pull",
    references: [cweUrl(494), cweUrl(1427), REF_MCP_SPEC],
  },
};

/** The canonical table with the CVSS qualitative rating derived from the score.
 *  Exported (read-only) so tooling/tests can introspect the full mapping. */
export const ADVISORY_TABLE: Readonly<Record<string, AdvisoryEntry>> = Object.fromEntries(
  Object.entries(RAW_TABLE).map(([id, e]) => [
    id,
    { ...e, cvssSeverity: cvssQualitative(e.cvssScore) },
  ])
);

/**
 * Resolve the CWE/CVSS mapping for a finding id (or an attack-class key).
 * Returns undefined for an unknown id so callers degrade gracefully — an
 * unmapped or custom-detector finding is simply rendered without CWE/CVSS.
 */
export function advisoryFor(id: string): AdvisoryEntry | undefined {
  return ADVISORY_TABLE[id];
}

// --- markdown rendering ------------------------------------------------------

/** Options shared by the advisory renderers. */
export interface AdvisoryOptions {
  /** Where the findings came from (a findings dir / findings.json path), shown
   *  in the reproduction/evidence section. */
  source?: string;
  /** A recorded session JSONL to attach as evidence, when available. */
  sessionFile?: string;
  /** Override generated-at (ms epoch) for deterministic output in tests. */
  generatedAt?: number;
}

function iso(ms?: number): string {
  return new Date(ms ?? Date.now()).toISOString();
}

/** The component line for the "Affected" section, from method + tool. */
function componentOf(f: Finding): string {
  const parts: string[] = [];
  if (f.tool) parts.push(`\`${f.tool}\``);
  if (f.method) parts.push(`\`${f.method}\``);
  if (parts.length === 0) return "the MCP server (surface not resolved)";
  return parts.join(" via ");
}

/** The bundled mcpwn command most likely to reproduce a finding of this class,
 *  derived from the method it relates to. Generic and safe (no real target). */
function reproCommand(f: Finding): string {
  const server = "<server> [args...]";
  switch (f.method) {
    case "tools/call":
      return `mcpwn scan --fuzz --findings-out ./out -- ${server}`;
    case "resources/read":
    case "resources/list":
    case "prompts/get":
    case "prompts/list":
    case "tools/list":
      return `mcpwn scan --findings-out ./out -- ${server}`;
    case "sampling/createMessage":
      return `mcpwn scan --findings-out ./out -- ${server}`;
    default:
      return `mcpwn --findings-out ./out -- ${server}`;
  }
}

/** Numbered reproduction steps derived from the finding's method/tool/evidence. */
function reproSteps(f: Finding): string[] {
  const steps: string[] = [];
  switch (f.method) {
    case "tools/list":
      steps.push("Enumerate the advertised tools and inspect their metadata.");
      break;
    case "tools/call":
      steps.push(
        f.tool
          ? `Invoke the \`${f.tool}\` tool (\`tools/call\`) and inspect the result.`
          : "Invoke the affected tool (`tools/call`) and inspect the result."
      );
      break;
    case "resources/read":
      steps.push("Read the affected resource (`resources/read`) and inspect its contents.");
      break;
    case "prompts/get":
      steps.push("Fetch the affected prompt (`prompts/get`) and inspect its messages.");
      break;
    case "sampling/createMessage":
      steps.push(
        "Observe the server-initiated `sampling/createMessage` request and its supplied prompt."
      );
      break;
    default:
      steps.push("Drive the traffic that exercises the affected surface.");
  }
  steps.push("Confirm mcpwn records the finding below in the findings output.");
  return steps;
}

/**
 * Render one finding as a filled advisory markdown section, mirroring
 * docs/ADVISORY_TEMPLATE.md. When `topLevel` is true the title is an H1 (for a
 * one-file-per-finding document); otherwise an H2 (for a combined document).
 */
export function renderAdvisory(f: Finding, opts: AdvisoryOptions = {}, topLevel = true): string {
  const a = advisoryFor(f.id);
  const h = topLevel ? "#" : "##";
  const sub = topLevel ? "##" : "###";
  const lines: string[] = [];

  lines.push(`${h} Security advisory - ${f.title}`);
  lines.push("");
  lines.push(`${sub} Summary`);
  lines.push("");
  lines.push(f.description ?? `${f.title}. Detected by mcpwn as \`${f.id}\` (${f.severity}).`);
  lines.push("");

  lines.push(`${sub} Affected`);
  lines.push("");
  lines.push(`- **Component:** ${componentOf(f)}`);
  if (f.method) lines.push(`- **Method:** \`${f.method}\``);
  if (f.tool) lines.push(`- **Tool:** \`${f.tool}\``);
  if (f.direction) lines.push(`- **Direction:** ${f.direction}`);
  lines.push(`- **Detector id:** \`${f.id}\``);
  lines.push("");

  lines.push(`${sub} Severity`);
  lines.push("");
  lines.push(`- **mcpwn severity:** ${f.severity}`);
  if (a) {
    lines.push(`- **CVSS v3.1:** ${a.cvssScore} (${a.cvssSeverity})`);
    lines.push(`- **CVSS vector:** \`${a.cvssVector}\``);
    lines.push(`- **CWE:** [${a.cwe}](${cweUrlFor(a.cwe)}) - ${a.cweName}`);
    lines.push(`- **Attack class:** ${a.attackClass}`);
  } else {
    lines.push(
      "- **CVSS v3.1 / CWE:** not mapped for this id (custom or unrecognised detector) - score manually."
    );
  }
  lines.push("");

  lines.push(`${sub} Reproduction with mcpwn`);
  lines.push("");
  lines.push("Run mcpwn against the target with the passive detectors enabled:");
  lines.push("");
  lines.push("```bash");
  lines.push(reproCommand(f));
  lines.push("```");
  lines.push("");
  const steps = reproSteps(f);
  for (let i = 0; i < steps.length; i++) lines.push(`${i + 1}. ${steps[i]}`);
  lines.push("");
  if (opts.source) {
    lines.push(`Findings source: \`${opts.source}\`.`);
    lines.push("");
  }
  if (opts.sessionFile) {
    lines.push(
      `Attach the relevant lines from the session log \`${opts.sessionFile}\` (redact any real secrets).`
    );
    lines.push("");
  }
  if (f.evidence) {
    lines.push(`${sub} Evidence`);
    lines.push("");
    lines.push("```");
    lines.push(f.evidence);
    lines.push("```");
    lines.push("");
  }

  lines.push(`${sub} Impact`);
  lines.push("");
  lines.push(impactText(f, a));
  lines.push("");

  lines.push(`${sub} Suggested remediation`);
  lines.push("");
  lines.push(
    f.remediation ??
      "Treat all server-supplied content as untrusted data, never as instructions or trusted metadata; validate and contain before it reaches the agent or any privileged call."
  );
  lines.push("");

  if (a && a.references.length) {
    lines.push(`${sub} References`);
    lines.push("");
    for (const r of a.references) lines.push(`- ${r}`);
    lines.push("");
  }

  lines.push(`${sub} Credit`);
  lines.push("");
  lines.push("Found with [mcpwn](https://github.com/moizxsec/mcpwn).");
  lines.push("");
  lines.push(`<!-- fingerprint: ${fingerprint(f)} -->`);
  lines.push("");

  return lines.join("\n");
}

/** A concrete impact sentence for the class, falling back to a generic one. */
function impactText(f: Finding, a?: AdvisoryEntry): string {
  switch (f.id) {
    case "secret-exposure":
      return "An agent ingesting this learns a live credential; it may be logged, cached, or forwarded onward, enabling account takeover or lateral movement.";
    case "tool-poisoning":
    case "injection-marker-in-description":
      return "The agent treats attacker-authored text as instructions (prompt injection), letting a malicious server redirect it into actions the user never approved.";
    case "invisible-unicode":
      return "Instructions invisible to a human reviewer are read by the model, smuggling a hidden prompt injection past review.";
    case "embedded-url":
      return "An auto-fetching agent follows an attacker-controlled link, enabling SSRF against internal targets and out-of-band exfiltration of appended data.";
    case "tool-shadowing":
      return "The agent resolves the wrong tool and routes a privileged call to an impostor implementation.";
    case "annotation-mismatch":
      return "A mutating tool mislabelled read-only is auto-approved and runs without the user's confirmation.";
    case "sampling-abuse":
      return "The server drives the client's model with an attacker-authored prompt (server-side influence over the user's LLM).";
    case "tool-added":
    case "tool-definition-changed":
    case "tool-removed":
    case "pin-drift":
      return "The server's advertised surface changed after the user approved it (rug pull): metadata the agent now sees differs from what was trusted.";
    case "provenance-taint":
      return "Untrusted server output flows into a privileged tool call - an indirect prompt injection turned into a real action (injection -> action kill chain).";
    default:
      return a
        ? `See ${a.cwe} (${a.cweName}). ${a.cweName} in this surface lets a malicious MCP server subvert the agent or its host.`
        : "A malicious or compromised MCP server can subvert the agent or its host through this surface.";
  }
}

/** Build a CWE definition URL from a "CWE-###" id. */
function cweUrlFor(cwe: string): string {
  const n = cwe.replace(/[^0-9]/g, "");
  return `https://cwe.mitre.org/data/definitions/${n}.html`;
}

/**
 * Render a combined advisory document for a whole findings set: a title, a
 * CVSS/CWE summary table (most-severe first), then one section per finding.
 */
export function renderAdvisorySet(findings: Finding[], opts: AdvisoryOptions = {}): string {
  const sorted = bySeverity(findings);
  const lines: string[] = [];
  lines.push("# mcpwn security advisories");
  lines.push("");
  lines.push(`Generated ${iso(opts.generatedAt)} - ${sorted.length} finding(s).`);
  if (opts.source) lines.push(`Source: \`${opts.source}\`.`);
  lines.push("");

  if (sorted.length === 0) {
    lines.push("_No findings to report._");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("| Severity | ID | CVSS | CWE | Title |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const f of sorted) {
    const a = advisoryFor(f.id);
    const cvss = a ? `${a.cvssScore} (${a.cvssSeverity})` : "-";
    const cwe = a ? a.cwe : "-";
    lines.push(`| ${f.severity} | ${mdCell(f.id)} | ${cvss} | ${cwe} | ${mdCell(f.title)} |`);
  }
  lines.push("");

  for (const f of sorted) {
    lines.push("---");
    lines.push("");
    lines.push(renderAdvisory(f, opts, false));
  }
  return lines.join("\n");
}

function mdCell(s: string): string {
  return s.replace(/\|/g, "\\|");
}

/** A filesystem-safe slug for a per-finding advisory filename. */
export function advisorySlug(f: Finding, index: number): string {
  const id = f.id.replace(/[^a-z0-9-]+/gi, "-").toLowerCase();
  const n = String(index + 1).padStart(2, "0");
  return `advisory-${n}-${id}-${fingerprint(f).slice(0, 8)}.md`;
}

// --- CLI ---------------------------------------------------------------------

export class AdvisoryArgError extends Error {}

export interface AdvisoryArgs {
  /** A findings directory (reads findings.json) or a direct findings.json file. */
  findingsPath?: string;
  /** Output: a directory (one .md per finding) or a .md file (combined). Omit to
   *  print the combined document to stdout. */
  out?: string;
  /** Attach this session JSONL as evidence in the reproduction section. */
  sessionFile?: string;
}

export function parseAdvisoryArgs(argv: string[]): AdvisoryArgs {
  const out: AdvisoryArgs = {};
  const value = (flag: string, i: number): [string, number] => {
    const v = argv[i + 1];
    if (v === undefined) throw new AdvisoryArgError(`option ${flag} requires an argument`);
    return [v, i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-o" || a === "--out") {
      [out.out, i] = value(a, i);
      continue;
    }
    if (a === "--session") {
      [out.sessionFile, i] = value(a, i);
      continue;
    }
    if (a.startsWith("-")) throw new AdvisoryArgError(`unknown option "${a}"`);
    if (out.findingsPath === undefined) {
      out.findingsPath = a;
      continue;
    }
    throw new AdvisoryArgError(`unexpected extra argument "${a}"`);
  }
  return out;
}

/** Load findings from a directory (findings.json) or a direct .json file. */
function loadFindingsFile(path: string): Finding[] {
  let file = path;
  try {
    if (statSync(path).isDirectory()) file = join(path, "findings.json");
  } catch {
    throw new AdvisoryArgError(`findings path not found: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new AdvisoryArgError(`could not read findings "${file}": ${(err as Error).message}`);
  }
  if (!Array.isArray(parsed)) throw new AdvisoryArgError(`${file} is not a findings array`);
  return parsed as Finding[];
}

/** Does `out` name a combined single file (ends in .md) vs a directory? */
function isCombinedFile(out: string): boolean {
  return /\.md$/i.test(out);
}

/**
 * `mcpwn advisory <findings-dir|findings.json> [-o <dir|file>] [--session <jsonl>]`
 *
 * Emits a filled CVSS/CWE advisory per finding. With no `-o`, prints a combined
 * document to stdout. With `-o <file.md>`, writes the combined document to that
 * file. With `-o <dir>`, writes one advisory `.md` per finding into the dir.
 */
export async function runAdvisory(argv: string[]): Promise<number> {
  let args: AdvisoryArgs;
  try {
    args = parseAdvisoryArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn advisory: ${(err as Error).message}\n`);
    return 2;
  }
  if (!args.findingsPath) {
    process.stderr.write("mcpwn advisory: missing <findings-dir|findings.json>\n");
    return 2;
  }

  let findings: Finding[];
  try {
    findings = loadFindingsFile(args.findingsPath);
  } catch (err) {
    process.stderr.write(`mcpwn advisory: ${(err as Error).message}\n`);
    return 2;
  }

  const opts: AdvisoryOptions = { source: args.findingsPath, sessionFile: args.sessionFile };

  // No -o, or -o is a .md file → one combined document.
  if (!args.out || isCombinedFile(args.out)) {
    const doc = renderAdvisorySet(findings, opts);
    if (!args.out) {
      process.stdout.write(doc);
      return 0;
    }
    try {
      writeFileSync(args.out, doc);
    } catch (err) {
      process.stderr.write(
        `mcpwn advisory: could not write "${args.out}": ${(err as Error).message}\n`
      );
      return 2;
    }
    process.stderr.write(`mcpwn: wrote combined advisory -> ${args.out}\n`);
    return 0;
  }

  // -o is a directory → one advisory file per finding.
  const dir = args.out;
  try {
    mkdirSync(dir, { recursive: true });
  } catch (err) {
    process.stderr.write(`mcpwn advisory: could not create "${dir}": ${(err as Error).message}\n`);
    return 2;
  }
  if (findings.length === 0) {
    process.stderr.write("mcpwn advisory: no findings to write\n");
    return 0;
  }
  const sorted = bySeverity(findings);
  let written = 0;
  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    const path = join(dir, advisorySlug(f, i));
    try {
      writeFileSync(path, renderAdvisory(f, opts, true));
      written++;
    } catch (err) {
      process.stderr.write(
        `mcpwn advisory: could not write "${path}": ${(err as Error).message}\n`
      );
      return 2;
    }
  }
  process.stderr.write(`mcpwn: wrote ${written} advisory file(s) -> ${dir}\n`);
  return 0;
}
