import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Direction } from "./types.js";

/**
 * Findings model + writers (§3.5). Detectors (§3.4, §3.9) record observations
 * here; the CLI serializes them on exit to JSON (machine), Markdown (human,
 * mirroring docs/ADVISORY_TEMPLATE.md) and SARIF 2.1.0 (CI / code-scanning).
 *
 * A finding is a passive observation — recording one NEVER changes what mcpwn
 * forwards on the wire (Invariant #2). Writers are pure string builders so they
 * are trivially unit-testable; `writeFindingsDir` is the only one that touches
 * disk.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable rule id, shared by every finding of the same class (e.g.
   *  "secret-exposure"). SARIF emits exactly one rule per distinct id. */
  id: string;
  /** One-line human summary. */
  title: string;
  severity: Severity;
  /** Which way the offending message was travelling, when relevant. */
  direction?: Direction;
  /** JSON-RPC method the finding relates to (resolved via correlation). */
  method?: string;
  /** Tool name the finding relates to, when known. */
  tool?: string;
  /** A short, already-redacted snippet proving the finding. Never put a raw
   *  secret here — detectors mask evidence before recording it. */
  evidence?: string;
  /** Longer explanation of what the flaw is. */
  description?: string;
  /** Suggested fix. */
  remediation?: string;
  /** When it was observed (ms epoch). */
  ts?: number;
}

/** A place detectors drop findings. `all()` returns them in insertion order. */
export interface FindingsSink {
  add(f: Finding): void;
  all(): Finding[];
}

/** The default in-memory sink. */
export class ArrayFindingsSink implements FindingsSink {
  private items: Finding[] = [];
  add(f: Finding): void {
    this.items.push(f);
  }
  all(): Finding[] {
    return this.items;
  }
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Most-severe first; ties keep insertion order (stable sort). Exported so
 *  other writers (e.g. the HTML report) order findings identically. */
export function bySeverity(findings: Finding[]): Finding[] {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => {
      const sa = SEVERITY_ORDER[a.f.severity] ?? 99;
      const sb = SEVERITY_ORDER[b.f.severity] ?? 99;
      return sa - sb || a.i - b.i;
    })
    .map((x) => x.f);
}

/** findings.json — a plain array so it round-trips exactly. */
export function writeJson(findings: Finding[]): string {
  return JSON.stringify(findings, null, 2) + "\n";
}

function mdEscape(s: string): string {
  return s.replace(/\|/g, "\\|");
}

/** findings.md — one section per finding, headings mirroring the advisory
 *  template (Severity / Description / Evidence / Suggested remediation). */
export function writeMarkdown(findings: Finding[]): string {
  const sorted = bySeverity(findings);
  const lines: string[] = [];
  lines.push("# mcpwn findings");
  lines.push("");
  lines.push(`Generated ${new Date().toISOString()} — ${sorted.length} finding(s).`);
  lines.push("");

  if (sorted.length === 0) {
    lines.push("_No findings recorded._");
    lines.push("");
    return lines.join("\n");
  }

  // Summary table.
  lines.push("| Severity | ID | Title |");
  lines.push("| --- | --- | --- |");
  for (const f of sorted) {
    lines.push(`| ${f.severity} | ${mdEscape(f.id)} | ${mdEscape(f.title)} |`);
  }
  lines.push("");

  for (const f of sorted) {
    lines.push(`## ${f.title}`);
    lines.push("");
    lines.push(`- **Severity:** ${f.severity}`);
    lines.push(`- **ID:** ${f.id}`);
    if (f.direction) lines.push(`- **Direction:** ${f.direction}`);
    if (f.method) lines.push(`- **Method:** ${f.method}`);
    if (f.tool) lines.push(`- **Tool:** ${f.tool}`);
    if (f.ts) lines.push(`- **Observed:** ${new Date(f.ts).toISOString()}`);
    lines.push("");
    if (f.description) {
      lines.push("### Description");
      lines.push("");
      lines.push(f.description);
      lines.push("");
    }
    if (f.evidence) {
      lines.push("### Evidence");
      lines.push("");
      lines.push("```");
      lines.push(f.evidence);
      lines.push("```");
      lines.push("");
    }
    if (f.remediation) {
      lines.push("### Suggested remediation");
      lines.push("");
      lines.push(f.remediation);
      lines.push("");
    }
  }
  return lines.join("\n");
}

type SarifLevel = "error" | "warning" | "note";

/** critical/high → error, medium → warning, low/info → note (§3.5). */
export function sarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/** findings.sarif — SARIF 2.1.0 with one rule per distinct Finding.id and one
 *  result per finding (logicalLocations carry the method/tool). */
export function writeSarif(findings: Finding[]): string {
  // One rule per distinct id (first occurrence wins for descriptive text).
  const ruleIndex = new Map<string, number>();
  const rules: unknown[] = [];
  for (const f of findings) {
    if (ruleIndex.has(f.id)) continue;
    ruleIndex.set(f.id, rules.length);
    rules.push({
      id: f.id,
      name: f.id,
      shortDescription: { text: f.title },
      defaultConfiguration: { level: sarifLevel(f.severity) },
    });
  }

  const results = findings.map((f) => {
    const logicalLocations: unknown[] = [];
    if (f.method) logicalLocations.push({ name: f.method, kind: "method" });
    if (f.tool) logicalLocations.push({ name: f.tool, kind: "member" });
    const text = f.evidence ? `${f.title}\n\n${f.evidence}` : f.title;
    const result: Record<string, unknown> = {
      ruleId: f.id,
      ruleIndex: ruleIndex.get(f.id),
      level: sarifLevel(f.severity),
      message: { text },
    };
    if (logicalLocations.length) result.logicalLocations = logicalLocations;
    return result;
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcpwn",
            informationUri: "https://github.com/moizxsec/mcpwn",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}

/** Write findings.json + findings.md + findings.sarif into `dir` (created if
 *  needed). Best-effort: a write error is thrown to the caller, which logs it. */
export function writeFindingsDir(dir: string, findings: Finding[]): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "findings.json"), writeJson(findings));
  writeFileSync(join(dir, "findings.md"), writeMarkdown(findings));
  writeFileSync(join(dir, "findings.sarif"), writeSarif(findings));
}
