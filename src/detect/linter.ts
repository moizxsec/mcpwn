import type { Detector } from "./detector.js";
import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";
import { builtinRedactPatterns, redact, type RedactPattern } from "../redact.js";

/**
 * Passive linters (§3.9). Each inspects messages read-only and records findings;
 * none ever changes what is forwarded. They self-gate on direction/method so a
 * single pass over every parseable message is cheap.
 */

function resolvedMethod(flow: FlowMessage): string | undefined {
  return flow.method ?? flow.correlatedMethod;
}

/** Concatenated text of all text blocks in a tools/call result. */
function resultText(flow: FlowMessage): string {
  const content = flow.json?.result?.content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((b: any) => b && b.type === "text" && typeof b.text === "string")
    .map((b: any) => b.text as string)
    .join("\n");
}

function snippet(text: string, max = 240): string {
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
}

function freshGlobal(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  return new RegExp(re.source, flags);
}

/** `secret-in-result`: a tools/call result text matching a known secret
 *  format → secret-exposure (high). Evidence is redacted before recording. */
export class SecretInResultDetector implements Detector {
  private patterns: RedactPattern[] = builtinRedactPatterns();

  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (resolvedMethod(flow) !== "tools/call") return;
    const text = resultText(flow);
    if (!text) return;
    for (const p of this.patterns) {
      if (freshGlobal(p.re).test(text)) {
        sink.add({
          id: "secret-exposure",
          severity: "high",
          title: `Secret pattern "${p.label}" returned in a tools/call result`,
          direction: flow.direction,
          method: "tools/call",
          evidence: redact(snippet(text), this.patterns),
          description:
            "A tool returned data matching a known credential format. An agent ingesting this result would learn a live secret, and it may be logged or forwarded onward.",
          remediation:
            "Ensure the server never includes credentials, tokens or private keys in tool output.",
          ts: flow.ts,
        });
      }
    }
  }
}

/** Phrases that read as instructions to the agent rather than documentation. */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|messages?)/i,
  /disregard\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|earlier)/i,
  /\bsystem\s+prompt\b/i,
  /\byou\s+must\s+(?:now|always|never)\b/i,
  /do\s+not\s+(?:tell|mention|inform|reveal|disclose)\b/i,
  /\boverride\b[^.\n]{0,40}\binstructions?\b/i,
  /\bimportant\b\s*:?[^.\n]{0,20}\byou\s+must\b/i,
];

/** Unicode directional-override / bidi controls used to hide text. */
const RTL_CHARS = /[‪-‮⁦-⁩‎‏؜]/;

/** `injection-marker-in-description`: imperative/override phrasing or bidi
 *  control chars in a tools/list description → tool-poisoning (high). */
export class InjectionMarkerInDescriptionDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (resolvedMethod(flow) !== "tools/list") return;
    const tools = flow.json?.result?.tools;
    if (!Array.isArray(tools)) return;
    for (const t of tools) {
      if (!t || typeof t !== "object") continue;
      const desc = typeof t.description === "string" ? (t.description as string) : "";
      if (!desc) continue;
      const matched = RTL_CHARS.test(desc) || INJECTION_PATTERNS.some((re) => re.test(desc));
      if (matched) {
        sink.add({
          id: "tool-poisoning",
          severity: "high",
          title: `Instruction-like content in tool description: ${t.name ?? "(unnamed)"}`,
          direction: flow.direction,
          method: "tools/list",
          tool: typeof t.name === "string" ? t.name : undefined,
          evidence: snippet(desc),
          description:
            "A tool description contains imperative/override phrasing or bidirectional control characters. Descriptions are fed to the agent, so this is a prompt-injection (tool-poisoning) vector.",
          remediation:
            "Treat the server as untrusted; descriptions should be plain documentation, not instructions to the model.",
          ts: flow.ts,
        });
      }
    }
  }
}

/** Names/descriptions suggesting a high-impact capability. Boundaries use
 *  [a-z0-9] (not \b) so an underscore counts as a separator — "exec_shell"
 *  matches "exec" while "execute" does not. */
const DANGEROUS = /(?<![a-z0-9])(?:exec|shell|eval|delete|send_email|http)(?![a-z0-9])/i;

/** `dangerous-tool`: a tool whose name or description matches a high-impact
 *  keyword → dangerous-tool (info). Advisory, not a vulnerability by itself. */
export class DangerousToolDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (resolvedMethod(flow) !== "tools/list") return;
    const tools = flow.json?.result?.tools;
    if (!Array.isArray(tools)) return;
    for (const t of tools) {
      if (!t || typeof t !== "object") continue;
      const name = typeof t.name === "string" ? (t.name as string) : "";
      const desc = typeof t.description === "string" ? (t.description as string) : "";
      const hit = DANGEROUS.exec(name) ?? DANGEROUS.exec(desc);
      if (hit) {
        sink.add({
          id: "dangerous-tool",
          severity: "info",
          title: `Potentially dangerous tool: ${name || "(unnamed)"}`,
          direction: flow.direction,
          method: "tools/list",
          tool: name || undefined,
          evidence: `matched "${hit[0]}"`,
          description:
            "A tool advertises a high-impact capability (command execution, deletion, email/HTTP egress). Review whether the agent should be able to reach it unsupervised.",
          ts: flow.ts,
        });
      }
    }
  }
}

/** `sampling-request`: a server->client sampling/createMessage request →
 *  sampling-abuse (info). The server is asking the client to run an LLM. */
export class SamplingRequestDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (flow.method !== "sampling/createMessage") return;
    sink.add({
      id: "sampling-abuse",
      severity: "info",
      title: "Server requested an LLM completion (sampling/createMessage)",
      direction: flow.direction,
      method: "sampling/createMessage",
      description:
        "The server asked the client to run a model completion on its behalf. Sampling lets a server influence the model directly; review the prompt it supplies.",
      ts: flow.ts,
    });
  }
}

/** The default passive linter set. */
export function builtinLinters(): Detector[] {
  return [
    new SecretInResultDetector(),
    new InjectionMarkerInDescriptionDetector(),
    new DangerousToolDetector(),
    new SamplingRequestDetector(),
  ];
}
