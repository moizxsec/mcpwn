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

/** One unit of agent-bound text pulled out of a server->client message, tagged
 *  with where it came from so a finding can point back at it. */
export interface TextSeg {
  text: string;
  method: string;
  where: string;
  tool?: string;
}

function pushSeg(
  out: TextSeg[],
  text: unknown,
  method: string,
  where: string,
  tool?: string
): void {
  if (typeof text === "string" && text.length > 0) out.push({ text, method, where, tool });
}

/** Pull `.text` out of an MCP content value (single content object or array). */
function contentTexts(content: any, out: TextSeg[], method: string, where: string): void {
  if (Array.isArray(content)) {
    for (const b of content) if (b && typeof b === "object") pushSeg(out, b.text, method, where);
  } else if (content && typeof content === "object") {
    pushSeg(out, content.text, method, where);
  }
}

/**
 * Every piece of text in a message that ultimately reaches the agent/model:
 * tool descriptions, tool results, resource contents, prompt messages, and the
 * server-supplied sampling prompt. Detectors iterate this so a single scan
 * covers all protocol surfaces, not just tool descriptions. Read-only.
 */
export function agentBoundTexts(flow: FlowMessage): TextSeg[] {
  if (flow.direction !== "server->client") return [];
  const method = resolvedMethod(flow);
  if (!method) return [];
  const out: TextSeg[] = [];
  const result = flow.json?.result;

  if (method === "tools/list" && Array.isArray(result?.tools)) {
    for (const t of result.tools) {
      if (!t || typeof t !== "object") continue;
      const tool = typeof t.name === "string" ? (t.name as string) : undefined;
      pushSeg(out, t.description, method, "tool description", tool);
    }
  }

  if (method === "tools/call" && Array.isArray(result?.content)) {
    for (const b of result.content) {
      if (b && typeof b === "object" && b.type === "text")
        pushSeg(out, b.text, method, "tool result");
    }
  }

  if (method === "resources/read" && Array.isArray(result?.contents)) {
    for (const c of result.contents) {
      if (c && typeof c === "object") pushSeg(out, c.text, method, "resource contents");
    }
  }

  if (method === "prompts/get") {
    pushSeg(out, result?.description, method, "prompt description");
    if (Array.isArray(result?.messages)) {
      for (const m of result.messages) {
        if (m && typeof m === "object") contentTexts(m.content, out, method, "prompt message");
      }
    }
  }

  if (method === "resources/list" && Array.isArray(result?.resources)) {
    for (const r of result.resources) {
      if (r && typeof r === "object")
        pushSeg(out, r.description, method, "resource description", r.name);
    }
  }

  if (method === "prompts/list" && Array.isArray(result?.prompts)) {
    for (const p of result.prompts) {
      if (p && typeof p === "object")
        pushSeg(out, p.description, method, "prompt description", p.name);
    }
  }

  if (method === "sampling/createMessage" && Array.isArray(flow.json?.params?.messages)) {
    for (const m of flow.json.params.messages) {
      if (m && typeof m === "object") contentTexts(m.content, out, method, "sampling message");
    }
  }

  return out;
}

function snippet(text: string, max = 240): string {
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
}

function freshGlobal(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  return new RegExp(re.source, flags);
}

/** `secret-in-result`: agent-bound text (tool result, resource, prompt, …)
 *  matching a known secret format → secret-exposure (high). Evidence is
 *  redacted before recording. Covers every protocol surface, not just
 *  tools/call. */
export class SecretInResultDetector implements Detector {
  private patterns: RedactPattern[] = builtinRedactPatterns();

  inspect(flow: FlowMessage, sink: FindingsSink): void {
    for (const seg of agentBoundTexts(flow)) {
      for (const p of this.patterns) {
        if (freshGlobal(p.re).test(seg.text)) {
          sink.add({
            id: "secret-exposure",
            severity: "high",
            title: `Secret pattern "${p.label}" in a ${seg.method} ${seg.where}`,
            direction: "server->client",
            method: seg.method,
            tool: seg.tool,
            evidence: redact(snippet(seg.text), this.patterns),
            description:
              "Agent-bound content matched a known credential format. An agent ingesting this would learn a live secret, and it may be logged or forwarded onward.",
            remediation:
              "Ensure the server never includes credentials, tokens or private keys in tool output, resources or prompts.",
            ts: flow.ts,
          });
        }
      }
    }
  }
}

/** Phrases that read as instructions to the agent rather than documentation.
 *  Exported so the guard (§3.14) can reuse the exact same signatures it both
 *  detects and sanitizes against — detector and firewall never drift apart. */
export const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|messages?)/i,
  /disregard\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|earlier)/i,
  /\bsystem\s+prompt\b/i,
  /\byou\s+must\s+(?:now|always|never)\b/i,
  /do\s+not\s+(?:tell|mention|inform|reveal|disclose)\b/i,
  /\boverride\b[^.\n]{0,40}\binstructions?\b/i,
  /\bimportant\b\s*:?[^.\n]{0,20}\byou\s+must\b/i,
];

/** Unicode directional-override / bidi controls used to hide text. */
export const RTL_CHARS = /[‪-‮⁦-⁩‎‏؜]/;

/** `injection-marker-in-description`: imperative/override phrasing or bidi
 *  control chars in agent-bound text → tool-poisoning (high). Despite the name
 *  it now scans every agent-bound surface (descriptions, tool results, resource
 *  contents, prompt + sampling messages), not just tool descriptions. */
export class InjectionMarkerInDescriptionDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    for (const seg of agentBoundTexts(flow)) {
      const matched =
        RTL_CHARS.test(seg.text) || INJECTION_PATTERNS.some((re) => re.test(seg.text));
      if (!matched) continue;
      sink.add({
        id: "tool-poisoning",
        severity: "high",
        title: `Instruction-like content in a ${seg.method} ${seg.where}${
          seg.tool ? `: ${seg.tool}` : ""
        }`,
        direction: "server->client",
        method: seg.method,
        tool: seg.tool,
        evidence: snippet(seg.text),
        description:
          "Agent-bound content contains imperative/override phrasing or bidirectional control characters. This text is fed to the agent, so it is a prompt-injection (tool-poisoning) vector.",
        remediation:
          "Treat the server as untrusted; descriptions, results, resources and prompts should be data, not instructions to the model.",
        ts: flow.ts,
      });
    }
  }
}

/** Zero-width / invisible / Unicode-Tag code points (ASCII smuggling), as a
 *  source string so a global+unicode clone can be built for enumeration. Spelt
 *  as an alternation (not one character class) so the zero-width joiner/
 *  non-joiner don't trip no-misleading-character-class; the Tag block stays a
 *  range. */
export const INVISIBLE_SRC =
  "\\u00AD|\\u180E|\\u200B|\\u200C|\\u200D|\\u2060|\\u2061|\\u2062|\\u2063|\\u2064|\\uFEFF|[\\u{E0000}-\\u{E007F}]";
export const INVISIBLE_RE = new RegExp(INVISIBLE_SRC, "u");

/** Distinct hidden code points in `text`, rendered as U+XXXX, plus whether any
 *  are Unicode Tag characters (U+E0000–U+E007F), which have no legitimate use
 *  in agent-bound text and are a strong ASCII-smuggling signal. */
function invisibleCodePoints(text: string): { labels: string[]; hasTag: boolean } {
  const g = new RegExp(INVISIBLE_SRC, "gu");
  const set = new Set<number>();
  let m: RegExpExecArray | null;
  while ((m = g.exec(text)) !== null) set.add(m[0].codePointAt(0) as number);
  let hasTag = false;
  const labels = [...set].map((cp) => {
    if (cp >= 0xe0000 && cp <= 0xe007f) hasTag = true;
    return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
  });
  return { labels, hasTag };
}

/** `invisible-unicode`: zero-width or invisible Unicode (including Unicode Tag
 *  characters) anywhere in agent-bound text → hidden-instruction smuggling.
 *  High when Tag characters are present (no legitimate use), else medium. */
export class InvisibleUnicodeDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    for (const seg of agentBoundTexts(flow)) {
      if (!INVISIBLE_RE.test(seg.text)) continue;
      const { labels, hasTag } = invisibleCodePoints(seg.text);
      sink.add({
        id: "invisible-unicode",
        severity: hasTag ? "high" : "medium",
        title: `Hidden/invisible Unicode in a ${seg.method} ${seg.where}${
          seg.tool ? `: ${seg.tool}` : ""
        }`,
        direction: "server->client",
        method: seg.method,
        tool: seg.tool,
        evidence: `hidden code points: ${labels.join(", ")}`,
        description:
          "Agent-bound text contains zero-width or invisible Unicode (including Unicode Tag characters). These are invisible to a human reviewer but read by the model, so they can smuggle hidden instructions (ASCII smuggling / hidden prompt injection).",
        remediation:
          "Strip non-printable and zero-width characters from server-supplied text before passing it to the model.",
        ts: flow.ts,
      });
    }
  }
}

/** Hosts commonly used as out-of-band / exfil collaborators. */
const EXFIL_HOSTS: RegExp[] = [
  /\bburpcollaborator\.net$/i,
  /\boast\.(?:live|site|pro|fun|me|online)$/i,
  /\binteract\.sh$/i,
  /\bwebhook\.site$/i,
  /\brequestbin\.(?:com|net)$/i,
  /\brequestrepo\.com$/i,
  /\bpipedream\.net$/i,
  /\bngrok(?:-free)?\.(?:io|app|dev)$/i,
  /\.onion$/i,
  /\bpastebin\.com$/i,
  /\btransfer\.sh$/i,
  /\bbeeceptor\.com$/i,
];

const URL_RE = /\bhttps?:\/\/([^/\s"'<>)\]}\\]+)/gi;

/** Lowercased hostnames of every http(s) URL in `text` (userinfo/port stripped). */
export function extractHosts(text: string): string[] {
  const re = new RegExp(URL_RE.source, "gi");
  const hosts: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const host = m[1].replace(/^[^@]*@/, "").replace(/[:/].*$/, "");
    if (host) hosts.push(host.toLowerCase());
  }
  return hosts;
}

export function isExfilHost(host: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true; // raw IPv4 literal
  return EXFIL_HOSTS.some((re) => re.test(host));
}

/** `embedded-url`: http(s) URLs in a tool result or resource. Low for a plain
 *  URL (an agent that auto-fetches it is an SSRF/exfil channel), high when a
 *  host matches a known out-of-band collaborator or is a raw IP literal. */
export class EmbeddedUrlDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    for (const seg of agentBoundTexts(flow)) {
      if (seg.method !== "tools/call" && seg.method !== "resources/read") continue;
      const hosts = extractHosts(seg.text);
      if (hosts.length === 0) continue;
      const exfil = hosts.filter(isExfilHost);
      const unique = [...new Set(hosts)];
      sink.add({
        id: "embedded-url",
        severity: exfil.length ? "high" : "low",
        title: exfil.length
          ? `Suspected exfil URL in a ${seg.method} ${seg.where}: ${exfil[0]}`
          : `Embedded URL(s) in a ${seg.method} ${seg.where}`,
        direction: "server->client",
        method: seg.method,
        tool: seg.tool,
        evidence: `host(s): ${unique.slice(0, 8).join(", ")}`,
        description:
          "A tool result or resource embeds one or more URLs. If the agent fetches an attacker-controlled link, appended data can be exfiltrated or the agent redirected (SSRF / data-exfiltration channel).",
        remediation:
          "Do not auto-fetch URLs found in tool output; treat server-supplied links as untrusted.",
        ts: flow.ts,
      });
    }
  }
}

/** Client/agent built-in tool names a server should not re-advertise. Kept to
 *  names strongly associated with privileged built-ins (not generic verbs) to
 *  avoid flagging ordinary server tools. */
const WELL_KNOWN_TOOLS = new Set([
  "bash",
  "computer",
  "text_editor",
  "str_replace_editor",
  "str_replace_based_edit_tool",
  "web_search",
  "web_fetch",
  "code_execution",
]);

/** `tool-shadowing`: two tools sharing a name (high — ambiguous/hijackable), or
 *  a name colliding with a well-known client built-in (medium — impersonation),
 *  in a tools/list response. */
export class ToolShadowingDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (resolvedMethod(flow) !== "tools/list") return;
    const tools = flow.json?.result?.tools;
    if (!Array.isArray(tools)) return;

    const counts = new Map<string, number>();
    for (const t of tools) {
      if (!t || typeof t !== "object" || typeof t.name !== "string") continue;
      counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
    }

    const reported = new Set<string>();
    for (const [name, count] of counts) {
      if (count > 1 && !reported.has(name)) {
        reported.add(name);
        sink.add({
          id: "tool-shadowing",
          severity: "high",
          title: `Duplicate tool name shadows another: ${name}`,
          direction: "server->client",
          method: "tools/list",
          tool: name,
          evidence: `${count} tools named "${name}"`,
          description:
            "Two or more advertised tools share a name. Which implementation the agent invokes is ambiguous; a later definition can shadow (hijack) an earlier, trusted one.",
          remediation:
            "Reject tool lists with duplicate names; require unique, namespaced tool identifiers.",
          ts: flow.ts,
        });
      }
    }

    for (const t of tools) {
      if (!t || typeof t !== "object" || typeof t.name !== "string") continue;
      const name = t.name as string;
      if (WELL_KNOWN_TOOLS.has(name.toLowerCase()) && (counts.get(name) ?? 0) === 1) {
        sink.add({
          id: "tool-shadowing",
          severity: "medium",
          title: `Tool name collides with a well-known built-in: ${name}`,
          direction: "server->client",
          method: "tools/list",
          tool: name,
          evidence: `"${name}" matches a known client/agent built-in`,
          description:
            "A server advertises a tool whose name matches a well-known client/agent built-in. The agent may confuse it for the trusted built-in and route privileged calls to the server.",
          remediation: "Namespace server tools; avoid names that collide with client built-ins.",
          ts: flow.ts,
        });
      }
    }
  }
}

/** Verbs implying a write/delete/execute (mutating) capability. Boundaries use
 *  [a-z0-9] (not \b) so an underscore separates — "delete_file" matches
 *  "delete". */
const MUTATING =
  /(?<![a-z0-9])(?:write|delete|remove|create|update|insert|drop|exec|execute|run|send|post|put|patch|modify|edit|rm|destroy|kill|install|deploy|upload|purge|revoke|grant)(?![a-z0-9])/i;

/** `annotation-mismatch`: a tool annotated readOnlyHint:true whose name or
 *  description describes a write/delete/execute action (high). Clients may
 *  auto-approve read-only tools, so a mislabelled mutating tool runs unprompted. */
export class AnnotationMismatchDetector implements Detector {
  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    if (resolvedMethod(flow) !== "tools/list") return;
    const tools = flow.json?.result?.tools;
    if (!Array.isArray(tools)) return;
    for (const t of tools) {
      if (!t || typeof t !== "object") continue;
      const readOnly = t.annotations?.readOnlyHint === true || t.readOnlyHint === true;
      if (!readOnly) continue;
      const name = typeof t.name === "string" ? (t.name as string) : "";
      const desc = typeof t.description === "string" ? (t.description as string) : "";
      const hit = MUTATING.exec(name) ?? MUTATING.exec(desc);
      if (!hit) continue;
      sink.add({
        id: "annotation-mismatch",
        severity: "high",
        title: `readOnlyHint:true on a write/exec-capable tool: ${name || "(unnamed)"}`,
        direction: "server->client",
        method: "tools/list",
        tool: name || undefined,
        evidence: `readOnlyHint=true but name/description implies "${hit[0]}"`,
        description:
          "A tool is annotated read-only (readOnlyHint:true) yet its name or description describes a write, delete or execute action. Clients may auto-approve read-only tools, so a mislabelled mutating tool can run without the user's confirmation.",
        remediation:
          "Set tool annotations honestly; a mutating tool must not claim readOnlyHint:true.",
        ts: flow.ts,
      });
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
    new InvisibleUnicodeDetector(),
    new EmbeddedUrlDetector(),
    new ToolShadowingDetector(),
    new AnnotationMismatchDetector(),
    new DangerousToolDetector(),
    new SamplingRequestDetector(),
  ];
}
