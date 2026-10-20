import { readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { bySeverity, type Finding, type Severity } from "./findings.js";
import type { Direction } from "./types.js";

/**
 * Static HTML report (§3.5, portfolio artifact).
 *
 *   mcpwn report <session.jsonl> [--findings <dir>] -o report.html
 *
 * Turns a recorded session (the JSONL the proxy writes via --log, see
 * logger.ts) plus an optional findings directory into a SINGLE self-contained
 * HTML file: inline CSS + a tiny vanilla-JS severity filter + an embedded JSON
 * copy of the data. ZERO runtime dependencies, ZERO external resources (no CDN,
 * fonts, or links) — the file opens offline and screenshots cleanly for an
 * advisory. This is a STATIC generated artifact, NOT a live server/UI (README
 * non-goal): nothing here listens, fetches, or executes attacker input.
 *
 * SECURITY: every byte of session/finding content is attacker-controlled (it is
 * literally the traffic under test). Correct HTML-escaping is therefore a
 * security property of this module, not cosmetics — {@link escapeHtml} guards
 * every interpolation into markup and {@link escapeJsonForScript} guards the
 * embedded `<script type="application/json">` blob against `</script>`
 * breakout. The writers are pure string builders (like findings.ts) so the
 * escaping is trivially unit-testable.
 */

/** One line of the session JSONL, as logger.ts writes it. All fields are
 *  optional/tolerant because the report must render a partial or hand-authored
 *  log without throwing. `raw` is the original message; `forwarded` is the exact
 *  bytes put back on the wire (null when dropped) — both are recorded, so tamper
 *  diffs are a real original-vs-tampered comparison, never a guess. */
export interface SessionRecord {
  ts?: number;
  direction?: Direction;
  kind?: string;
  method?: string | null;
  id?: string | number | null;
  applied?: string[];
  dropped?: boolean;
  manualEdit?: boolean;
  raw: string;
  forwarded?: string | null;
}

export interface ReportInput {
  /** Display name for the source session (shown in the header). */
  sessionFile: string;
  records: SessionRecord[];
  findings: Finding[];
  /** mcpwn version string for the header. */
  toolVersion: string;
  /** Override the generated-at timestamp (ms epoch) for deterministic output
   *  in tests. Defaults to now. */
  generatedAt?: number;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// --- escaping (the security-critical core) ---------------------------------

/** HTML-escape text destined for element content or an attribute value. Covers
 *  the five characters that can break out of markup; applied to EVERY piece of
 *  session/finding content before it enters the page. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Make a JSON string safe to embed inside a `<script type="application/json">`
 *  element. JSON.stringify does not escape `<`, so a payload containing
 *  `</script>` would otherwise close the element and inject markup; neutralise
 *  the three characters that matter (`<`, `>`, `&`). The blob is parsed as JSON,
 *  not executed, so JS-only concerns (U+2028/2029) do not apply here. */
export function escapeJsonForScript(json: string): string {
  return json.replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}

// --- small helpers ----------------------------------------------------------

/** Parse a JSONL session body into records, skipping blank/unparseable lines so
 *  a truncated or hand-edited log still renders. */
export function parseSession(text: string): SessionRecord[] {
  const out: SessionRecord[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const rec = JSON.parse(t) as SessionRecord;
      if (rec && typeof rec.raw === "string") out.push(rec);
    } catch {
      /* skip a corrupt line rather than abort the whole report */
    }
  }
  return out;
}

function truncate(s: string, n: number): string {
  const oneLine = s.replace(/\s+/g, " ").trim();
  return oneLine.length > n ? oneLine.slice(0, n) + "…" : oneLine;
}

/** Pretty-print a JSON-RPC line, or return the raw string if it is not JSON. */
function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function safeParse(raw: string | null | undefined): any {
  if (typeof raw !== "string") return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function arrow(dir: Direction | undefined): string {
  return dir === "server->client" ? "S→C" : "C→S";
}

function dirClass(dir: Direction | undefined): string {
  return dir === "server->client" ? "s2c" : "c2s";
}

/** The tool name a record concerns: `params.name` for a tools/call request, or
 *  the name carried over from its request for the matching response (looked up
 *  in `toolById`). */
function toolNameOf(rec: SessionRecord, toolById: Map<string, string>): string | undefined {
  const json = safeParse(rec.raw);
  const direct = json?.params?.name;
  if (typeof direct === "string") return direct;
  if (rec.id !== undefined && rec.id !== null) {
    const got = toolById.get(JSON.stringify(rec.id));
    if (got) return got;
  }
  return undefined;
}

// --- diff (original vs tampered) -------------------------------------------

interface DiffSpan {
  prefix: string;
  aMid: string;
  bMid: string;
  suffix: string;
}

/** Reduce two strings to a shared prefix, a shared suffix, and the single
 *  differing span in the middle of each. Tamper actions (append / prepend /
 *  replace / match-replace / arg rewrite) each mutate one contiguous region, so
 *  a common-prefix/common-suffix diff isolates exactly what the rule changed —
 *  including the `<INJECTED by mcpwn>` marker, which simply falls inside the
 *  highlighted span. We diff the pretty-printed forms so the result is readable.
 *
 *  NOTE: this is intentionally a coarse single-span diff, not a full LCS — it is
 *  exact for the way mcpwn rules tamper (localized edits) and keeps the report
 *  dependency-free. A rule that scatters many edits would show one enclosing
 *  span rather than several; acceptable for an evidence view. */
function diffSpan(a: string, b: string): DiffSpan {
  const max = Math.min(a.length, b.length);
  let p = 0;
  while (p < max && a[p] === b[p]) p++;
  let s = 0;
  while (s < max - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  return {
    prefix: a.slice(0, p),
    aMid: a.slice(p, a.length - s),
    bMid: b.slice(p, b.length - s),
    suffix: a.slice(a.length - s),
  };
}

// --- narrative --------------------------------------------------------------

interface Narrative {
  server: string;
  messageCount: number;
  tamperedCount: number;
  droppedCount: number;
  findingCount: number;
  highest?: Severity;
  tamperClasses: string[];
  detectorClasses: string[];
  text: string;
}

function buildNarrative(records: SessionRecord[], findings: Finding[]): Narrative {
  let server = "the target MCP server";
  for (const r of records) {
    const j = safeParse(r.raw);
    const info = j?.result?.serverInfo;
    if (info?.name) {
      server = info.version ? `${info.name} v${info.version}` : String(info.name);
      break;
    }
  }

  const tamperClasses = [
    ...new Set(records.flatMap((r) => (Array.isArray(r.applied) ? r.applied : []))),
  ];
  const tamperedCount = records.filter((r) => (r.applied?.length ?? 0) > 0).length;
  const droppedCount = records.filter((r) => r.dropped === true).length;
  const detectorClasses = [...new Set(findings.map((f) => f.id))];
  const highest = findings.length ? bySeverity(findings)[0].severity : undefined;

  const parts: string[] = [];
  parts.push(
    `This report captures ${records.length} JSON-RPC message(s) exchanged with ${server}.`
  );
  if (tamperedCount > 0) {
    parts.push(
      `mcpwn actively tampered ${tamperedCount} message(s)` +
        (droppedCount ? ` (dropping ${droppedCount})` : "") +
        ` using: ${tamperClasses.join(", ")}.`
    );
  } else {
    parts.push("No messages were tampered — this was a passive X-ray of the traffic.");
  }
  if (findings.length) {
    parts.push(
      `${findings.length} finding(s) were recorded` +
        (highest ? `, the most severe rated ${highest}` : "") +
        (detectorClasses.length ? ` (${detectorClasses.join(", ")}).` : ".")
    );
  } else {
    parts.push("No findings were recorded by the passive detectors.");
  }

  return {
    server,
    messageCount: records.length,
    tamperedCount,
    droppedCount,
    findingCount: findings.length,
    highest,
    tamperClasses,
    detectorClasses,
    text: parts.join(" "),
  };
}

// --- section builders -------------------------------------------------------

function renderHeader(
  input: ReportInput,
  nar: Narrative,
  counts: Record<Severity, number>
): string {
  const generated = new Date(input.generatedAt ?? Date.now()).toISOString();
  const chips = SEVERITIES.filter((s) => counts[s] > 0)
    .map((s) => `<span class="chip sev-${s}">${s}: ${counts[s]}</span>`)
    .join("");
  return [
    `<header class="hdr">`,
    `  <h1>mcpwn <span class="ver">v${escapeHtml(input.toolVersion)}</span> report</h1>`,
    `  <dl class="meta">`,
    `    <div><dt>Session</dt><dd class="mono">${escapeHtml(input.sessionFile)}</dd></div>`,
    `    <div><dt>Generated</dt><dd class="mono">${escapeHtml(generated)}</dd></div>`,
    `  </dl>`,
    `  <div class="stats">`,
    `    <span class="stat"><b>${nar.messageCount}</b> messages</span>`,
    `    <span class="stat"><b>${nar.tamperedCount}</b> tampered</span>`,
    `    <span class="stat"><b>${nar.findingCount}</b> findings</span>`,
    `    ${chips}`,
    `  </div>`,
    `</header>`,
  ].join("\n");
}

function renderNarrative(nar: Narrative): string {
  return [
    `<section class="panel">`,
    `  <h2>Attack narrative</h2>`,
    `  <p class="narrative">${escapeHtml(nar.text)}</p>`,
    `</section>`,
  ].join("\n");
}

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return [
      `<section class="panel">`,
      `  <h2>Findings</h2>`,
      `  <p class="muted">No findings recorded.</p>`,
      `</section>`,
    ].join("\n");
  }
  const sorted = bySeverity(findings);
  const filters = ["all", ...SEVERITIES]
    .map(
      (s) =>
        `<button type="button" class="filter" data-filter="${s}" aria-pressed="${
          s === "all" ? "true" : "false"
        }">${s}</button>`
    )
    .join("");

  const rows = sorted
    .map((f) => {
      const meta: string[] = [];
      meta.push(`<div><dt>ID</dt><dd class="mono">${escapeHtml(f.id)}</dd></div>`);
      meta.push(`<div><dt>Severity</dt><dd>${escapeHtml(f.severity)}</dd></div>`);
      if (f.direction)
        meta.push(`<div><dt>Direction</dt><dd>${escapeHtml(arrow(f.direction))}</dd></div>`);
      if (f.method)
        meta.push(`<div><dt>Method</dt><dd class="mono">${escapeHtml(f.method)}</dd></div>`);
      if (f.tool) meta.push(`<div><dt>Tool</dt><dd class="mono">${escapeHtml(f.tool)}</dd></div>`);
      if (f.ts)
        meta.push(
          `<div><dt>Observed</dt><dd class="mono">${escapeHtml(new Date(f.ts).toISOString())}</dd></div>`
        );
      const body: string[] = [`<dl class="kv">${meta.join("")}</dl>`];
      if (f.description) body.push(`<p>${escapeHtml(f.description)}</p>`);
      if (f.evidence)
        body.push(`<h4>Evidence</h4><pre class="evidence">${escapeHtml(f.evidence)}</pre>`);
      if (f.remediation) body.push(`<h4>Remediation</h4><p>${escapeHtml(f.remediation)}</p>`);
      return [
        `  <details class="finding" data-sev="${f.severity}">`,
        `    <summary>`,
        `      <span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span>`,
        `      <span class="fid mono">${escapeHtml(f.id)}</span>`,
        `      <span class="ftitle">${escapeHtml(f.title)}</span>`,
        `    </summary>`,
        `    <div class="body">${body.join("\n      ")}</div>`,
        `  </details>`,
      ].join("\n");
    })
    .join("\n");

  return [
    `<section class="panel">`,
    `  <h2>Findings <span class="count">${sorted.length}</span></h2>`,
    `  <div class="filters" role="group" aria-label="Filter findings by severity">${filters}</div>`,
    rows,
    `</section>`,
  ].join("\n");
}

function renderTimeline(records: SessionRecord[], toolById: Map<string, string>): string {
  const rows = records
    .map((rec, i) => {
      const method = rec.method ?? "(" + (rec.kind ?? "message") + ")";
      const tool = toolNameOf(rec, toolById);
      const idStr = rec.id !== undefined && rec.id !== null ? "#" + JSON.stringify(rec.id) : "";
      const badges: string[] = [];
      if (rec.dropped) badges.push(`<span class="badge drop">dropped</span>`);
      else if ((rec.applied?.length ?? 0) > 0)
        badges.push(`<span class="badge tamper">tampered</span>`);
      if (rec.manualEdit) badges.push(`<span class="badge edit">edited</span>`);
      const preview = truncate(rec.raw, 96);
      return [
        `  <details class="msg" data-dir="${dirClass(rec.direction)}">`,
        `    <summary>`,
        `      <span class="seq">${i + 1}</span>`,
        `      <span class="dir dir-${dirClass(rec.direction)}">${arrow(rec.direction)}</span>`,
        `      <span class="method mono">${escapeHtml(method)}</span>`,
        tool ? `      <span class="tool mono">${escapeHtml(tool)}</span>` : "",
        `      <span class="mid mono">${escapeHtml(idStr)}</span>`,
        badges.length ? `      <span class="badges">${badges.join("")}</span>` : "",
        `      <span class="preview mono">${escapeHtml(preview)}</span>`,
        `    </summary>`,
        `    <pre class="payload">${escapeHtml(pretty(rec.raw))}</pre>`,
        `  </details>`,
      ]
        .filter(Boolean)
        .join("\n");
    })
    .join("\n");

  return [
    `<section class="panel">`,
    `  <h2>Session timeline <span class="count">${records.length}</span></h2>`,
    rows,
    `</section>`,
  ].join("\n");
}

function renderDiffs(records: SessionRecord[], toolById: Map<string, string>): string {
  // A message is diffable when a rule changed its bytes, or when it was dropped.
  const changed = records
    .map((rec, i) => ({ rec, i }))
    .filter(
      ({ rec }) =>
        rec.dropped === true ||
        ((rec.applied?.length ?? 0) > 0 &&
          typeof rec.forwarded === "string" &&
          rec.forwarded !== rec.raw)
    );

  if (changed.length === 0) {
    return [
      `<section class="panel">`,
      `  <h2>Tamper diffs</h2>`,
      `  <p class="muted">No messages were modified in this session.</p>`,
      `</section>`,
    ].join("\n");
  }

  const blocks = changed
    .map(({ rec, i }) => {
      const method = rec.method ?? "(" + (rec.kind ?? "message") + ")";
      const tool = toolNameOf(rec, toolById);
      const rules = (rec.applied ?? []).join(", ") || (rec.dropped ? "drop" : "");
      const label = [
        `#${i + 1}`,
        escapeHtml(method),
        tool ? escapeHtml(tool) : "",
        `<span class="rule mono">${escapeHtml(rules)}</span>`,
      ]
        .filter(Boolean)
        .join(" ");

      if (rec.dropped || typeof rec.forwarded !== "string") {
        return [
          `  <details class="diff" open>`,
          `    <summary>${label} <span class="badge drop">dropped</span></summary>`,
          `    <p class="muted">This message was dropped by a rule — it never reached the wire.</p>`,
          `    <pre class="payload">${escapeHtml(pretty(rec.raw))}</pre>`,
          `  </details>`,
        ].join("\n");
      }

      const d = diffSpan(pretty(rec.raw), pretty(rec.forwarded));
      const pre = escapeHtml(d.prefix);
      const suf = escapeHtml(d.suffix);
      const original = `${pre}<mark class="del">${escapeHtml(d.aMid)}</mark>${suf}`;
      const tampered = `${pre}<mark class="add">${escapeHtml(d.bMid)}</mark>${suf}`;
      return [
        `  <details class="diff" open>`,
        `    <summary>${label}</summary>`,
        `    <div class="diff-cols">`,
        `      <div class="diff-col"><h4>Original (received)</h4><pre class="payload">${original}</pre></div>`,
        `      <div class="diff-col"><h4>Tampered (forwarded)</h4><pre class="payload">${tampered}</pre></div>`,
        `    </div>`,
        `  </details>`,
      ].join("\n");
    })
    .join("\n");

  return [
    `<section class="panel">`,
    `  <h2>Tamper diffs <span class="count">${changed.length}</span></h2>`,
    blocks,
    `</section>`,
  ].join("\n");
}

// --- the page ---------------------------------------------------------------

const STYLE = `
:root {
  --bg: #0d1117; --panel: #161b22; --panel2: #0b0f14; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff; --mono: ui-monospace,
  SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --c2s: #56d4dd; --s2c: #3fb950;
  --crit: #f85149; --high: #ff7b43; --med: #d29922; --low: #3fb950; --info: #58a6ff;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 4rem; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica,
  Arial, sans-serif;
}
.mono { font-family: var(--mono); }
.wrap { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
h2 { font-size: 1.15rem; margin: 0 0 .75rem; border-bottom: 1px solid var(--border);
  padding-bottom: .4rem; }
h4 { margin: .75rem 0 .3rem; color: var(--muted); font-size: .85rem;
  text-transform: uppercase; letter-spacing: .04em; }
.ver { color: var(--muted); font-weight: 400; font-size: 1rem; }
.hdr { border-bottom: 2px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }
.meta { display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 0 0 1rem; }
.meta div { display: flex; gap: .5rem; }
.meta dt { color: var(--muted); margin: 0; }
.meta dd { margin: 0; }
.stats { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: 6px;
  padding: .25rem .6rem; }
.stat b { color: var(--accent); }
.chip { border-radius: 999px; padding: .2rem .65rem; font-size: .8rem; font-weight: 600;
  color: #0d1117; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 1.1rem 1.25rem; margin-bottom: 1.25rem; }
.count { background: var(--panel2); border: 1px solid var(--border); border-radius: 999px;
  font-size: .8rem; padding: 0 .55rem; color: var(--muted); }
.muted { color: var(--muted); }
.narrative { margin: 0; }
.filters { display: flex; gap: .4rem; flex-wrap: wrap; margin-bottom: .9rem; }
.filter { background: var(--panel2); color: var(--text); border: 1px solid var(--border);
  border-radius: 6px; padding: .25rem .7rem; cursor: pointer; font-size: .8rem; }
.filter[aria-pressed="true"] { border-color: var(--accent); color: var(--accent); }
details { border: 1px solid var(--border); border-radius: 6px; margin-bottom: .5rem;
  background: var(--panel2); }
summary { cursor: pointer; padding: .55rem .75rem; display: flex; gap: .6rem;
  align-items: center; flex-wrap: wrap; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary::before { content: "▸"; color: var(--muted); }
details[open] > summary::before { content: "▾"; }
.body { padding: 0 .9rem .9rem 1.7rem; }
.kv { display: flex; flex-wrap: wrap; gap: .4rem 1.4rem; margin: .5rem 0; }
.kv div { display: flex; gap: .4rem; }
.kv dt { color: var(--muted); margin: 0; }
.kv dd { margin: 0; }
.sev, .chip.sev-critical, .sev-critical { }
.sev { border-radius: 4px; padding: .1rem .5rem; font-size: .75rem; font-weight: 700;
  color: #0d1117; text-transform: uppercase; }
.sev-critical, .chip.sev-critical { background: var(--crit); }
.sev-high, .chip.sev-high { background: var(--high); }
.sev-medium, .chip.sev-medium { background: var(--med); }
.sev-low, .chip.sev-low { background: var(--low); }
.sev-info, .chip.sev-info { background: var(--info); }
.fid { color: var(--muted); }
.ftitle { font-weight: 600; }
.seq { color: var(--muted); min-width: 1.8rem; text-align: right; }
.dir { font-weight: 700; font-family: var(--mono); }
.dir-c2s { color: var(--c2s); }
.dir-s2c { color: var(--s2c); }
.method { font-weight: 600; }
.tool { color: var(--accent); }
.mid { color: var(--muted); }
.preview { color: var(--muted); flex: 1 1 14rem; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; font-size: .82rem; }
.badge { border-radius: 4px; padding: .05rem .4rem; font-size: .72rem; font-weight: 600; }
.badge.tamper { background: var(--med); color: #0d1117; }
.badge.drop { background: var(--crit); color: #0d1117; }
.badge.edit { background: var(--accent); color: #0d1117; }
.payload { margin: 0; padding: .75rem; background: #010409; border: 1px solid var(--border);
  border-radius: 0 0 6px 6px; overflow-x: auto; font-family: var(--mono); font-size: .82rem;
  white-space: pre-wrap; word-break: break-word; }
.evidence { margin: 0; padding: .6rem; background: #010409; border: 1px solid var(--border);
  border-radius: 6px; overflow-x: auto; font-family: var(--mono); font-size: .82rem;
  white-space: pre-wrap; word-break: break-word; }
.diff-cols { display: grid; grid-template-columns: 1fr 1fr; gap: .6rem; padding: .5rem .75rem .75rem; }
.diff-col h4 { margin-top: 0; }
mark.del { background: rgba(248,81,73,.28); color: #ffb3ad; border-radius: 2px; }
mark.add { background: rgba(63,185,80,.28); color: #a5e8ad; border-radius: 2px; }
.rule { color: var(--med); }
footer { color: var(--muted); font-size: .8rem; text-align: center; margin-top: 2rem; }
@media (max-width: 720px) { .diff-cols { grid-template-columns: 1fr; } }
`;

const SCRIPT = `
(function () {
  var buttons = document.querySelectorAll("[data-filter]");
  function apply(sev) {
    var items = document.querySelectorAll(".finding[data-sev]");
    for (var i = 0; i < items.length; i++) {
      var show = sev === "all" || items[i].getAttribute("data-sev") === sev;
      items[i].style.display = show ? "" : "none";
    }
    for (var j = 0; j < buttons.length; j++) {
      buttons[j].setAttribute("aria-pressed",
        buttons[j].getAttribute("data-filter") === sev ? "true" : "false");
    }
  }
  for (var k = 0; k < buttons.length; k++) {
    buttons[k].addEventListener("click", function () {
      apply(this.getAttribute("data-filter"));
    });
  }
})();
`;

/** Build the full, self-contained HTML document. Pure: no I/O, no globals. */
export function renderReport(input: ReportInput): string {
  const { records, findings } = input;

  // Pre-pass: map each tools/call request id -> tool name so responses (which
  // carry no name on the wire) can be labelled in the timeline + diffs.
  const toolById = new Map<string, string>();
  for (const rec of records) {
    if (rec.id === undefined || rec.id === null) continue;
    const json = safeParse(rec.raw);
    const name = json?.params?.name;
    if (typeof name === "string") toolById.set(JSON.stringify(rec.id), name);
  }

  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) if (counts[f.severity] !== undefined) counts[f.severity]++;

  const nar = buildNarrative(records, findings);

  // Embedded machine-readable copy of everything, breakout-safe.
  const data = escapeJsonForScript(
    JSON.stringify({
      meta: {
        tool: "mcpwn",
        version: input.toolVersion,
        session: input.sessionFile,
        generatedAt: new Date(input.generatedAt ?? Date.now()).toISOString(),
      },
      records,
      findings,
    })
  );

  return [
    `<!DOCTYPE html>`,
    `<html lang="en">`,
    `<head>`,
    `<meta charset="utf-8">`,
    `<meta name="viewport" content="width=device-width, initial-scale=1">`,
    `<meta name="generator" content="mcpwn report">`,
    `<title>mcpwn report — ${escapeHtml(input.sessionFile)}</title>`,
    `<style>${STYLE}</style>`,
    `</head>`,
    `<body>`,
    `<div class="wrap">`,
    renderHeader(input, nar, counts),
    renderNarrative(nar),
    renderFindings(findings),
    renderDiffs(records, toolById),
    renderTimeline(records, toolById),
    `<footer>Generated by mcpwn — static report, no live services. Authorized testing only.</footer>`,
    `</div>`,
    `<script type="application/json" id="mcpwn-data">${data}</script>`,
    `<script>${SCRIPT}</script>`,
    `</body>`,
    `</html>`,
    ``,
  ].join("\n");
}

// --- CLI --------------------------------------------------------------------

export class ReportArgError extends Error {}

export interface ReportArgs {
  sessionFile?: string;
  findingsPath?: string;
  out?: string;
}

export function parseReportArgs(argv: string[]): ReportArgs {
  const out: ReportArgs = {};
  const value = (flag: string, i: number): [string, number] => {
    const v = argv[i + 1];
    if (v === undefined) throw new ReportArgError(`option ${flag} requires an argument`);
    return [v, i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--findings" || a === "--findings-dir") {
      [out.findingsPath, i] = value(a, i);
      continue;
    }
    if (a === "-o" || a === "--out") {
      [out.out, i] = value(a, i);
      continue;
    }
    if (a.startsWith("-")) {
      throw new ReportArgError(`unknown option "${a}"`);
    }
    if (out.sessionFile === undefined) {
      out.sessionFile = a;
      continue;
    }
    throw new ReportArgError(`unexpected extra argument "${a}"`);
  }
  return out;
}

/** Resolve the mcpwn version from package.json (same source as `--version`). */
function resolveVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    return require("../package.json").version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** Load findings from a directory (findings.json) or a direct .json file. Absent
 *  path → no findings. A missing/invalid file is a hard error (the operator
 *  asked for them). */
function loadFindings(path: string): Finding[] {
  let file = path;
  try {
    if (statSync(path).isDirectory()) file = join(path, "findings.json");
  } catch {
    throw new ReportArgError(`findings path not found: ${path}`);
  }
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  if (!Array.isArray(parsed)) throw new ReportArgError(`${file} is not a findings array`);
  return parsed as Finding[];
}

/** `mcpwn report <session.jsonl> [--findings <dir>] -o report.html`. */
export async function runReport(argv: string[]): Promise<number> {
  let args: ReportArgs;
  try {
    args = parseReportArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn report: ${(err as Error).message}\n`);
    return 2;
  }
  if (!args.sessionFile) {
    process.stderr.write("mcpwn report: missing <session.jsonl>\n");
    return 2;
  }

  let sessionText: string;
  try {
    sessionText = readFileSync(args.sessionFile, "utf8");
  } catch (err) {
    process.stderr.write(
      `mcpwn report: could not read session "${args.sessionFile}": ${(err as Error).message}\n`
    );
    return 2;
  }

  let findings: Finding[] = [];
  if (args.findingsPath) {
    try {
      findings = loadFindings(args.findingsPath);
    } catch (err) {
      process.stderr.write(`mcpwn report: ${(err as Error).message}\n`);
      return 2;
    }
  }

  const html = renderReport({
    sessionFile: args.sessionFile,
    records: parseSession(sessionText),
    findings,
    toolVersion: resolveVersion(),
  });

  if (args.out) {
    try {
      writeFileSync(args.out, html);
    } catch (err) {
      process.stderr.write(
        `mcpwn report: could not write "${args.out}": ${(err as Error).message}\n`
      );
      return 2;
    }
    process.stderr.write(`mcpwn: wrote report -> ${args.out}\n`);
  } else {
    process.stdout.write(html);
  }
  return 0;
}
