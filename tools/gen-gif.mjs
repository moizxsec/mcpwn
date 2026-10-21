#!/usr/bin/env node
/**
 * Render the README demo as a GIF, fully headless (pureimage -> PNG frames
 * -> ffmpeg). No terminal recorder, no browser, reproducible in CI. This is
 * the SINGLE source of truth for assets/demo.gif.
 *
 * The frame is a macOS-style terminal window (traffic-light dots, centred
 * title, rounded dark chrome) drawn in mcpwn's own report.ts palette. The body
 * is the ACTUAL stderr of a real `mcpwn scan --fuzz` run against a bundled
 * DVMCP server, revealed one line at a time and coloured to mirror mcpwn's
 * output. The findings table under the summary is derived from the real
 * findings.json the same scan writes, with CWEs read from the canonical
 * advisory table. Nothing is hand-authored: edit the scan, re-run, re-render.
 *
 *   # capture a FRESH real run AND render it (the default):
 *   node tools/gen-gif.mjs                 # == npm run gif
 *
 *   # just refresh the transcript (no font / ffmpeg needed, used by the CI
 *   # drift check to detect a stale demo without flaky image comparisons):
 *   node tools/gen-gif.mjs --capture-only
 *
 *   # render from an existing transcript, no re-capture:
 *   node tools/gen-gif.mjs --no-capture
 *   node tools/gen-gif.mjs --from <transcript>
 *
 *   node tools/gen-gif.mjs [--font /path/to/Mono.ttf] [--out assets/demo.gif]
 *
 * Fonts: JetBrains Mono Regular + Bold ship committed under tools/fonts/ (they
 * are excluded from the npm tarball via package.json `files`), so CI renders
 * the same glyphs offline. Requires ffmpeg on PATH and (for capture) a built
 * dist/. POSIX-only capture (like the demo e2e); on Windows pre-capture a
 * transcript and pass --no-capture / --from.
 */
import * as PImage from "pureimage";
import { spawnSync } from "node:child_process";
import {
  createWriteStream,
  mkdtempSync,
  existsSync,
  rmSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}
const hasFlag = (name) => process.argv.includes(name);

const outPath = arg("--out", join(root, "assets", "demo.gif"));
const fromPath = arg("--from", join(root, "assets", ".demo-transcript.txt"));
const fromExplicit = process.argv.includes("--from");
const noCapture = hasFlag("--no-capture");
const captureOnly = hasFlag("--capture-only");

// The scenario: a real active scan of the DVMCP command-injection server. It
// yields the richest honest spread (several highs across distinct detectors,
// plus a low and an info), so the summary + findings table read like a real
// engagement rather than a toy.
const DVMCP_SERVER = "examples/dvmcp/command-injection.mjs";
const SCAN_ARGV = ["scan", "--fuzz", "--"];
const SCAN_CMD = `mcpwn scan --fuzz -- node ${DVMCP_SERVER}`;
// How many fuzz "hit" blocks (C->S / server note / S->C) to show. The run emits
// one per command-injection payload; two is enough to show the fuzzer working
// without a wall of near-identical lines.
const NOTES_KEPT = 2;
// How many findings to tabulate under the summary (deduped by id, highest
// severity first). The summary line still reports the full counts.
const FINDING_ROWS = 4;

/** Severity sort: most severe first, mirroring findings.ts. */
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Read the real findings.json a scan wrote and reduce it to a small, stable
 *  table: one row per finding id (keeping its most severe hit), ordered by
 *  severity then id, capped at FINDING_ROWS. CWEs come from the canonical
 *  advisory table (dist/advisory.js), so the rows are never hand-authored. */
async function findingRows(findingsDir) {
  let findings = [];
  try {
    findings = JSON.parse(readFileSync(join(findingsDir, "findings.json"), "utf8"));
  } catch {
    return [];
  }
  let advisoryFor = () => undefined;
  try {
    const mod = await import(pathToFileURL(join(root, "dist", "advisory.js")).href);
    if (typeof mod.advisoryFor === "function") advisoryFor = mod.advisoryFor;
  } catch {
    /* no advisory table -> rows carry id + severity only */
  }
  const best = new Map();
  for (const f of findings) {
    if (!f || typeof f.id !== "string" || typeof f.severity !== "string") continue;
    const prev = best.get(f.id);
    if (!prev || (SEV_RANK[f.severity] ?? 9) < (SEV_RANK[prev.severity] ?? 9)) best.set(f.id, f);
  }
  const chosen = [...best.values()]
    .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || a.id.localeCompare(b.id))
    .slice(0, FINDING_ROWS);
  return chosen.map((f) => {
    const adv = advisoryFor(f.id);
    const cwe = adv ? adv.cwe : "";
    return `  ${f.severity.padEnd(6)}${f.id.padEnd(18)}${cwe}`;
  });
}

/** Keep only the engagement-relevant lines of a real scan, in wire order:
 *  the banner/handshake, the enumerated surface, a couple of fuzz hits (the
 *  server note with its surrounding C->S / S->C), the "wrote N findings" line
 *  and the summary block. Deterministic given the (deterministic) scan output,
 *  so --capture-only reproduces the committed transcript byte for byte. */
function selectScanLines(lines) {
  const out = [`$ ${SCAN_CMD}`];
  let notes = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^mcpwn: scanning\b/.test(l)) out.push(l);
    else if (/^mcpwn: handshake ok\b/.test(l)) out.push(l);
    else if (/^[CS].[CS] initialize\b/.test(l)) out.push(l);
    else if (/^[CS].[CS] tools\/list\b/.test(l)) out.push(l);
    else if (/^\[dvmcp-/.test(l) && notes < NOTES_KEPT) {
      const prev = lines[i - 1];
      const next = lines[i + 1];
      if (prev && /^C.S tools\/call\b/.test(prev)) out.push(prev);
      out.push(l);
      if (next && /^S.C tools\/call\b/.test(next)) out.push(next);
      notes++;
    }
  }
  const wrote = lines.find((l) => /^mcpwn: wrote \d+ finding/.test(l));
  if (wrote) out.push(wrote.replace(/->.*$/, "-> findings/"));
  const sIdx = lines.findIndex((l) => /^mcpwn scan summary\b/.test(l));
  if (sIdx >= 0) {
    out.push("");
    for (let j = sIdx; j < lines.length; j++) {
      out.push(lines[j]);
      if (/^\s+fail-on:/.test(lines[j])) break;
    }
  }
  return out;
}

/**
 * Run the REAL scan and write a curated transcript to `toPath`. Combines
 * stdout + stderr in wire order via a shell (`2>&1`) so the frames mirror a
 * live session; the summary + per-message log all go to stderr. The scan also
 * writes its findings to a temp dir, which we read back to build the findings
 * table. POSIX-only.
 */
async function captureTranscript(toPath) {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-scan-"));
  const findingsDir = join(work, "findings");
  const argv = [
    "dist/cli.js",
    ...SCAN_ARGV.slice(0, -1),
    "--findings-out",
    findingsDir,
    "--",
    "node",
    DVMCP_SERVER,
  ];
  const quoted = argv.map((a) => (/[^A-Za-z0-9_./-]/.test(a) ? `'${a}'` : a)).join(" ");
  const r = spawnSync("sh", ["-c", `node ${quoted} 2>&1`], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.error) throw new Error(`could not run scan: ${r.error.message}`);
  const all = (r.stdout ?? "").replace(/\r/g, "").split("\n");
  const kept = selectScanLines(all);
  if (kept.length <= 1) {
    rmSync(work, { recursive: true, force: true });
    throw new Error("scan produced no transcript (is dist/ built?)");
  }
  const rows = await findingRows(findingsDir);
  rmSync(work, { recursive: true, force: true });
  const script = rows.length ? [...kept, "", ...rows] : kept;
  while (script.length && script[script.length - 1].trim() === "") script.pop();
  writeFileSync(toPath, script.join("\n") + "\n");
}

// --capture-only: refresh the transcript and stop (no font / ffmpeg required).
if (captureOnly) {
  await captureTranscript(fromPath);
  console.log(`captured transcript -> ${fromPath}`);
  process.exit(0);
}

// --- fonts (only needed for rendering) -------------------------------------
// JetBrains Mono ships committed under tools/fonts/ so CI renders the same
// glyphs offline. A system/DejaVu fallback keeps a bare checkout rendering.
const BUNDLED_REG = join(here, "fonts", "JetBrainsMono-Regular.ttf");
const BUNDLED_BOLD = join(here, "fonts", "JetBrainsMono-Bold.ttf");
const REG_CANDIDATES = [
  arg("--font", null),
  BUNDLED_REG,
  "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
  "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
  "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
].filter(Boolean);
const regPath = REG_CANDIDATES.find((p) => existsSync(p));
if (!regPath) {
  console.error("No monospace TTF found. Pass --font <path> (or use --capture-only).");
  process.exit(1);
}
const BOLD_CANDIDATES = [
  BUNDLED_BOLD,
  "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf",
  "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
  "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
  regPath, // last resort: reuse the regular face so bold lines still render
].filter((p) => existsSync(p));
const boldPath = BOLD_CANDIDATES[0];
PImage.registerFont(regPath, "mono").loadSync();
PImage.registerFont(boldPath, "monob").loadSync();

// --- layout (final/1x px; everything is rendered at SCALE then downscaled) --
const SCALE = 2; // supersample for crisp text + smooth rounded corners
const PT = 13; // body font size
const TITLE_PT = 12;
const LH = 22; // line height
const PADX = 28; // window inner horizontal padding
const PADTOP = 18; // gap under the title bar
const PADBOT = 20; // gap under the last line
const TITLEBAR = 38; // title bar height
const MARGIN = 18; // backdrop around the window
const RADIUS = 11; // window corner radius
const TITLE = "mcpwn - Burp Suite for AI agents";

// Palette, verbatim from src/report.ts (GitHub dark + severity scale).
const COL = {
  backdrop: "#010409",
  body: "#0d1117",
  bar: "#161b22",
  border: "#30363d",
  fg: "#c9d1d9",
  muted: "#8b949e",
  accent: "#58a6ff",
  c2s: "#56d4dd",
  s2c: "#3fb950",
  high: "#ff7b43",
  medium: "#d29922",
  low: "#3fb950",
  info: "#58a6ff",
  critical: "#f85149",
  dot1: "#ff5f57",
  dot2: "#febc2e",
  dot3: "#28c840",
};

const px = (n) => Math.round(n * SCALE);
const font = (pt, bold) => `${pt * SCALE}pt ${bold ? "monob" : "mono"}`;

/** Measure the real per-glyph advance (monospace, so one advance fits all). */
function measureCharW() {
  const ctx = PImage.make(10, 10).getContext("2d");
  ctx.font = font(PT, false);
  const probe = "M".repeat(40);
  return ctx.measureText(probe).width / probe.length;
}
const charW = measureCharW(); // already in SCALE px

// Capture a fresh transcript by default; opt out with --no-capture / --from.
if (!fromExplicit && !noCapture) {
  await captureTranscript(fromPath);
}
if (!existsSync(fromPath)) {
  console.error(
    `No transcript at ${fromPath}. Capture a real run first:\n` +
      `  node tools/gen-gif.mjs            # captures + renders\n` +
      `  node tools/gen-gif.mjs --from <transcript>`
  );
  process.exit(1);
}

// --- script (coloured view of the real transcript) -------------------------

/** Classify a real line for colour/weight. Cosmetic only, the text is the
 *  program's actual output (or rows derived from its real findings). */
function classify(text) {
  const sev = /^ {2}(critical|high|medium|low|info)\b/.exec(text);
  if (sev) return { kind: "finding", color: COL[sev[1]], bold: false };
  if (/^\$ /.test(text)) return { kind: "prompt", color: COL.accent, bold: true };
  if (/^C.S /.test(text)) return { kind: "line", color: COL.c2s, bold: false };
  if (/^S.C /.test(text)) return { kind: "line", color: COL.s2c, bold: false };
  if (/^\[dvmcp-/.test(text)) return { kind: "line", color: COL.medium, bold: false };
  if (/^mcpwn scan summary$/.test(text)) return { kind: "line", color: COL.fg, bold: true };
  if (/^mcpwn: /.test(text)) return { kind: "line", color: COL.muted, bold: false };
  if (/^\s+(surfaces|findings|fail-on):/.test(text)) return { kind: "line", color: COL.muted, bold: false };
  return { kind: "line", color: COL.fg, bold: false };
}

const raw = readFileSync(fromPath, "utf8").replace(/\r/g, "").split("\n");
while (raw.length && raw[raw.length - 1].trim() === "") raw.pop();
const SCRIPT = raw.map((text) => ({ text, ...classify(text) }));

const COLS = Math.max(TITLE.length + 6, ...SCRIPT.map((l) => l.text.length));
const windowW = PADX * SCALE * 2 + Math.ceil(COLS * charW);
let W = windowW + MARGIN * SCALE * 2;
if (W % 2) W += 1; // keep the downscaled width even
const bodyTop = (MARGIN + TITLEBAR) * SCALE;
const firstBaseline = bodyTop + PADTOP * SCALE + PT * SCALE;
let H = bodyTop + (PADTOP + PADBOT) * SCALE + SCRIPT.length * LH * SCALE + MARGIN * SCALE;
if (H % 2) H += 1;

/** Rounded-rect path (pureimage lacks arcTo; roundRect is implemented). */
function roundRectPath(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.roundRect(x, y, w, h, r);
}

function drawChrome(ctx) {
  ctx.fillStyle = COL.backdrop;
  ctx.fillRect(0, 0, W, H);
  const x = MARGIN * SCALE;
  const y = MARGIN * SCALE;
  const w = W - MARGIN * SCALE * 2;
  const h = H - MARGIN * SCALE * 2;
  const r = RADIUS * SCALE;
  // window body
  roundRectPath(ctx, x, y, w, h, r);
  ctx.fillStyle = COL.body;
  ctx.fill();
  // title bar (clip to the rounded top so its corners match the window)
  ctx.save();
  roundRectPath(ctx, x, y, w, h, r);
  ctx.clip();
  ctx.fillStyle = COL.bar;
  ctx.fillRect(x, y, w, TITLEBAR * SCALE);
  ctx.restore();
  // hairline separator under the bar
  ctx.fillStyle = COL.border;
  ctx.fillRect(x, y + TITLEBAR * SCALE, w, Math.max(1, Math.round(SCALE / 2)));
  // border
  roundRectPath(ctx, x, y, w, h, r);
  ctx.strokeStyle = COL.border;
  ctx.lineWidth = SCALE;
  ctx.stroke();
  // traffic lights
  const dots = [COL.dot1, COL.dot2, COL.dot3];
  const cy = y + (TITLEBAR * SCALE) / 2;
  dots.forEach((d, i) => {
    ctx.fillStyle = d;
    ctx.beginPath();
    ctx.arc(x + (PADX - 2) * SCALE + i * 20 * SCALE, cy, 6 * SCALE, 0, Math.PI * 2);
    ctx.fill();
  });
  // centred title
  ctx.font = font(TITLE_PT, true);
  ctx.fillStyle = COL.muted;
  const tw = ctx.measureText(TITLE).width;
  ctx.fillText(TITLE, (W - tw) / 2, cy + TITLE_PT * SCALE * 0.38);
}

function drawLine(ctx, line, baseline) {
  const x = MARGIN * SCALE + PADX * SCALE;
  if (line.kind === "prompt") {
    ctx.font = font(PT, false);
    ctx.fillStyle = COL.accent;
    ctx.fillText("$ ", x, baseline);
    ctx.font = font(PT, true);
    ctx.fillStyle = COL.fg;
    ctx.fillText(line.text.slice(2), x + 2 * charW, baseline);
    return;
  }
  ctx.font = font(PT, line.bold);
  ctx.fillStyle = line.color;
  ctx.fillText(line.text, x, baseline);
}

function drawCursor(ctx, line, baseline) {
  const x = MARGIN * SCALE + PADX * SCALE;
  const endX = x + (line ? line.text.length + 1 : 0) * charW;
  ctx.globalAlpha = 0.85;
  ctx.fillStyle = COL.accent;
  ctx.fillRect(endX, baseline - PT * SCALE, charW, PT * SCALE * 1.15);
  ctx.globalAlpha = 1;
}

// --- frame schedule --------------------------------------------------------
const FPS = 12;
const frames = [];
const push = (n, final, fidx) => frames.push({ n, final: !!final, fidx: fidx ?? 0 });
for (let i = 0; i < 4; i++) push(0); // settle on the empty window
for (let n = 1; n <= SCRIPT.length; n++) {
  const t = SCRIPT[n - 1].text;
  let hold = 2;
  if (t.trim() === "") hold = 1;
  else if (/^mcpwn scan summary$/.test(t)) hold = 5;
  else if (/^\s+findings:/.test(t)) hold = 4;
  else if (SCRIPT[n - 1].kind === "finding") hold = 3;
  for (let i = 0; i < hold; i++) push(n);
}
for (let i = 0; i < 30; i++) push(SCRIPT.length, true, i); // final hold + blink

async function main() {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-gif-"));
  for (let f = 0; f < frames.length; f++) {
    const { n, final, fidx } = frames[f];
    const img = PImage.make(W, H);
    const ctx = img.getContext("2d");
    drawChrome(ctx);
    for (let i = 0; i < n; i++) {
      drawLine(ctx, SCRIPT[i], firstBaseline + i * LH * SCALE);
    }
    // block cursor at the end of the last revealed non-blank line
    let last = n - 1;
    while (last >= 0 && SCRIPT[last].text.trim() === "") last--;
    const blink = final ? Math.floor(fidx / 5) % 2 === 0 : true;
    if (last >= 0 && blink) {
      drawCursor(ctx, SCRIPT[last], firstBaseline + last * LH * SCALE);
    }
    const file = join(work, `f${String(f).padStart(4, "0")}.png`);
    await new Promise((res, rej) => {
      const s = createWriteStream(file);
      PImage.encodePNGToStream(img, s).then(res).catch(rej);
    });
  }

  // ffmpeg: supersampled PNGs -> lanczos downscale -> shared palette GIF.
  const pattern = join(work, "f%04d.png");
  const palette = join(work, "palette.png");
  const outW = Math.round(W / SCALE);
  const scale = `scale=${outW}:-1:flags=lanczos`;
  const run = (args) => {
    const r = spawnSync("ffmpeg", args, { stdio: "ignore" });
    if (r.status !== 0) throw new Error("ffmpeg failed: " + args.join(" "));
  };
  run([
    "-y",
    "-framerate", String(FPS),
    "-i", pattern,
    "-vf", `${scale},palettegen=stats_mode=full`,
    palette,
  ]);
  run([
    "-y",
    "-framerate", String(FPS),
    "-i", pattern,
    "-i", palette,
    "-lavfi", `${scale}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3`,
    outPath,
  ]);

  rmSync(work, { recursive: true, force: true });
  console.log(
    `wrote ${outPath}  (${frames.length} frames @ ${FPS}fps, ${outW}x${Math.round(H / SCALE)}, ` +
      `${SCRIPT.length} lines from ${fromPath})`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
