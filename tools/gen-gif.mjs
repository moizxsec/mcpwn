#!/usr/bin/env node
/**
 * Render the README demo as a GIF, fully headless (pureimage -> PNG frames
 * -> ffmpeg). No terminal recorder, no browser — reproducible in CI. This is
 * the SINGLE source of truth for assets/demo.gif (the old vhs tape is gone).
 *
 *   # capture a FRESH real run AND render it (the default):
 *   node tools/gen-gif.mjs                 # == npm run gif
 *
 *   # just refresh the transcript (no font / ffmpeg needed — used by the CI
 *   # drift check to detect a stale demo without flaky image comparisons):
 *   node tools/gen-gif.mjs --capture-only
 *
 *   # render from an existing transcript, no re-capture:
 *   node tools/gen-gif.mjs --no-capture
 *   node tools/gen-gif.mjs --from <transcript>
 *
 *   node tools/gen-gif.mjs [--font /path/to/Mono.ttf] [--out assets/demo.gif]
 *
 * The transcript is the ACTUAL stdout/stderr of `examples/run-demo.mjs` — the
 * frames reveal those real lines one at a time, coloured to mirror mcpwn's own
 * output. Nothing is scripted by hand: edit the demo, re-run, re-render.
 * Requires a monospace TTF, ffmpeg on PATH, and (for capture) a built dist/.
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
import { fileURLToPath } from "node:url";

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

/** Sanitise a captured line: never leak the capturing machine's filesystem path. */
function sanitise(line) {
  return line.replace(/^\s{2}proxying:.*$/, "  proxying: node ./examples/vulnerable-server.mjs");
}

/**
 * Run the REAL demo and write its transcript to `toPath`. Combines stdout +
 * stderr in wire order via a shell (`2>&1`) — exactly what the old manual pipe
 * did — so the frames mirror a live session. POSIX-only (like the demo e2e);
 * on Windows, pre-capture a transcript and pass --no-capture / --from.
 */
function captureTranscript(toPath) {
  const r = spawnSync("sh", ["-c", "node examples/run-demo.mjs 2>&1"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.error) throw new Error(`could not run demo: ${r.error.message}`);
  const all = (r.stdout ?? "").replace(/\r/g, "").split("\n");
  const start = all.findIndex((l) => /mcpwn — MCP intercept/.test(l));
  let kept = (start >= 0 ? all.slice(start) : all).map(sanitise);
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  if (kept.length === 0) throw new Error("demo produced no transcript (is dist/ built?)");
  writeFileSync(toPath, kept.join("\n") + "\n");
}

// --capture-only: refresh the transcript and stop (no font / ffmpeg required).
if (captureOnly) {
  captureTranscript(fromPath);
  console.log(`captured transcript -> ${fromPath}`);
  process.exit(0);
}

// --- font (only needed for rendering) --------------------------------------
const FONT_CANDIDATES = [
  arg("--font", null),
  "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
  "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
  "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
].filter(Boolean);
const fontPath = FONT_CANDIDATES.find((p) => existsSync(p));
if (!fontPath) {
  console.error("No monospace TTF found. Pass --font <path> (or use --capture-only).");
  process.exit(1);
}
// Register the font ONCE, up front, so we can both measure glyph metrics and
// draw with it. pureimage's registerFont().loadSync() is synchronous.
PImage.registerFont(fontPath, "mono").loadSync();

// --- layout constants ------------------------------------------------------
const PT = 15; // font size in pt
const LH = 23; // line height px
const PADX = 26;
const PADY = 20;
const TOPBAR = 32;
const MAX_W = 900; // target canvas width (px); wrap width is derived from it

/** Measure the REAL per-glyph advance for the chosen font at this size, rather
 *  than hardcoding it — a wrong value clips text (wide fonts) or over-pads it.
 *  Monospace, so every glyph shares one advance; average a run to be safe. */
function measureCharW(pt) {
  const ctx = PImage.make(10, 10).getContext("2d");
  ctx.font = `${pt}pt mono`;
  const probe = "M".repeat(40);
  return ctx.measureText(probe).width / probe.length;
}
const charW = measureCharW(PT);
// Soft-wrap columns keyed off the measured advance so wrapped lines never spill
// past MAX_W regardless of which monospace font was found.
const WRAP = Math.max(40, Math.floor((MAX_W - PADX * 2) / charW));

// Palette (GitHub dark).
const COL = {
  bg: "#0d1117",
  fg: "#c9d1d9",
  dim: "#6e7681",
  cyan: "#39c5cf",
  green: "#3fb950",
  yellow: "#d29922",
  red: "#f85149",
  white: "#ffffff",
};

/** Colour a real transcript line by its content — cosmetic only; the text is
 *  the program's actual output, never rewritten. */
function colourFor(text) {
  const t = text.trimStart();
  if (/\[tampered:/.test(text) || /Complying/.test(text)) return { color: "yellow", bold: true };
  if (/<INJECTED|SYSTEM OVERRIDE|send_email CALLED|attacker@|SECRET_API_KEY|Ignore all prior/.test(text))
    return { color: "red", bold: /CALLED/.test(text) };
  if (/^RESULT:|DEMONSTRATED/.test(t)) return { color: "green", bold: true };
  if (/^C→S/.test(t)) return { color: "cyan" };
  if (/^S→C/.test(t)) return { color: "green" };
  if (/^AGENT/.test(t)) return { color: "fg", bold: true };
  if (/^─+$/.test(t)) return { color: "dim" };
  if (/authorized testing only|proxying:|rules:|session summary|messages:|tools:|findings:/.test(text))
    return { color: "dim" };
  if (/^mcpwn — /.test(text)) return { color: "cyan", bold: true };
  return { color: "fg", bold: false };
}

/** Wrap a long line, indenting continuations under their original indent. */
function wrap(text) {
  if (text.length <= WRAP) return [text];
  const indent = (text.match(/^\s*/) ?? [""])[0] + "  ";
  const out = [];
  let rest = text;
  let first = true;
  while (rest.length > 0) {
    const width = first ? WRAP : WRAP - indent.length;
    if (rest.length <= width) {
      out.push((first ? "" : indent) + rest);
      break;
    }
    let cut = rest.lastIndexOf(" ", width);
    if (cut < width * 0.5) cut = width; // no good break point: hard cut
    out.push((first ? "" : indent) + rest.slice(0, cut).trimEnd());
    rest = rest.slice(cut).trimStart();
    first = false;
  }
  return out;
}

// Capture a fresh transcript by default; opt out with --no-capture / --from.
if (!fromExplicit && !noCapture) {
  captureTranscript(fromPath);
}

if (!existsSync(fromPath)) {
  console.error(
    `No transcript at ${fromPath}. Capture a real run first:\n` +
      `  node tools/gen-gif.mjs            # captures + renders\n` +
      `  node tools/gen-gif.mjs --from <transcript>`
  );
  process.exit(1);
}

// Build the frame script from the REAL transcript.
const raw = readFileSync(fromPath, "utf8").replace(/\r/g, "").split("\n");
// Drop a trailing blank line if present; sanitise the local absolute path.
while (raw.length && raw[raw.length - 1].trim() === "") raw.pop();
const SCRIPT = [];
for (const line0 of raw) {
  const line = sanitise(line0);
  for (const seg of wrap(line)) {
    const c = colourFor(line);
    SCRIPT.push({ text: seg, color: c.color, bold: c.bold });
  }
}

const COLS = Math.min(WRAP + 2, Math.max(...SCRIPT.map((l) => l.text.length), 40));
const W = Math.ceil(PADX * 2 + COLS * charW);
const H = TOPBAR + PADY + SCRIPT.length * LH + PADY;

async function main() {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-gif-"));
  const FPS = 12;
  const frames = [];

  // Reveal frames: grow visible lines; dwell on the punchy lines.
  let shown = 0;
  while (shown <= SCRIPT.length) {
    const holdHere =
      shown > 0 && /DEMONSTRATED|CALLED|Complying/.test(SCRIPT[shown - 1]?.text ?? "");
    frames.push(shown);
    if (holdHere) for (let i = 0; i < 6; i++) frames.push(shown); // dwell
    shown += 1;
  }
  for (let i = 0; i < 30; i++) frames.push(SCRIPT.length); // final hold

  for (let f = 0; f < frames.length; f++) {
    const img = PImage.make(W, H);
    const ctx = img.getContext("2d");
    ctx.fillStyle = COL.bg;
    ctx.fillRect(0, 0, W, H);
    // title bar dots
    const dots = ["#ff5f56", "#ffbd2e", "#27c93f"];
    dots.forEach((d, i) => {
      ctx.fillStyle = d;
      ctx.beginPath();
      ctx.arc(PADX + i * 22, TOPBAR / 2, 7, 0, Math.PI * 2);
      ctx.fill();
    });
    ctx.font = `${PT}pt mono`;
    const visible = frames[f];
    for (let i = 0; i < visible; i++) {
      const line = SCRIPT[i];
      if (!line) continue;
      ctx.fillStyle = COL[line.color] ?? COL.fg;
      ctx.fillText(line.text, PADX, TOPBAR + PADY + i * LH + PT);
    }
    const file = join(work, `f${String(f).padStart(4, "0")}.png`);
    await new Promise((res, rej) => {
      const s = createWriteStream(file);
      PImage.encodePNGToStream(img, s).then(res).catch(rej);
    });
  }

  // ffmpeg: high-quality gif via palettegen/paletteuse.
  const pattern = join(work, "f%04d.png");
  const palette = join(work, "palette.png");
  const run = (args) => {
    const r = spawnSync("ffmpeg", args, { stdio: "ignore" });
    if (r.status !== 0) throw new Error("ffmpeg failed: " + args.join(" "));
  };
  run(["-y", "-framerate", String(FPS), "-i", pattern, "-vf", "palettegen=stats_mode=full", palette]);
  run([
    "-y",
    "-framerate", String(FPS),
    "-i", pattern,
    "-i", palette,
    "-lavfi", "paletteuse=dither=bayer:bayer_scale=3",
    outPath,
  ]);

  rmSync(work, { recursive: true, force: true });
  console.log(
    `wrote ${outPath}  (${frames.length} frames @ ${FPS}fps, ${W}x${H}, ` +
      `charW=${charW.toFixed(2)} wrap=${WRAP}, ${SCRIPT.length} lines from ${fromPath})`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
