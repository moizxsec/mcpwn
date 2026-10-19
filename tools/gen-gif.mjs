#!/usr/bin/env node
/**
 * Render the README demo as a GIF, fully headless (pureimage -> PNG frames
 * -> ffmpeg). No terminal recorder, no browser — reproducible in CI.
 *
 *   # capture a real run, then render it:
 *   npm run demo 2>&1 | sed -n '/mcpwn — MCP intercept/,$p' > assets/.demo-transcript.txt
 *   node tools/gen-gif.mjs
 *
 *   node tools/gen-gif.mjs [--from <transcript>] [--font /path/to/Mono.ttf] [--out assets/demo.gif]
 *
 * The transcript is the ACTUAL stdout/stderr of `npm run demo` — the frames
 * reveal those real lines one at a time, coloured to mirror mcpwn's own
 * output. Nothing is scripted by hand: edit the demo, re-capture, re-render.
 * Requires ffmpeg on PATH.
 */
import * as PImage from "pureimage";
import { spawnSync } from "node:child_process";
import { createWriteStream, mkdtempSync, existsSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}

const FONT_CANDIDATES = [
  arg("--font", null),
  "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
  "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
  "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
].filter(Boolean);
const fontPath = FONT_CANDIDATES.find((p) => existsSync(p));
if (!fontPath) {
  console.error("No monospace TTF found. Pass --font <path>.");
  process.exit(1);
}
const outPath = arg("--out", join(root, "assets", "demo.gif"));
const fromPath = arg("--from", join(root, "assets", ".demo-transcript.txt"));

if (!existsSync(fromPath)) {
  console.error(
    `No transcript at ${fromPath}. Capture a real run first:\n` +
      `  npm run demo 2>&1 | sed -n '/mcpwn — MCP intercept/,$p' > ${fromPath}`
  );
  process.exit(1);
}

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
  if (/authorized testing only|proxying:|rules:/.test(text)) return { color: "dim" };
  if (/^mcpwn — /.test(text)) return { color: "cyan", bold: true };
  return { color: "fg", bold: false };
}

const WRAP = 94; // soft-wrap columns

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

// Build the frame script from the REAL transcript.
const raw = readFileSync(fromPath, "utf8").replace(/\r/g, "").split("\n");
// Drop a trailing blank line if present; sanitise the local absolute path.
while (raw.length && raw[raw.length - 1].trim() === "") raw.pop();
const SCRIPT = [];
for (const line0 of raw) {
  // Don't leak the capturing machine's filesystem path.
  const line = line0.replace(/\s{2}proxying:.*$/, "  proxying: node ./examples/vulnerable-server.mjs");
  for (const seg of wrap(line)) {
    const c = colourFor(line);
    SCRIPT.push({ text: seg, color: c.color, bold: c.bold });
  }
}

// Layout.
const PT = 15; // font size in pt
const LH = 23; // line height px
const PADX = 26;
const PADY = 20;
const TOPBAR = 32;
const charW = 9.0; // approx advance for mono at this size
const COLS = Math.min(WRAP + 2, Math.max(...SCRIPT.map((l) => l.text.length), 40));
const W = Math.ceil(PADX * 2 + COLS * charW);
const H = TOPBAR + PADY + SCRIPT.length * LH + PADY;

async function main() {
  PImage.registerFont(fontPath, "mono").loadSync();

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
  console.log(`wrote ${outPath}  (${frames.length} frames @ ${FPS}fps, ${W}x${H}, ${SCRIPT.length} lines from ${fromPath})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
