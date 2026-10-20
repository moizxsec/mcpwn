import { readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./findings.js";

/**
 * Static SVG status badge (§Phase-8/F2). A server author can embed the result of
 * a scan — "mcpwn | 0 findings" (green) or "mcpwn | N findings" (red) — in their
 * README, like a CI badge. Pure string-built shields-style flat SVG, ZERO deps
 * (no network, no font metrics lib). Width is estimated from a fixed per-char
 * advance so the two halves line up well enough without a font library.
 */

export interface BadgeSpec {
  label: string;
  message: string;
  /** Right-half colour (any CSS/SVG colour; hex recommended). */
  color: string;
  /** Left-half colour. Defaults to the shields.io grey. */
  labelColor?: string;
}

const LEFT_COLOR = "#555";
const GREEN = "#4c1"; // shields "brightgreen"
const RED = "#e05d44"; // shields "red"

/** Rough text width in px at 11px DejaVu-ish; ~7px/char + padding. Good enough
 *  for alignment without pulling in a font-metrics dependency. */
function textWidth(s: string): number {
  return s.length * 7;
}

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Render a flat shields-style badge to an SVG string. */
export function renderBadge(spec: BadgeSpec): string {
  const label = spec.label;
  const message = spec.message;
  const labelColor = spec.labelColor ?? LEFT_COLOR;
  const pad = 10;
  const lw = textWidth(label) + pad * 2;
  const rw = textWidth(message) + pad * 2;
  const w = lw + rw;
  const h = 20;
  // Text is centred in each half; x10 scale matches shields' textLength trick.
  const lx = (lw / 2) * 10;
  const rx = (lw + rw / 2) * 10;
  const lLen = textWidth(label) * 10;
  const rLen = textWidth(message) * 10;
  const el = xmlEscape(label);
  const em = xmlEscape(message);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="${el}: ${em}">
  <title>${el}: ${em}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${w}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="${h}" fill="${labelColor}"/>
    <rect x="${lw}" width="${rw}" height="${h}" fill="${spec.color}"/>
    <rect width="${w}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text x="${lx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${lLen}">${el}</text>
    <text x="${lx}" y="140" transform="scale(.1)" textLength="${lLen}">${el}</text>
    <text x="${rx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${rLen}">${em}</text>
    <text x="${rx}" y="140" transform="scale(.1)" textLength="${rLen}">${em}</text>
  </g>
</svg>
`;
}

/** The badge for a finding count: green at zero, red otherwise. */
export function findingsBadge(count: number): string {
  const message = `${count} finding${count === 1 ? "" : "s"}`;
  return renderBadge({ label: "mcpwn", message, color: count === 0 ? GREEN : RED });
}

/** Count findings in a findings dir (reads findings.json) or a findings.json
 *  file path. Throws on unreadable/invalid input. */
export function countFindingsAt(pathArg: string): number {
  let file = pathArg;
  try {
    if (statSync(pathArg).isDirectory()) file = join(pathArg, "findings.json");
  } catch {
    /* fall through — treat as a file path, error surfaces on read */
  }
  const data = JSON.parse(readFileSync(file, "utf8"));
  if (!Array.isArray(data)) throw new Error(`${file} is not a findings array`);
  return (data as Finding[]).length;
}

/** `mcpwn badge [--count <n> | --findings <dir|file>] [-o <file>]`. Standalone
 *  emitter so a badge can be regenerated from an existing findings dir without a
 *  re-scan. Writes to the file or prints to stdout. */
export function runBadge(argv: string[]): number {
  let count: number | undefined;
  let findings: string | undefined;
  let out: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (what: string): string => {
      const v = argv[++i];
      if (v === undefined) {
        process.stderr.write(`mcpwn badge: option ${a} requires ${what}\n`);
        process.exit(2);
      }
      return v;
    };
    switch (a) {
      case "--count": {
        const n = Number(need("a <number>"));
        if (!Number.isInteger(n) || n < 0) {
          process.stderr.write("mcpwn badge: --count must be a non-negative integer\n");
          return 2;
        }
        count = n;
        break;
      }
      case "--findings":
        findings = need("a <dir|file>");
        break;
      case "-o":
      case "--out":
        out = need("a <file>");
        break;
      default:
        process.stderr.write(`mcpwn badge: unknown option "${a}"\n`);
        return 2;
    }
  }

  if (count === undefined && findings) {
    try {
      count = countFindingsAt(findings);
    } catch (err) {
      process.stderr.write(`mcpwn badge: ${(err as Error).message}\n`);
      return 2;
    }
  }
  if (count === undefined) {
    process.stderr.write("mcpwn badge: give --count <n> or --findings <dir|file>\n");
    return 2;
  }

  const svg = findingsBadge(count);
  if (out) {
    try {
      writeFileSync(out, svg);
    } catch (err) {
      process.stderr.write(`mcpwn badge: could not write ${out}: ${(err as Error).message}\n`);
      return 2;
    }
    process.stderr.write(`mcpwn badge: wrote ${out} (${count} finding(s))\n`);
  } else {
    process.stdout.write(svg);
  }
  return 0;
}
