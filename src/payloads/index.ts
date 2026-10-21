import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/**
 * Bundled payload library (§3.7). Zero runtime deps: payloads ship as plain
 * `.txt` wordlists under `payloads/` at the package root (one payload per line,
 * `#` full-line comments). `fuzzArgs.payloads` may name a bundled category or
 * give a path to a `.txt` file on disk.
 *
 * Bundled categories: prompt-injection, ssrf, path-traversal,
 * command-injection, sqli.
 */

const CATEGORIES = [
  "prompt-injection",
  "ssrf",
  "path-traversal",
  "command-injection",
  "sqli",
] as const;

/** Absolute path to the bundled `payloads/` directory. From the compiled
 *  `dist/payloads/index.js` the package root is two levels up. */
function bundledDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "payloads");
}

/** Strip comments/blank lines; keep each payload line exactly as written. */
function parsePayloadText(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    out.push(line);
  }
  return out;
}

/** Names of the bundled payload categories (what `mcpwn payloads list` prints).
 *  Falls back to the known category list if the directory can't be read. */
export function listPayloads(): string[] {
  try {
    return readdirSync(bundledDir())
      .filter((f) => f.endsWith(".txt"))
      .map((f) => f.slice(0, -".txt".length))
      .sort();
  } catch {
    return [...CATEGORIES];
  }
}

/**
 * Resolve a payload reference to its lines. Resolution order (§3.7): a bundled
 * category name maps to the shipped `payloads/<name>.txt`; anything else is
 * treated as a filesystem path to a `.txt` wordlist. Throws a friendly error
 * when neither resolves — the caller's per-rule safety net logs it and forwards
 * the message untampered (never blocks the wire).
 */
export function loadPayloads(name: string): string[] {
  const isCategory = (CATEGORIES as readonly string[]).includes(name);
  const path = isCategory ? join(bundledDir(), `${name}.txt`) : name;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    if (isCategory) {
      throw new Error(`bundled payload library "${name}" is missing from the package`);
    }
    throw new Error(
      `unknown payload library "${name}" - use a bundled name (${listPayloads().join(", ")}) ` +
        `or a path to a .txt wordlist`
    );
  }
  return parsePayloadText(text);
}
