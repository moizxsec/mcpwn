import { readFileSync } from "node:fs";

/**
 * Secret redaction (§3.9). When `--redact` is set the Logger masks matches of
 * these patterns in BOTH the stderr display and the JSONL raw/forwarded fields,
 * so evidence logs never persist a live credential. Redaction is a LOGGING
 * concern only — it never alters the bytes mcpwn forwards on the wire.
 *
 * Masks render as «redacted:<label>» so a reviewer can tell what was removed.
 */

export interface RedactPattern {
  label: string;
  re: RegExp;
}

/** The built-in secret patterns, shared with the secret-in-result linter so a
 *  pattern and its mask stay in lockstep. */
export function builtinRedactPatterns(): RedactPattern[] {
  return [
    { label: "aws-access-key", re: /AKIA[0-9A-Z]{16}/g },
    { label: "sk-token", re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
    {
      label: "jwt",
      re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
    },
    {
      label: "private-key",
      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    },
  ];
}

/** A fresh global RegExp from a pattern, so reuse across calls is stateless. */
function globalClone(re: RegExp): RegExp {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  return new RegExp(re.source, flags);
}

/**
 * Mask every match of every pattern as «redacted:<label>». Total: a pattern
 * that somehow fails to apply is skipped rather than throwing (never block the
 * wire / the log).
 */
export function redact(text: string, patterns: RedactPattern[]): string {
  if (!patterns || patterns.length === 0) return text;
  let out = text;
  for (const p of patterns) {
    try {
      out = out.replace(globalClone(p.re), `«redacted:${p.label}»`);
    } catch {
      /* a bad custom pattern must never break logging */
    }
  }
  return out;
}

/**
 * Load extra patterns from a file (`--redact-file`). One pattern per line:
 *   label=regex          → named
 *   regex                → label defaults to "custom"
 * Blank lines and `#` comments are ignored. Invalid regexes are skipped (with
 * no crash). Built-in patterns are NOT included — combine with
 * {@link builtinRedactPatterns} at the call site if both are wanted.
 */
export function loadRedactPatterns(file: string): RedactPattern[] {
  const text = readFileSync(file, "utf8");
  const out: RedactPattern[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    let label = "custom";
    let source = line;
    if (eq > 0) {
      label = line.slice(0, eq).trim() || "custom";
      source = line.slice(eq + 1).trim();
    }
    if (source.length === 0) continue;
    try {
      out.push({ label, re: new RegExp(source, "g") });
    } catch {
      /* skip an invalid pattern line */
    }
  }
  return out;
}
