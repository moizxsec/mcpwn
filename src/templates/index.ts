import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Rule } from "../types.js";
import { validateRuleFile } from "../engine/validate.js";
import type { Severity } from "../findings.js";

/**
 * Community template gallery (§3.12, platform layer). A template is a nuclei-style
 * rule-pack: the exact same `rules` array a `-r` tamper-rule file carries, PLUS a
 * metadata block (`id` + `info`) describing the attack it encodes. Templates ship
 * under `templates/` at the package root and are also the format community
 * contributions take, so they are self-describing and lint-able.
 *
 * Because a template reuses the rule shape verbatim, it is directly loadable as a
 * rule file (`mcpwn -r templates/<file>` works — the rule validator ignores the
 * extra top-level `id`/`info` keys) and resolvable by id (`--template <id>`).
 *
 * Zero runtime deps: templates are plain JSON, validated by the same hand-rolled
 * validator the rest of mcpwn uses. `schema/templates.schema.json` is the
 * published machine-readable mirror for editors/CI.
 */

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Metadata describing the attack a template encodes. */
export interface TemplateInfo {
  name: string;
  author: string;
  severity: Severity;
  /** Which mcpwn attack class this maps to (e.g. "tool-poisoning"). */
  attackClass: string;
  description: string;
  /** Background links (advisories, spec sections, CVEs). */
  references?: string[];
  /** Related CWE, e.g. "CWE-77". */
  cwe?: string;
  /** MCP protocol version the template targets, e.g. "2024-11-05". */
  mcpVersion?: string;
}

/** A parsed, validated template. `path` is set when it was read from disk. */
export interface Template {
  id: string;
  info: TemplateInfo;
  rules: Rule[];
  path?: string;
}

export type TemplateValidationResult =
  { ok: true; template: Template } | { ok: false; errors: string[] };

/** Top-level keys a template file may carry (`$schema` is an editor hint). */
const TEMPLATE_FIELDS = ["$schema", "id", "info", "rules"];
const INFO_REQUIRED = ["name", "author", "severity", "attackClass", "description"];
const INFO_FIELDS = [...INFO_REQUIRED, "references", "cwe", "mcpVersion"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/**
 * Validate a parsed template object. Reuses {@link validateRuleFile} for the
 * `rules` array (so a template's rules get exactly the same checks a `-r` file
 * does) and layers the metadata validation on top. Collects every error.
 */
export function validateTemplate(
  data: unknown,
  opts: { actionKinds?: string[] } = {}
): TemplateValidationResult {
  const errors: string[] = [];
  if (!isPlainObject(data)) {
    return { ok: false, errors: [`template must be a JSON object (got ${typeName(data)})`] };
  }

  for (const key of Object.keys(data)) {
    if (!TEMPLATE_FIELDS.includes(key)) errors.push(`template: unknown field "${key}"`);
  }

  if (!("id" in data)) errors.push('template: missing required "id"');
  else if (typeof data.id !== "string" || data.id.length === 0)
    errors.push(`template.id: must be a non-empty string (got ${typeName(data.id)})`);

  if (!("info" in data)) errors.push('template: missing required "info"');
  else validateInfo(data.info, errors);

  // Rules: delegate to the rule-file validator (wrap in the { rules } envelope it
  // expects). Prefix its errors so they point back at template.rules[...].
  if (!("rules" in data)) {
    errors.push('template: missing required "rules"');
  } else {
    const rres = validateRuleFile({ rules: data.rules }, { actionKinds: opts.actionKinds });
    if (!rres.ok) for (const e of rres.errors) errors.push(`template.${e}`);
  }

  if (errors.length) return { ok: false, errors };
  const d = data as unknown as Template;
  return { ok: true, template: { id: d.id, info: d.info, rules: d.rules } };
}

function validateInfo(info: unknown, errors: string[]): void {
  if (!isPlainObject(info)) {
    errors.push(`template.info: must be an object (got ${typeName(info)})`);
    return;
  }
  for (const key of Object.keys(info)) {
    if (!INFO_FIELDS.includes(key)) errors.push(`template.info: unknown field "${key}"`);
  }
  for (const field of ["name", "author", "attackClass", "description"]) {
    if (!(field in info)) errors.push(`template.info: missing required "${field}"`);
    else if (typeof info[field] !== "string")
      errors.push(`template.info.${field}: must be a string (got ${typeName(info[field])})`);
  }
  if (!("severity" in info)) {
    errors.push('template.info: missing required "severity"');
  } else if (!SEVERITIES.includes(info.severity as Severity)) {
    errors.push(
      `template.info.severity: must be one of ${SEVERITIES.map((s) => `"${s}"`).join(", ")} (got ${typeName(info.severity)})`
    );
  }
  if ("references" in info) {
    const refs = info.references;
    if (!Array.isArray(refs) || !refs.every((r) => typeof r === "string"))
      errors.push("template.info.references: must be an array of strings");
  }
  for (const field of ["cwe", "mcpVersion"]) {
    if (field in info && typeof info[field] !== "string")
      errors.push(`template.info.${field}: must be a string (got ${typeName(info[field])})`);
  }
}

/** Absolute path to the bundled `templates/` directory. From the compiled
 *  `dist/templates/index.js` the package root is two levels up. */
export function templatesDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "templates");
}

/**
 * Load and validate a template from disk. Throws a friendly, multi-line error
 * when the file is missing/invalid (mirrors {@link loadRules}). `extraActionKinds`
 * are `--rule-plugin` kinds the rules may reference.
 */
export function loadTemplate(path: string, extraActionKinds?: string[]): Template {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`could not read template "${path}": ${(err as Error).message}`);
  }
  const res = validateTemplate(data, { actionKinds: extraActionKinds });
  if (!res.ok) {
    throw new Error(`invalid template "${path}":\n  - ${res.errors.join("\n  - ")}`);
  }
  res.template.path = path;
  return res.template;
}

/** All valid templates in `dir` (defaults to the bundled gallery), sorted by id.
 *  Invalid files are skipped here — use {@link lintTemplates} to surface them. */
export function listTemplates(dir: string = templatesDir()): Template[] {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
  const out: Template[] = [];
  for (const f of files.sort()) {
    try {
      out.push(loadTemplate(join(dir, f)));
    } catch {
      /* skip invalid; lintTemplates reports it */
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** Resolve a template by its `id` in `dir` (defaults to the bundled gallery). */
export function findTemplate(id: string, dir: string = templatesDir()): Template | undefined {
  return listTemplates(dir).find((t) => t.id === id);
}

/** One lint result per `.json` file in `dir`. */
export interface TemplateLintResult {
  file: string;
  ok: boolean;
  id?: string;
  errors: string[];
}

/** Validate every `.json` file in `dir` against the template schema (the
 *  community-contribution flow). Does not throw; returns per-file results. */
export function lintTemplates(
  dir: string = templatesDir(),
  extraActionKinds?: string[]
): TemplateLintResult[] {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch (err) {
    return [{ file: dir, ok: false, errors: [`cannot read directory: ${(err as Error).message}`] }];
  }
  return files.sort().map((f) => {
    const full = join(dir, f);
    let data: unknown;
    try {
      data = JSON.parse(readFileSync(full, "utf8"));
    } catch (err) {
      return { file: f, ok: false, errors: [`invalid JSON: ${(err as Error).message}`] };
    }
    const res = validateTemplate(data, { actionKinds: extraActionKinds });
    if (res.ok) return { file: f, ok: true, id: res.template.id, errors: [] };
    return { file: f, ok: false, errors: res.errors };
  });
}
