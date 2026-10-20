import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Severity } from "./findings.js";

/**
 * Optional project config (§3.13). A `mcpwn.config.json` next to your server
 * lets you commit a baseline invocation — rule/template packs, scope, redaction,
 * findings output, the CI fail-on gate — so you don't retype flags every run.
 *
 * Precedence is defaults < config < CLI flags: the config seeds the parser's
 * starting values, then the usual flag parsing runs on top (scalars override,
 * list flags like `-r` append). Validation is hand-rolled — mcpwn ships ZERO
 * runtime deps, so it does not evaluate schema/config.schema.json at runtime
 * (that file documents the same shape for editors / CI).
 */
export const DEFAULT_CONFIG_FILENAME = "mcpwn.config.json";

export interface McpwnConfigScope {
  methods?: string[];
  tools?: string[];
  direction?: "c2s" | "s2c";
}

export interface McpwnConfig {
  /** Tamper-rule files to load (like repeated `-r`). */
  rules?: string[];
  /** Community templates to load by id (like repeated `--template`). */
  templates?: string[];
  /** Interception scope (§3.6). */
  scope?: McpwnConfigScope;
  /** Enable built-in secret redaction in logs (like `--redact`). */
  redact?: boolean;
  /** Extra redaction-pattern file (like `--redact-file`). */
  redactFile?: string;
  /** Directory for findings.json/md/sarif on exit (like `--findings-out`). */
  findingsOut?: string;
  /** CI gate severity for `mcpwn scan` (like `--fail-on`). */
  failOn?: Severity;
  /** JSONL session-log path (like `-l`). */
  log?: string;
  /** Pretty-print full bodies (like `-v`). */
  verbose?: boolean;
}

/** Thrown for an unreadable / malformed / schema-invalid config file. */
export class ConfigError extends Error {}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const KNOWN_KEYS = new Set<keyof McpwnConfig>([
  "rules",
  "templates",
  "scope",
  "redact",
  "redactFile",
  "findingsOut",
  "failOn",
  "log",
  "verbose",
]);
const KNOWN_SCOPE_KEYS = new Set<keyof McpwnConfigScope>(["methods", "tools", "direction"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asStringArray(v: unknown, where: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new ConfigError(`${where} must be an array of strings`);
  }
  return v as string[];
}

/** Validate a parsed config value (hand-rolled, zero-dep). `source` is only used
 *  in error messages. Throws ConfigError on the first problem. */
export function validateConfig(data: unknown, source = "mcpwn.config.json"): McpwnConfig {
  if (!isPlainObject(data)) throw new ConfigError(`${source}: top level must be a JSON object`);

  for (const k of Object.keys(data)) {
    if (k === "$schema") continue;
    if (!KNOWN_KEYS.has(k as keyof McpwnConfig)) {
      throw new ConfigError(`${source}: unknown key "${k}"`);
    }
  }

  const out: McpwnConfig = {};
  if (data.rules !== undefined) out.rules = asStringArray(data.rules, `${source}: "rules"`);
  if (data.templates !== undefined) {
    out.templates = asStringArray(data.templates, `${source}: "templates"`);
  }
  if (data.scope !== undefined) {
    if (!isPlainObject(data.scope)) throw new ConfigError(`${source}: "scope" must be an object`);
    for (const k of Object.keys(data.scope)) {
      if (!KNOWN_SCOPE_KEYS.has(k as keyof McpwnConfigScope)) {
        throw new ConfigError(`${source}: unknown key "scope.${k}"`);
      }
    }
    const scope: McpwnConfigScope = {};
    if (data.scope.methods !== undefined) {
      scope.methods = asStringArray(data.scope.methods, `${source}: "scope.methods"`);
    }
    if (data.scope.tools !== undefined) {
      scope.tools = asStringArray(data.scope.tools, `${source}: "scope.tools"`);
    }
    if (data.scope.direction !== undefined) {
      if (data.scope.direction !== "c2s" && data.scope.direction !== "s2c") {
        throw new ConfigError(`${source}: "scope.direction" must be "c2s" or "s2c"`);
      }
      scope.direction = data.scope.direction;
    }
    out.scope = scope;
  }
  if (data.redact !== undefined) {
    if (typeof data.redact !== "boolean")
      throw new ConfigError(`${source}: "redact" must be a boolean`);
    out.redact = data.redact;
  }
  if (data.redactFile !== undefined) {
    if (typeof data.redactFile !== "string") {
      throw new ConfigError(`${source}: "redactFile" must be a string`);
    }
    out.redactFile = data.redactFile;
  }
  if (data.findingsOut !== undefined) {
    if (typeof data.findingsOut !== "string") {
      throw new ConfigError(`${source}: "findingsOut" must be a string`);
    }
    out.findingsOut = data.findingsOut;
  }
  if (data.failOn !== undefined) {
    if (typeof data.failOn !== "string" || !SEVERITIES.includes(data.failOn as Severity)) {
      throw new ConfigError(`${source}: "failOn" must be one of ${SEVERITIES.join("|")}`);
    }
    out.failOn = data.failOn as Severity;
  }
  if (data.log !== undefined) {
    if (typeof data.log !== "string") throw new ConfigError(`${source}: "log" must be a string`);
    out.log = data.log;
  }
  if (data.verbose !== undefined) {
    if (typeof data.verbose !== "boolean") {
      throw new ConfigError(`${source}: "verbose" must be a boolean`);
    }
    out.verbose = data.verbose;
  }
  return out;
}

/** Read + parse + validate a config file. Throws ConfigError on any failure. */
export function loadConfig(path: string): McpwnConfig {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new ConfigError(`cannot read config "${path}": ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`invalid JSON in config "${path}": ${(err as Error).message}`);
  }
  return validateConfig(data, path);
}

/** Lightweight pre-scan of argv for the config flags, run BEFORE the main parse
 *  so the loaded config can seed the parser's starting values. Stops at `--` so
 *  a server flag of the same name is never consumed. Shared by the proxy + scan
 *  arg parsers. */
export function preScanConfigFlags(argv: string[]): { configFile?: string; noAuto: boolean } {
  let configFile: string | undefined;
  let noAuto = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    if (a === "--config") configFile = argv[++i];
    else if (a === "--no-auto-config") noAuto = true;
  }
  return { configFile, noAuto };
}

/** The auto-load path (`./mcpwn.config.json`), or undefined if absent. */
export function findDefaultConfig(cwd: string = process.cwd()): string | undefined {
  const p = resolve(cwd, DEFAULT_CONFIG_FILENAME);
  return existsSync(p) ? p : undefined;
}

/** Resolve which config file to use given the CLI's `--config` / `--no-auto-config`
 *  decision. Returns the path + whether it was auto-discovered (for the notice),
 *  or undefined when no config applies. */
export function resolveConfigPath(opts: {
  explicit?: string;
  noAuto?: boolean;
  cwd?: string;
}): { path: string; auto: boolean } | undefined {
  if (opts.explicit) return { path: opts.explicit, auto: false };
  if (opts.noAuto) return undefined;
  const auto = findDefaultConfig(opts.cwd);
  return auto ? { path: auto, auto: true } : undefined;
}
