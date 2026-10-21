import { readFileSync, writeFileSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { basename, dirname, join, posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Client config injection (§Phase-8/B1) — the adoption unlock.
 *
 *   mcpwn wrap   --client <id> [--server <name>] [--dry-run] [--config-path <f>]
 *   mcpwn unwrap --client <id> [--server <name>] [--dry-run] [--config-path <f>]
 *
 * Instead of hand-editing an MCP client's JSON config to route each server
 * `through` mcpwn (the snippet in the README), `wrap` does it for you: it finds
 * the client's config file (per-OS standard path), BACKS IT UP, and rewrites
 * every configured stdio server entry so its command/args run under mcpwn:
 *
 *     before:  { "command": "npx", "args": ["-y", "@some/server"] }
 *     after:   { "command": "mcpwn", "args": ["--", "npx", "-y", "@some/server"] }
 *
 * `unwrap` restores the backup byte-for-byte (or, if absent, reverses the
 * transform). Both are SAFE: never clobber without a backup, idempotent (a second
 * `wrap` is a no-op), and `--dry-run` prints the diff without touching disk.
 *
 * Zero runtime deps (node:* only). This module does read/write local files the
 * operator explicitly points it at; it never fetches or auto-discovers anything.
 */

/** Thrown for a user-facing wrap/unwrap error (bad client, missing file, …). */
export class WrapError extends Error {}

export type ClientId = "claude-desktop" | "cursor" | "cline" | "vscode" | "windsurf";

export interface ClientSpec {
  id: ClientId;
  label: string;
  /** Top-level JSON key holding the server map ("mcpServers" for most; VS Code
   *  native MCP uses "servers"). */
  serversKey: string;
  /** Resolve the standard config path for the given platform/env, or undefined
   *  when it can't be determined (e.g. no HOME). */
  resolve(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined;
}

function homeDir(env: NodeJS.ProcessEnv): string | undefined {
  return env.HOME || env.USERPROFILE || undefined;
}

/** Join using the TARGET platform's separators, not the host's — so resolving a
 *  darwin/linux path on a Windows host (and vice versa, e.g. in tests) yields the
 *  separators that platform actually uses. */
function pjoin(platform: NodeJS.Platform, ...parts: string[]): string {
  return (platform === "win32" ? win32 : posix).join(...parts);
}

/** Per-OS user-config base dir: %APPDATA% (win), ~/Library/Application Support
 *  (mac), $XDG_CONFIG_HOME or ~/.config (linux/other). */
function configBase(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined {
  if (platform === "win32") return env.APPDATA || undefined;
  if (platform === "darwin") {
    const h = homeDir(env);
    return h ? pjoin(platform, h, "Library", "Application Support") : undefined;
  }
  if (env.XDG_CONFIG_HOME) return env.XDG_CONFIG_HOME;
  const h = homeDir(env);
  return h ? pjoin(platform, h, ".config") : undefined;
}

/** VS Code's per-user dir (`.../Code/User`), host for both VS Code's own
 *  `mcp.json` and the Cline extension's settings. */
function vscodeUserDir(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string | undefined {
  const base = configBase(env, platform);
  return base ? pjoin(platform, base, "Code", "User") : undefined;
}

/** The supported clients and where each keeps its MCP config. */
export const CLIENTS: Record<ClientId, ClientSpec> = {
  "claude-desktop": {
    id: "claude-desktop",
    label: "Claude Desktop",
    serversKey: "mcpServers",
    resolve(env, platform) {
      const base = configBase(env, platform);
      return base ? pjoin(platform, base, "Claude", "claude_desktop_config.json") : undefined;
    },
  },
  cursor: {
    id: "cursor",
    label: "Cursor",
    serversKey: "mcpServers",
    resolve(env, platform) {
      const h = homeDir(env);
      return h ? pjoin(platform, h, ".cursor", "mcp.json") : undefined;
    },
  },
  cline: {
    id: "cline",
    label: "Cline (VS Code)",
    serversKey: "mcpServers",
    resolve(env, platform) {
      const dir = vscodeUserDir(env, platform);
      return dir
        ? pjoin(
            platform,
            dir,
            "globalStorage",
            "saoudrizwan.claude-dev",
            "settings",
            "cline_mcp_settings.json"
          )
        : undefined;
    },
  },
  vscode: {
    id: "vscode",
    label: "VS Code",
    serversKey: "servers",
    resolve(env, platform) {
      const dir = vscodeUserDir(env, platform);
      return dir ? pjoin(platform, dir, "mcp.json") : undefined;
    },
  },
  windsurf: {
    id: "windsurf",
    label: "Windsurf",
    serversKey: "mcpServers",
    resolve(env, platform) {
      const h = homeDir(env);
      return h ? pjoin(platform, h, ".codeium", "windsurf", "mcp_config.json") : undefined;
    },
  },
};

export const CLIENT_IDS = Object.keys(CLIENTS) as ClientId[];

/** How mcpwn re-invokes the real server when wrapping an entry. */
export interface WrapInvocation {
  command: string;
  args: string[];
}

/** The default invocation: the globally-installed `mcpwn` binary, no extra args. */
export function defaultInvocation(): WrapInvocation {
  return { command: "mcpwn", args: [] };
}

/** The `node <dist/cli.js>` invocation — for a non-global / zero-install setup.
 *  Resolves this module's sibling compiled `cli.js`. */
export function nodeInvocation(): WrapInvocation {
  const cli = join(dirname(fileURLToPath(import.meta.url)), "cli.js");
  return { command: process.execPath, args: [cli] };
}

/** Does this server entry already route through mcpwn? Recognises the `mcpwn`
 *  binary, the `node .../cli.js` form, and `npx ...mcpwn` — all with a `--`
 *  separator before the real command. Keeps `wrap` idempotent. */
export function isWrappedEntry(entry: any): boolean {
  if (!entry || typeof entry !== "object") return false;
  const cmd = typeof entry.command === "string" ? entry.command : "";
  const args: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];
  const sep = args.indexOf("--");
  if (sep === -1) return false;
  const base = basename(cmd).toLowerCase();
  if (base === "mcpwn" || base === "mcpwn.cmd" || base === "mcpwn.exe") return true;
  const pre = args.slice(0, sep);
  if (base === "node" || base === "node.exe") {
    if (pre.some((a) => /(^|[\\/])cli\.js$/.test(a) || a.toLowerCase().includes("mcpwn"))) {
      return true;
    }
  }
  if (base === "npx" || base === "npx.cmd") {
    if (pre.some((a) => a.toLowerCase().includes("mcpwn"))) return true;
  }
  return false;
}

/** True when an entry is a wrappable stdio server (has a string `command`). An
 *  http/url-only server has nothing to wrap. */
function isStdioEntry(entry: any): boolean {
  return !!entry && typeof entry === "object" && typeof entry.command === "string";
}

function wrapEntry(entry: any, inv: WrapInvocation): any {
  const origArgs: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];
  // Spread first so existing keys (env, cwd, …) and their order are preserved;
  // command/args are overwritten in place.
  return { ...entry, command: inv.command, args: [...inv.args, "--", entry.command, ...origArgs] };
}

function unwrapEntry(entry: any): any {
  const args: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];
  const sep = args.indexOf("--");
  const rest = sep === -1 ? [] : args.slice(sep + 1);
  const out: any = { ...entry, command: rest[0] };
  const restArgs = rest.slice(1);
  if (restArgs.length) out.args = restArgs;
  else delete out.args;
  return out;
}

export interface TransformResult {
  config: any;
  changed: string[];
  skipped: string[];
}

/** Pure transform: wrap every (or one named) server in a parsed client config. */
export function wrapConfigObject(
  config: any,
  serversKey: string,
  inv: WrapInvocation,
  only?: string
): TransformResult {
  const servers = config?.[serversKey];
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
    throw new WrapError(`no "${serversKey}" object found in the config`);
  }
  if (only && !(only in servers)) {
    const names = Object.keys(servers).join(", ") || "(none)";
    throw new WrapError(`server "${only}" not found (configured: ${names})`);
  }
  const names = only ? [only] : Object.keys(servers);
  const outServers: any = { ...servers };
  const changed: string[] = [];
  const skipped: string[] = [];
  for (const name of names) {
    const entry = servers[name];
    if (!isStdioEntry(entry) || isWrappedEntry(entry)) {
      skipped.push(name);
      continue;
    }
    outServers[name] = wrapEntry(entry, inv);
    changed.push(name);
  }
  return { config: { ...config, [serversKey]: outServers }, changed, skipped };
}

/** Pure transform: reverse the wrap for every (or one named) wrapped server. */
export function unwrapConfigObject(
  config: any,
  serversKey: string,
  only?: string
): TransformResult {
  const servers = config?.[serversKey];
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
    throw new WrapError(`no "${serversKey}" object found in the config`);
  }
  if (only && !(only in servers)) {
    const names = Object.keys(servers).join(", ") || "(none)";
    throw new WrapError(`server "${only}" not found (configured: ${names})`);
  }
  const names = only ? [only] : Object.keys(servers);
  const outServers: any = { ...servers };
  const changed: string[] = [];
  const skipped: string[] = [];
  for (const name of names) {
    const entry = servers[name];
    if (!isWrappedEntry(entry)) {
      skipped.push(name);
      continue;
    }
    outServers[name] = unwrapEntry(entry);
    changed.push(name);
  }
  return { config: { ...config, [serversKey]: outServers }, changed, skipped };
}

/** A minimal, human-readable diff between two JSON texts (line-prefixed). Pure
 *  string builder; good enough to preview a wrap without a diff dependency. */
export function textDiff(before: string, after: string): string {
  const a = before.split("\n");
  const b = after.split("\n");
  const out: string[] = [];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    const x = a[i];
    const y = b[i];
    if (x === y) {
      if (x !== undefined) out.push(`  ${x}`);
      continue;
    }
    if (x !== undefined) out.push(`- ${x}`);
    if (y !== undefined) out.push(`+ ${y}`);
  }
  return out.join("\n");
}

const BACKUP_SUFFIX = ".mcpwn.bak";

function readConfigFile(path: string): { text: string; config: any } {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new WrapError(`cannot read config "${path}": ${(err as Error).message}`);
  }
  let config: any;
  try {
    config = JSON.parse(text);
  } catch (err) {
    throw new WrapError(`invalid JSON in "${path}": ${(err as Error).message}`);
  }
  return { text, config };
}

export interface WrapFileResult {
  path: string;
  backupPath: string;
  changed: string[];
  skipped: string[];
  dryRun: boolean;
  wrote: boolean;
  diff: string;
  /** For unwrap: whether the restore came from the byte-for-byte backup. */
  restoredFromBackup?: boolean;
}

/** Wrap a config file on disk. Backs up the exact pre-wrap bytes to
 *  `<path>.mcpwn.bak` before writing. No-op (no backup, no write) when nothing
 *  changes, so re-running is safe. */
export function wrapFile(opts: {
  path: string;
  serversKey: string;
  invocation: WrapInvocation;
  only?: string;
  dryRun?: boolean;
}): WrapFileResult {
  const { text, config } = readConfigFile(opts.path);
  const res = wrapConfigObject(config, opts.serversKey, opts.invocation, opts.only);
  const nextText = JSON.stringify(res.config, null, 2) + "\n";
  const backupPath = opts.path + BACKUP_SUFFIX;
  let wrote = false;
  if (res.changed.length && !opts.dryRun) {
    // Backup the EXACT pre-wrap bytes first — unwrap restores these verbatim.
    copyFileSync(opts.path, backupPath);
    writeFileSync(opts.path, nextText);
    wrote = true;
  }
  return {
    path: opts.path,
    backupPath,
    changed: res.changed,
    skipped: res.skipped,
    dryRun: !!opts.dryRun,
    wrote,
    diff: textDiff(text, nextText),
  };
}

/** Unwrap a config file on disk. Prefers a byte-for-byte restore from the
 *  `<path>.mcpwn.bak` backup (removing it afterwards); otherwise reverses the
 *  transform in place. */
export function unwrapFile(opts: {
  path: string;
  serversKey: string;
  only?: string;
  dryRun?: boolean;
}): WrapFileResult {
  const backupPath = opts.path + BACKUP_SUFFIX;
  const { text } = readConfigFile(opts.path);

  // Byte-for-byte restore from the backup (whole-file only — narrowing with
  // --server falls through to the reverse transform).
  if (!opts.only && existsSync(backupPath)) {
    let backup: string;
    try {
      backup = readFileSync(backupPath, "utf8");
    } catch (err) {
      throw new WrapError(`cannot read backup "${backupPath}": ${(err as Error).message}`);
    }
    let wrote = false;
    if (!opts.dryRun) {
      writeFileSync(opts.path, backup);
      try {
        rmSync(backupPath);
      } catch {
        /* backup removal is best-effort */
      }
      wrote = true;
    }
    return {
      path: opts.path,
      backupPath,
      changed: ["<restored from backup>"],
      skipped: [],
      dryRun: !!opts.dryRun,
      wrote,
      diff: textDiff(text, backup),
      restoredFromBackup: true,
    };
  }

  // No backup (or narrowed to one server): reverse the transform.
  const { config } = readConfigFile(opts.path);
  const res = unwrapConfigObject(config, opts.serversKey, opts.only);
  const nextText = JSON.stringify(res.config, null, 2) + "\n";
  let wrote = false;
  if (res.changed.length && !opts.dryRun) {
    writeFileSync(opts.path, nextText);
    wrote = true;
  }
  return {
    path: opts.path,
    backupPath,
    changed: res.changed,
    skipped: res.skipped,
    dryRun: !!opts.dryRun,
    wrote,
    diff: textDiff(text, nextText),
    restoredFromBackup: false,
  };
}

// --- CLI arg parsing + entry points ----------------------------------------

export interface WrapCliArgs {
  client?: ClientId;
  server?: string;
  configPath?: string;
  dryRun: boolean;
  /** Use the `node <dist/cli.js>` invocation instead of the `mcpwn` binary. */
  node: boolean;
  /** Explicit override for the wrapping command. */
  mcpwnCommand?: string;
}

export function parseWrapArgs(argv: string[]): WrapCliArgs {
  const out: WrapCliArgs = { dryRun: false, node: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (what: string): string => {
      const v = argv[++i];
      if (v === undefined) throw new WrapError(`option ${a} requires ${what}`);
      return v;
    };
    switch (a) {
      case "--client": {
        const v = need("a <client> id");
        if (!(v in CLIENTS)) {
          throw new WrapError(`unknown client "${v}" (one of: ${CLIENT_IDS.join(", ")})`);
        }
        out.client = v as ClientId;
        break;
      }
      case "--server":
        out.server = need("a <name> argument");
        break;
      case "--config-path":
        out.configPath = need("a <file> argument");
        break;
      case "--dry-run":
        out.dryRun = true;
        break;
      case "--node":
        out.node = true;
        break;
      case "--mcpwn-command":
        out.mcpwnCommand = need("a <command> argument");
        break;
      default:
        throw new WrapError(`unknown option "${a}"`);
    }
  }
  return out;
}

/** Resolve the client spec + config path from parsed args. serversKey defaults
 *  to "mcpServers" when only a `--config-path` is given without a `--client`. */
export function resolveTarget(args: WrapCliArgs): {
  serversKey: string;
  path: string;
  label: string;
} {
  let serversKey = "mcpServers";
  let label = "custom config";
  let path = args.configPath;
  if (args.client) {
    const spec = CLIENTS[args.client];
    serversKey = spec.serversKey;
    label = spec.label;
    if (!path) {
      path = spec.resolve(process.env, process.platform);
      if (!path) {
        throw new WrapError(
          `could not resolve the ${spec.label} config path on this platform - pass --config-path <file>`
        );
      }
    }
  }
  if (!path) {
    throw new WrapError("missing target - pass --client <id> and/or --config-path <file>");
  }
  return { serversKey, path, label };
}

function invocationFor(args: WrapCliArgs): WrapInvocation {
  if (args.mcpwnCommand) return { command: args.mcpwnCommand, args: [] };
  if (args.node) return nodeInvocation();
  return defaultInvocation();
}

export async function runWrap(argv: string[]): Promise<number> {
  let args: WrapCliArgs;
  try {
    args = parseWrapArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn wrap: ${(err as Error).message}\n`);
    return 2;
  }
  let target: { serversKey: string; path: string; label: string };
  try {
    target = resolveTarget(args);
  } catch (err) {
    process.stderr.write(`mcpwn wrap: ${(err as Error).message}\n`);
    return 2;
  }
  if (!existsSync(target.path)) {
    process.stderr.write(`mcpwn wrap: config not found at ${target.path}\n`);
    return 2;
  }

  let res: WrapFileResult;
  try {
    res = wrapFile({
      path: target.path,
      serversKey: target.serversKey,
      invocation: invocationFor(args),
      only: args.server,
      dryRun: args.dryRun,
    });
  } catch (err) {
    process.stderr.write(`mcpwn wrap: ${(err as Error).message}\n`);
    return 2;
  }

  if (args.dryRun) {
    process.stdout.write(`# dry-run - ${target.label} (${target.path})\n`);
    if (res.changed.length) {
      process.stdout.write(`# would wrap: ${res.changed.join(", ")}\n`);
    } else {
      process.stdout.write(`# nothing to wrap (already wrapped or no stdio servers)\n`);
    }
    process.stdout.write(res.diff + "\n");
    return 0;
  }

  if (!res.changed.length) {
    process.stderr.write(
      `mcpwn wrap: already wrapped - nothing to do (${target.path})\n` +
        (res.skipped.length ? `  skipped: ${res.skipped.join(", ")}\n` : "")
    );
    return 0;
  }
  process.stderr.write(
    `mcpwn wrap: wrapped ${res.changed.length} server(s) in ${target.label} [${res.changed.join(", ")}]\n` +
      `  backup:  ${res.backupPath}\n` +
      `  restore: mcpwn unwrap ${args.client ? `--client ${args.client}` : `--config-path ${target.path}`}\n` +
      (res.skipped.length ? `  skipped: ${res.skipped.join(", ")}\n` : "")
  );
  return 0;
}

export async function runUnwrap(argv: string[]): Promise<number> {
  let args: WrapCliArgs;
  try {
    args = parseWrapArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn unwrap: ${(err as Error).message}\n`);
    return 2;
  }
  let target: { serversKey: string; path: string; label: string };
  try {
    target = resolveTarget(args);
  } catch (err) {
    process.stderr.write(`mcpwn unwrap: ${(err as Error).message}\n`);
    return 2;
  }
  if (!existsSync(target.path)) {
    process.stderr.write(`mcpwn unwrap: config not found at ${target.path}\n`);
    return 2;
  }

  let res: WrapFileResult;
  try {
    res = unwrapFile({
      path: target.path,
      serversKey: target.serversKey,
      only: args.server,
      dryRun: args.dryRun,
    });
  } catch (err) {
    process.stderr.write(`mcpwn unwrap: ${(err as Error).message}\n`);
    return 2;
  }

  if (args.dryRun) {
    process.stdout.write(`# dry-run - ${target.label} (${target.path})\n`);
    process.stdout.write(
      res.restoredFromBackup
        ? `# would restore from backup ${res.backupPath}\n`
        : `# would unwrap: ${res.changed.join(", ") || "(nothing)"}\n`
    );
    process.stdout.write(res.diff + "\n");
    return 0;
  }

  if (res.restoredFromBackup) {
    process.stderr.write(
      `mcpwn unwrap: restored ${target.label} from backup (byte-for-byte)\n` +
        `  config: ${target.path}\n`
    );
    return 0;
  }
  if (!res.changed.length) {
    process.stderr.write(`mcpwn unwrap: nothing wrapped - nothing to do (${target.path})\n`);
    return 0;
  }
  process.stderr.write(
    `mcpwn unwrap: unwrapped ${res.changed.length} server(s) in ${target.label} [${res.changed.join(", ")}]\n`
  );
  return 0;
}
