import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  CLIENTS,
  CLIENT_IDS,
  WrapError,
  wrapFile,
  defaultInvocation,
  nodeInvocation,
  type ClientId,
  type WrapInvocation,
} from "./wrap.js";
import { defaultPolicy } from "./guard/policy.js";

/**
 * Onboarding wizard (§Phase-8/F1). `mcpwn init` detects which supported MCP
 * client configs exist on the machine, offers to wrap one, and can drop a
 * starter mcpwn.config.json / mcpwn.policy.json.
 *
 * It is deliberately NON-interactive (never blocks on a TTY): without --yes it
 * only PREVIEWS (prints what it would do, dry-run diff, writes nothing); with
 * --yes it APPLIES. That keeps it scriptable and testable in CI.
 */

export interface InitArgs {
  yes: boolean;
  client?: ClientId;
  configPath?: string;
  noWrap: boolean;
  writeConfig: boolean;
  writePolicy: boolean;
  node: boolean;
  /** Directory to write starter config/policy into (default: cwd). */
  dir: string;
}

export function parseInitArgs(argv: string[]): InitArgs {
  const out: InitArgs = {
    yes: false,
    noWrap: false,
    writeConfig: false,
    writePolicy: false,
    node: false,
    dir: process.cwd(),
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (what: string): string => {
      const v = argv[++i];
      if (v === undefined) throw new WrapError(`option ${a} requires ${what}`);
      return v;
    };
    switch (a) {
      case "-y":
      case "--yes":
        out.yes = true;
        break;
      case "--client": {
        const v = need("a <client> id");
        if (!(v in CLIENTS)) {
          throw new WrapError(`unknown client "${v}" (one of: ${CLIENT_IDS.join(", ")})`);
        }
        out.client = v as ClientId;
        break;
      }
      case "--config-path":
        out.configPath = need("a <file> argument");
        break;
      case "--no-wrap":
        out.noWrap = true;
        break;
      case "--write-config":
        out.writeConfig = true;
        break;
      case "--write-policy":
        out.writePolicy = true;
        break;
      case "--node":
        out.node = true;
        break;
      case "--dir":
        out.dir = need("a <dir> argument");
        break;
      default:
        throw new WrapError(`unknown option "${a}"`);
    }
  }
  return out;
}

export interface DetectedClient {
  id: ClientId;
  label: string;
  path: string;
  serversKey: string;
}

/** Scan every known client's standard path and return those that exist. */
export function detectClients(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): DetectedClient[] {
  const out: DetectedClient[] = [];
  for (const id of CLIENT_IDS) {
    const spec = CLIENTS[id];
    const path = spec.resolve(env, platform);
    if (path && existsSync(path)) {
      out.push({ id, label: spec.label, path, serversKey: spec.serversKey });
    }
  }
  return out;
}

function starterConfig(): string {
  return (
    JSON.stringify(
      {
        $schema: "./schema/config.schema.json",
        findingsOut: "./mcpwn-out",
        failOn: "high",
        redact: true,
      },
      null,
      2
    ) + "\n"
  );
}

function starterPolicy(): string {
  const pol = defaultPolicy();
  return JSON.stringify({ $schema: "./schema/policy.schema.json", ...pol }, null, 2) + "\n";
}

function invocationFor(args: InitArgs): WrapInvocation {
  return args.node ? nodeInvocation() : defaultInvocation();
}

/** `mcpwn init [--yes] [--client <id>] [--config-path <f>] [--dir <d>]`. */
export async function runInit(argv: string[]): Promise<number> {
  let args: InitArgs;
  try {
    args = parseInitArgs(argv);
  } catch (err) {
    process.stderr.write(`mcpwn init: ${(err as Error).message}\n`);
    return 2;
  }

  const out = process.stdout;
  out.write("mcpwn init - onboarding\n\n");

  // 1) Detect installed clients.
  const detected = detectClients();
  if (detected.length) {
    out.write("Detected MCP client config(s):\n");
    for (const c of detected) out.write(`  - ${c.label.padEnd(16)} ${c.path}\n`);
  } else {
    out.write("No known MCP client configs detected on this machine.\n");
  }
  out.write("\n");

  // 2) Choose a wrap target: an explicit --client, else the sole detected one.
  let targetId: ClientId | undefined = args.client;
  let targetPath: string | undefined = args.configPath;
  let serversKey = args.client ? CLIENTS[args.client].serversKey : "mcpServers";
  if (!targetId && detected.length === 1) {
    targetId = detected[0].id;
    targetPath = targetPath ?? detected[0].path;
    serversKey = detected[0].serversKey;
  } else if (targetId && !targetPath) {
    const found = detected.find((c) => c.id === targetId);
    targetPath = found?.path ?? CLIENTS[targetId].resolve(process.env, process.platform);
    serversKey = CLIENTS[targetId].serversKey;
  }

  const label = targetId ? CLIENTS[targetId].label : "the selected config";
  const canWrap = !args.noWrap && !!targetId && !!targetPath && existsSync(targetPath);

  // 3) Apply (with --yes) or preview.
  if (!args.yes) {
    out.write("Preview (run again with --yes to apply):\n");
    if (canWrap && targetPath) {
      try {
        const res = wrapFile({
          path: targetPath,
          serversKey,
          invocation: invocationFor(args),
          dryRun: true,
        });
        out.write(
          `  wrap ${label} (${targetPath}) - would wrap: ${res.changed.join(", ") || "(nothing; already wrapped)"}\n`
        );
      } catch (err) {
        out.write(`  wrap ${label}: ${(err as Error).message}\n`);
      }
    } else if (targetId && targetPath && !existsSync(targetPath)) {
      out.write(`  wrap ${label}: config not found at ${targetPath} (nothing to wrap)\n`);
    } else {
      out.write("  wrap: no single client selected - pass --client <id> to choose one\n");
    }
    const cfgPath = join(args.dir, "mcpwn.config.json");
    const polPath = join(args.dir, "mcpwn.policy.json");
    out.write(`  would write ${cfgPath}${existsSync(cfgPath) ? " (exists - kept)" : ""}\n`);
    out.write(`  would write ${polPath}${existsSync(polPath) ? " (exists - kept)" : ""}\n`);
    return 0;
  }

  // --yes: apply.
  let exit = 0;
  if (canWrap && targetPath) {
    try {
      const res = wrapFile({
        path: targetPath,
        serversKey,
        invocation: invocationFor(args),
      });
      if (res.changed.length) {
        out.write(`Wrapped ${label} [${res.changed.join(", ")}] - backup at ${res.backupPath}\n`);
      } else {
        out.write(`${label}: already wrapped - nothing to do\n`);
      }
    } catch (err) {
      process.stderr.write(`mcpwn init: wrap failed: ${(err as Error).message}\n`);
      exit = 1;
    }
  } else if (targetId && targetPath && !existsSync(targetPath)) {
    out.write(`${label}: config not found at ${targetPath} - skipping wrap\n`);
  } else if (!args.noWrap) {
    out.write("No single client selected - skipping wrap (pass --client <id>)\n");
  }

  // Starter files: write when absent (never clobber), or when forced.
  const cfgPath = join(args.dir, "mcpwn.config.json");
  if (!existsSync(cfgPath) || args.writeConfig) {
    writeFileSync(cfgPath, starterConfig());
    out.write(`Wrote ${cfgPath}\n`);
  } else {
    out.write(`Kept existing ${cfgPath}\n`);
  }
  const polPath = join(args.dir, "mcpwn.policy.json");
  if (!existsSync(polPath) || args.writePolicy) {
    writeFileSync(polPath, starterPolicy());
    out.write(`Wrote ${polPath}\n`);
  } else {
    out.write(`Kept existing ${polPath}\n`);
  }

  out.write("\nDone. Next: mcpwn scan --findings-out ./mcpwn-out -- <your-server>\n");
  return exit;
}
