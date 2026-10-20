import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Detector } from "../detect/detector.js";
import type { FlowMessage, Direction } from "../types.js";
import type { FindingsSink } from "../findings.js";

/**
 * Plugin loading (§3.11, platform layer). mcpwn is extensible in two places:
 *
 *   - `--detector <file.mjs>`   a custom passive {@link Detector}.
 *   - `--rule-plugin <file.mjs>`  a custom tamper action ({@link RuleActionPlugin})
 *                                 whose `kind` rule files may then reference.
 *
 * ──────────────────────────── TRUST MODEL ────────────────────────────
 * Loading a plugin runs `await import()` on a local file, which EXECUTES
 * ARBITRARY LOCAL CODE by design — exactly like a nuclei template, an ESLint
 * plugin or a Jest transformer. Consequences and the guard rails we keep:
 *
 *   - Plugins are ONLY ever loaded from paths you pass explicitly on the CLI.
 *     mcpwn NEVER auto-discovers, scans the cwd, or runs anything implicitly.
 *   - We NEVER fetch a remote plugin. The path must already be on disk.
 *   - Every loaded plugin prints a one-line notice naming its path on startup
 *     (see the CLI), so a run's active plugins are always visible in the log.
 *   - A detector plugin runs through the same read-only, per-detector try/catch
 *     isolation the built-ins get (the pipeline wraps every `inspect` call), so
 *     a throwing or slow plugin can never block the wire or crash a scan.
 *   - A rule-action plugin is applied under the same snapshot/rollback-on-throw
 *     discipline as a built-in action (see engine/rules.ts): a throw rolls the
 *     message back and forwards it untampered.
 *
 * Only ever point these flags at code you wrote or have audited.
 */

/** A rule file's `action` object as authored (its `kind` plus any extra fields
 *  the plugin defined). Passed verbatim to {@link RuleActionPlugin.apply}. */
export type RuleActionParams = Record<string, unknown>;

/** Collaborators a custom action receives: the flow's direction + resolved
 *  method (so a plugin can self-gate / honour scope exactly like a built-in
 *  action does) and a working COPY of the message JSON it may freely mutate. */
export interface RuleActionContext {
  direction: Direction;
  method?: string;
  /** A deep clone of the current message JSON. Mutating it has no effect unless
   *  it is returned; return it (or a fresh object) to take effect. */
  message: any;
}

/**
 * A custom tamper action. `apply` returns the new message JSON to forward, or
 * `undefined` for "no change" (the message is forwarded untampered). Throwing is
 * safe: the engine rolls the message back and forwards the original.
 */
export interface RuleActionPlugin {
  kind: string;
  apply(ctx: RuleActionContext, params: RuleActionParams): any | undefined;
}

/** Registry of custom action kinds, keyed by `kind`. Threaded into the rules
 *  engine (never a module global) so two concurrent pipelines stay independent. */
export type RuleActionRegistry = Map<string, RuleActionPlugin>;

/** Resolve a user-supplied path to an absolute `file://` URL for dynamic import. */
function toModuleUrl(path: string): string {
  return pathToFileURL(resolve(process.cwd(), path)).href;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

/** Pick the plugin value out of a module namespace: an explicit `default`
 *  export, then a conventionally-named export, else the namespace itself. */
function pickExport(mod: Record<string, unknown>, names: string[]): unknown {
  if (mod.default !== undefined && mod.default !== null) return mod.default;
  for (const n of names) {
    if (mod[n] !== undefined && mod[n] !== null) return mod[n];
  }
  return mod;
}

async function importModule(path: string): Promise<Record<string, unknown>> {
  let mod: Record<string, unknown>;
  try {
    mod = (await import(toModuleUrl(path))) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`could not load plugin "${path}": ${(err as Error)?.message ?? err}`);
  }
  return mod;
}

/**
 * Load a custom {@link Detector} from `path`. The module (or its default export)
 * must be an object exposing a `name:string` and an `inspect(flow, sink)` — or
 * `visit(flow, sink)` — method matching detect/detector.ts. Returns a Detector
 * that delegates to it; isolation is provided by the pipeline, which wraps every
 * detector call in try/catch. Throws a clear error when the module is missing or
 * does not implement the interface.
 */
export async function loadDetectorPlugin(path: string): Promise<Detector & { name: string }> {
  const mod = await importModule(path);
  const exported = pickExport(mod, ["detector", "Detector"]);
  if (!isObject(exported) && typeof exported !== "function") {
    throw new Error(
      `detector plugin "${path}" must export an object implementing { name, inspect(flow, sink) }`
    );
  }
  const obj = exported as Record<string, unknown>;
  const method =
    typeof obj.inspect === "function"
      ? "inspect"
      : typeof obj.visit === "function"
        ? "visit"
        : undefined;
  if (!method) {
    throw new Error(
      `detector plugin "${path}" must expose an inspect(flow, sink) or visit(flow, sink) method`
    );
  }
  const name = typeof obj.name === "string" && obj.name.length ? (obj.name as string) : path;
  const fn = obj[method] as (flow: FlowMessage, sink: FindingsSink) => void;
  return {
    name,
    inspect(flow: FlowMessage, sink: FindingsSink): void {
      fn.call(obj, flow, sink);
    },
  };
}

/**
 * Load a custom {@link RuleActionPlugin} from `path`. The module (or its default
 * export) is either an object `{ kind, apply }` or a function carrying a `kind`
 * property. Throws a clear error when neither the kind nor an apply function is
 * present.
 */
export async function loadRuleActionPlugin(path: string): Promise<RuleActionPlugin> {
  const mod = await importModule(path);
  const exported = pickExport(mod, ["action", "plugin", "rulePlugin"]);

  let kind: unknown;
  let apply: unknown;
  if (typeof exported === "function") {
    // A bare function IS the apply; it must carry a `kind` property.
    apply = exported;
    kind = (exported as { kind?: unknown }).kind;
  } else if (isObject(exported)) {
    kind = (exported as { kind?: unknown }).kind;
    apply = (exported as { apply?: unknown }).apply;
  }

  if (typeof kind !== "string" || kind.length === 0) {
    throw new Error(
      `rule-plugin "${path}" must declare a non-empty string "kind" (object { kind, apply } or a function with a .kind property)`
    );
  }
  if (typeof apply !== "function") {
    throw new Error(
      `rule-plugin "${path}" (kind "${kind}") must provide an apply(ctx, params) function`
    );
  }
  const applyFn = apply as RuleActionPlugin["apply"];
  const self = isObject(exported) ? exported : undefined;
  return {
    kind,
    apply(ctx, params) {
      return applyFn.call(self, ctx, params);
    },
  };
}

/** Build a {@link RuleActionRegistry} from loaded plugins. A later plugin with a
 *  duplicate kind wins (and the caller is told). */
export function buildActionRegistry(plugins: RuleActionPlugin[]): RuleActionRegistry {
  const reg: RuleActionRegistry = new Map();
  for (const p of plugins) reg.set(p.kind, p);
  return reg;
}
