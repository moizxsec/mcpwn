import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { LineFramer, parseLine } from "../engine/parser.js";
import type { Detector } from "./detector.js";
import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";

/**
 * Rug-pull PINNING (§3.14, A3) — a persisted, cross-session lockfile.
 *
 * `--baseline` (src/detect/baseline.ts) compares the live tools/list against a
 * snapshot captured EARLIER IN THE SAME SESSION. Pinning is the stronger, CI-grade
 * cousin: `mcpwn pin capture` writes a canonical `mcpwn.lock` that records a hash
 * of the server's WHOLE advertised surface — tools (name + description +
 * inputSchema) AND resources/list AND prompts/list — and `--pin <file>` then diffs
 * every later run against that committed lock. Because the lock lives on disk, the
 * capture and the check can be weeks and many processes apart, so it catches a
 * server that quietly re-poisons a description or adds a privileged tool long
 * after the user approved it.
 *
 * Hashing (sha256 over canonicalised JSON) means the lock never has to diff — or
 * leak — full text, and the order of keys/entries never matters. The diff is a
 * read-only {@link Detector}: it only records findings and NEVER changes what the
 * proxy forwards (Invariant #2). It is deliberately a SEPARATE detector from
 * BaselineDetector so wiring `--pin` can never alter `--baseline` behaviour.
 */

/** Hash basis for one advertised item. `name` is the identity key; a change to
 *  `descriptionHash` or `shapeHash` (input schema / resource metadata / prompt
 *  arguments) between the lock and a live listing is silent drift. */
export interface PinEntry {
  name: string;
  descriptionHash: string;
  /** inputSchema (tools), {uri,name,mimeType} (resources) or arguments (prompts). */
  shapeHash: string;
  /** The raw item as captured, for human review. */
  raw: unknown;
}

/** The three surfaces a server advertises, as the capture saw them. */
export interface PinFile {
  version: 1;
  capturedAt: string;
  tools: PinEntry[];
  resources: PinEntry[];
  prompts: PinEntry[];
}

/** The advertised surfaces, each with its JSON-RPC method + result array key +
 *  the field whose change is "shape" drift (vs description). */
type Surface = "tool" | "resource" | "prompt";

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Stable JSON: object keys sorted recursively so hashing is order-independent. */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = canonical((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

function hashJson(v: unknown): string {
  return sha256(JSON.stringify(canonical(v)));
}

function descHash(item: any): string {
  return sha256(typeof item?.description === "string" ? item.description : "");
}

/** Build a pin entry for one advertised item of a given surface. Returns null for
 *  anything without a usable identity key. */
function entryOf(surface: Surface, item: any): PinEntry | null {
  if (!item || typeof item !== "object") return null;
  if (surface === "tool") {
    if (typeof item.name !== "string") return null;
    return {
      name: item.name,
      descriptionHash: descHash(item),
      shapeHash: hashJson(item.inputSchema ?? item.schema ?? null),
      raw: item,
    };
  }
  if (surface === "resource") {
    // Resources are keyed by uri (the stable identity), falling back to name.
    const key = typeof item.uri === "string" ? item.uri : item.name;
    if (typeof key !== "string") return null;
    return {
      name: key,
      descriptionHash: descHash(item),
      shapeHash: hashJson({ uri: item.uri, name: item.name, mimeType: item.mimeType }),
      raw: item,
    };
  }
  // prompt
  if (typeof item.name !== "string") return null;
  return {
    name: item.name,
    descriptionHash: descHash(item),
    shapeHash: hashJson(item.arguments ?? null),
    raw: item,
  };
}

function entriesOf(surface: Surface, items: unknown[]): PinEntry[] {
  const out: PinEntry[] = [];
  for (const item of items) {
    const e = entryOf(surface, item);
    if (e) out.push(e);
  }
  return out;
}

/** Build a lock from the three advertised surfaces (as returned by *_list). */
export function buildPin(tools: unknown[], resources: unknown[], prompts: unknown[]): PinFile {
  return {
    version: 1,
    capturedAt: new Date().toISOString(),
    tools: entriesOf("tool", tools),
    resources: entriesOf("resource", resources),
    prompts: entriesOf("prompt", prompts),
  };
}

export function loadPin(path: string): PinFile {
  const data = JSON.parse(readFileSync(path, "utf8"));
  if (!data || typeof data !== "object" || !Array.isArray((data as any).tools)) {
    throw new Error(`pin lockfile "${path}" is not a valid lock (missing "tools" array)`);
  }
  const d = data as Partial<PinFile>;
  return {
    version: 1,
    capturedAt: typeof d.capturedAt === "string" ? d.capturedAt : "",
    tools: Array.isArray(d.tools) ? d.tools : [],
    resources: Array.isArray(d.resources) ? d.resources : [],
    prompts: Array.isArray(d.prompts) ? d.prompts : [],
  };
}

/** Human labels per surface (method, result key, the "shape" field name). */
const SURFACE_META: Record<Surface, { method: string; key: string; shape: string }> = {
  tool: { method: "tools/list", key: "tools", shape: "input schema" },
  resource: { method: "resources/list", key: "resources", shape: "metadata" },
  prompt: { method: "prompts/list", key: "prompts", shape: "arguments" },
};

function resolvedMethod(flow: FlowMessage): string | undefined {
  return flow.method ?? flow.correlatedMethod;
}

/**
 * Diffs each advertised surface (tools/resources/prompts) against the committed
 * lock. Every drift is HIGH: for a pinned surface any silent change is a trust
 * violation (the whole point of pinning is that nothing moves without a re-pin).
 *   - item present live, absent from lock → pin-drift (added)
 *   - item in lock, absent live           → pin-drift (removed)
 *   - description hash differs            → pin-drift (description changed)
 *   - shape hash differs                  → pin-drift (schema/metadata/args changed)
 */
export class PinDetector implements Detector {
  private readonly lock: Record<Surface, Map<string, PinEntry>>;

  constructor(lock: PinFile) {
    this.lock = {
      tool: new Map(lock.tools.map((e) => [e.name, e])),
      resource: new Map(lock.resources.map((e) => [e.name, e])),
      prompt: new Map(lock.prompts.map((e) => [e.name, e])),
    };
  }

  inspect(flow: FlowMessage, sink: FindingsSink): void {
    if (flow.direction !== "server->client") return;
    const method = resolvedMethod(flow);
    for (const surface of ["tool", "resource", "prompt"] as Surface[]) {
      const meta = SURFACE_META[surface];
      if (method !== meta.method) continue;
      const live = flow.json?.result?.[meta.key];
      // Only diff when the server actually returned the array; an error reply
      // (no result array) must never read as "every pinned item removed".
      if (!Array.isArray(live)) continue;
      this.diff(surface, entriesOf(surface, live), flow, sink);
    }
  }

  private diff(surface: Surface, live: PinEntry[], flow: FlowMessage, sink: FindingsSink): void {
    const meta = SURFACE_META[surface];
    const pinned = this.lock[surface];
    const seen = new Set<string>();

    const add = (name: string, what: string, evidence: string): void => {
      sink.add({
        id: "pin-drift",
        severity: "high",
        title: `Pinned ${surface} ${what}: ${name}`,
        direction: flow.direction,
        method: meta.method,
        tool: surface === "tool" ? name : undefined,
        evidence,
        description:
          `A ${surface} drifted from the committed pin lock (${what}). The server's advertised ` +
          "surface changed since it was pinned - a rug-pull signature: metadata the user " +
          "approved is no longer what the agent will see.",
        remediation:
          "Treat the server as untrusted until the change is explained; re-run `mcpwn pin capture` only if the change is expected.",
        ts: flow.ts,
      });
    };

    for (const cur of live) {
      seen.add(cur.name);
      const base = pinned.get(cur.name);
      if (!base) {
        add(cur.name, "added since pin", `${surface} not present in the lock`);
        continue;
      }
      if (cur.shapeHash !== base.shapeHash) {
        add(
          cur.name,
          `${meta.shape} changed since pin`,
          `${meta.shape} hash differs from the lock`
        );
      }
      if (cur.descriptionHash !== base.descriptionHash) {
        add(cur.name, "description changed since pin", "description hash differs from the lock");
      }
    }

    for (const name of pinned.keys()) {
      if (!seen.has(name))
        add(name, "removed since pin", `${surface} present in the lock, gone now`);
    }
  }
}

/** Minimal logging surface the capture path uses (mirrors baseline.ts). */
interface PinLogger {
  info(text: string): void;
  error(text: string): void;
}

/**
 * `mcpwn pin capture [--out mcpwn.lock] -- <server> [args...]` — spawn the server,
 * run a minimal MCP handshake (initialize → initialized), enumerate tools/list,
 * resources/list and prompts/list, hash each surface into a canonical lockfile,
 * then exit. Drives the child directly (like baseline capture) rather than
 * proxying, so stdio here is normal CLI I/O. A surface the server does not support
 * (JSON-RPC error) is recorded as empty — the capture never hangs on it.
 */
export async function capturePin(
  command: string,
  args: string[],
  outFile: string,
  logger: PinLogger
): Promise<number> {
  return new Promise<number>((resolve) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
    const framer = new LineFramer();
    let settled = false;

    // ids: 2=tools/list, 3=resources/list, 4=prompts/list.
    const collected: Record<number, unknown[]> = {};
    const pending = new Set<number>([2, 3, 4]);

    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
      resolve(code);
    };

    const send = (obj: unknown): void => {
      try {
        child.stdin.write(JSON.stringify(obj) + "\n");
      } catch {
        /* child stdin gone */
      }
    };

    const timer = setTimeout(() => {
      logger.error("pin capture timed out waiting for the server's surface");
      finish(1);
    }, 15000);
    timer.unref();

    const writeLock = (): void => {
      const lock = buildPin(collected[2] ?? [], collected[3] ?? [], collected[4] ?? []);
      try {
        writeFileSync(outFile, JSON.stringify(lock, null, 2) + "\n");
        logger.info(
          `pin captured (${lock.tools.length} tool(s), ${lock.resources.length} resource(s), ` +
            `${lock.prompts.length} prompt(s)) -> ${outFile}`
        );
        clearTimeout(timer);
        finish(0);
      } catch (err) {
        logger.error(`could not write lock "${outFile}": ${(err as Error).message}`);
        clearTimeout(timer);
        finish(1);
      }
    };

    const noteReply = (id: number, json: any): void => {
      if (!pending.has(id)) return;
      pending.delete(id);
      if (json && "result" in json) {
        const key = id === 2 ? "tools" : id === 3 ? "resources" : "prompts";
        const arr = json.result?.[key];
        collected[id] = Array.isArray(arr) ? arr : [];
      } else {
        collected[id] = []; // unsupported surface / error → empty
      }
      if (pending.size === 0) writeLock();
    };

    child.on("error", (err) => {
      logger.error(`failed to spawn "${command}": ${(err as Error).message}`);
      clearTimeout(timer);
      finish(127);
    });

    child.stdout.on("data", (chunk: Buffer) => {
      for (const line of framer.push(chunk)) {
        const json = parseLine(line).json;
        if (!json || typeof json !== "object") continue;
        if (json.id === 1 && "result" in json) {
          send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
          send({ jsonrpc: "2.0", id: 3, method: "resources/list", params: {} });
          send({ jsonrpc: "2.0", id: 4, method: "prompts/list", params: {} });
        } else if (typeof json.id === "number") {
          noteReply(json.id, json);
        }
      }
    });

    child.on("close", (code) => {
      if (!settled) {
        logger.error(`server exited before advertising its surface (code ${code ?? 0})`);
        clearTimeout(timer);
        finish(code ?? 1);
      }
    });

    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcpwn-pin", version: "0.0.0" },
      },
    });
  });
}
