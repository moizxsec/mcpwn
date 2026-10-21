import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { LineFramer, parseLine } from "../engine/parser.js";
import type { Detector } from "./detector.js";
import type { FlowMessage } from "../types.js";
import type { FindingsSink } from "../findings.js";

/**
 * Baseline / rug-pull detector (§3.4). An MCP server advertises its tools in
 * `tools/list`; a malicious (or compromised) server can serve a benign set
 * while the client builds trust, then quietly change a tool's description or
 * input schema — or add/remove tools — to redirect the agent ("rug pull").
 *
 * `baseline capture` records the FIRST tools/list result. `--baseline <file>`
 * then diffs every later server->client tools/list against it and records
 * findings. Hashing (sha256 over the canonicalised description + input schema)
 * means the baseline file never has to store — or diff — the full text.
 */

export interface BaselineTool {
  name: string;
  descriptionHash: string;
  inputSchemaHash: string;
  /** The raw tool object as captured, for human review. */
  raw: unknown;
}

export interface BaselineFile {
  capturedAt: string;
  tools: BaselineTool[];
}

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

function descHash(tool: any): string {
  return sha256(typeof tool?.description === "string" ? tool.description : "");
}

function schemaHash(tool: any): string {
  // Accept either inputSchema (MCP) or schema as a fallback.
  const schema = tool?.inputSchema ?? tool?.schema ?? null;
  return sha256(JSON.stringify(canonical(schema)));
}

/** Build a baseline snapshot from a tools array (as found in a tools/list result). */
export function buildBaseline(tools: unknown[]): BaselineFile {
  const out: BaselineTool[] = [];
  for (const t of tools) {
    if (!t || typeof t !== "object") continue;
    const name = (t as any).name;
    if (typeof name !== "string") continue;
    out.push({
      name,
      descriptionHash: descHash(t),
      inputSchemaHash: schemaHash(t),
      raw: t,
    });
  }
  return { capturedAt: new Date().toISOString(), tools: out };
}

export function loadBaseline(path: string): BaselineFile {
  const data = JSON.parse(readFileSync(path, "utf8"));
  if (!data || typeof data !== "object" || !Array.isArray((data as any).tools)) {
    throw new Error(`baseline file "${path}" is not a valid baseline (missing "tools" array)`);
  }
  return data as BaselineFile;
}

/** Is this flow a server->client tools/list result carrying a tools array? */
function toolsListTools(flow: FlowMessage): any[] | null {
  if (flow.direction !== "server->client") return null;
  const method = flow.method ?? flow.correlatedMethod;
  if (method !== "tools/list") return null;
  const tools = flow.json?.result?.tools;
  return Array.isArray(tools) ? tools : null;
}

/**
 * Diffs each server->client tools/list against a captured baseline:
 *   - input schema changed  → tool-definition-changed (high)
 *   - description changed    → tool-definition-changed (medium)
 *   - tool present now, not in baseline → tool-added (high)
 *   - tool in baseline, gone now        → tool-removed (low)
 */
export class BaselineDetector implements Detector {
  private byName: Map<string, BaselineTool>;

  constructor(baseline: BaselineFile) {
    this.byName = new Map(baseline.tools.map((t) => [t.name, t]));
  }

  inspect(flow: FlowMessage, sink: FindingsSink): void {
    const tools = toolsListTools(flow);
    if (!tools) return;
    const seen = new Set<string>();

    for (const t of tools) {
      if (!t || typeof t !== "object" || typeof t.name !== "string") continue;
      const name = t.name as string;
      seen.add(name);
      const base = this.byName.get(name);
      if (!base) {
        sink.add({
          id: "tool-added",
          severity: "high",
          title: `Tool added after baseline: ${name}`,
          direction: flow.direction,
          method: "tools/list",
          tool: name,
          description:
            "A tool not present in the trusted baseline appeared in tools/list - a server may be expanding its capabilities after the client built trust (rug pull).",
          remediation:
            "Re-review the server's tool set and re-capture the baseline only if the change is expected.",
          ts: flow.ts,
        });
        continue;
      }
      if (schemaHash(t) !== base.inputSchemaHash) {
        sink.add({
          id: "tool-definition-changed",
          severity: "high",
          title: `Tool input schema changed since baseline: ${name}`,
          direction: flow.direction,
          method: "tools/list",
          tool: name,
          description:
            "A tool's input schema changed after the baseline was captured - new or altered parameters can silently redirect how the agent calls the tool.",
          remediation:
            "Treat the server as untrusted until the schema change is explained; re-capture the baseline if intended.",
          ts: flow.ts,
        });
      }
      if (descHash(t) !== base.descriptionHash) {
        sink.add({
          id: "tool-definition-changed",
          severity: "medium",
          title: `Tool description changed since baseline: ${name}`,
          direction: flow.direction,
          method: "tools/list",
          tool: name,
          description:
            "A tool's description changed after the baseline was captured - descriptions steer the agent and are a classic tool-poisoning surface.",
          remediation:
            "Review the new description for injected instructions; re-capture the baseline if intended.",
          ts: flow.ts,
        });
      }
    }

    for (const name of this.byName.keys()) {
      if (seen.has(name)) continue;
      sink.add({
        id: "tool-removed",
        severity: "low",
        title: `Tool removed since baseline: ${name}`,
        direction: flow.direction,
        method: "tools/list",
        tool: name,
        description: "A tool present in the baseline no longer appears in tools/list.",
        ts: flow.ts,
      });
    }
  }
}

/** Minimal logging surface the capture paths use. */
interface BaselineLogger {
  info(text: string): void;
  error(text: string): void;
}

/**
 * Inline capture detector for `--baseline-capture <file>`: records the FIRST
 * server->client tools/list that flows through the proxy, then stays inert.
 * Writing a file is a read-only side effect wrt the flow (it never mutates or
 * blocks the message); the pipeline's per-detector try/catch keeps a write
 * error off the wire.
 */
export class BaselineCaptureDetector implements Detector {
  private done = false;
  constructor(
    private outFile: string,
    private logger?: BaselineLogger
  ) {}

  inspect(flow: FlowMessage, _sink: FindingsSink): void {
    if (this.done) return;
    const tools = toolsListTools(flow);
    if (!tools) return;
    const baseline = buildBaseline(tools);
    writeFileSync(this.outFile, JSON.stringify(baseline, null, 2) + "\n");
    this.done = true;
    this.logger?.info(`baseline captured (${baseline.tools.length} tool(s)) -> ${this.outFile}`);
  }
}

/**
 * `mcpwn baseline capture [--out <file>] -- <server> [args...]` — spawn the
 * server, run a minimal MCP handshake (initialize → initialized → tools/list),
 * write the first tools/list result to the baseline file, then exit. Drives the
 * child directly (like replay) rather than proxying, so stdio here is normal CLI
 * I/O and nothing is written to our stdout.
 */
export async function captureBaseline(
  command: string,
  args: string[],
  outFile: string,
  logger: BaselineLogger
): Promise<number> {
  return new Promise<number>((resolve) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
    const framer = new LineFramer();
    let settled = false;
    let phase: "init" | "list" = "init";

    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
      resolve(code);
    };

    const send = (obj: unknown) => {
      try {
        child.stdin.write(JSON.stringify(obj) + "\n");
      } catch {
        /* child stdin gone */
      }
    };

    const timer = setTimeout(() => {
      logger.error("baseline capture timed out waiting for tools/list");
      finish(1);
    }, 15000);
    timer.unref();

    child.on("error", (err) => {
      logger.error(`failed to spawn "${command}": ${(err as Error).message}`);
      clearTimeout(timer);
      finish(127);
    });

    child.stdout.on("data", (chunk: Buffer) => {
      for (const line of framer.push(chunk)) {
        const msg = parseLine(line);
        const json = msg.json;
        if (!json || typeof json !== "object") continue;
        if (phase === "init" && json.id === 1 && "result" in json) {
          send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
          phase = "list";
        } else if (phase === "list" && json.id === 2 && "result" in json) {
          const tools = json.result?.tools;
          const baseline = buildBaseline(Array.isArray(tools) ? tools : []);
          try {
            writeFileSync(outFile, JSON.stringify(baseline, null, 2) + "\n");
            logger.info(`baseline captured (${baseline.tools.length} tool(s)) -> ${outFile}`);
            clearTimeout(timer);
            finish(0);
          } catch (err) {
            logger.error(`could not write baseline "${outFile}": ${(err as Error).message}`);
            clearTimeout(timer);
            finish(1);
          }
        }
      }
    });

    child.on("close", (code) => {
      if (!settled) {
        logger.error(`server exited before tools/list (code ${code ?? 0})`);
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
        clientInfo: { name: "mcpwn-baseline", version: "0.0.0" },
      },
    });
  });
}
