import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";
import { LineFramer } from "../engine/parser.js";
import { MessagePipeline } from "./pipeline.js";
import { inScope, type Scope } from "./scope.js";
import { builtinLinters } from "../detect/linter.js";
import { PinDetector, loadPin } from "../detect/pin.js";
import { TaintDetector } from "../detect/taint.js";
import { ArrayFindingsSink, writeFindingsDir, type Finding, type Severity } from "../findings.js";
import { findingsBadge } from "../badge.js";
import { writeFileSync } from "node:fs";
import { loadPayloads } from "../payloads/index.js";
import { loadDetectorPlugin } from "../plugins/index.js";
import { Logger } from "../logger.js";
import { loadConfig, resolveConfigPath, preScanConfigFlags } from "../config.js";
import type { Detector } from "../detect/detector.js";
import type { FlowMessage } from "../types.js";

/**
 * Self-driving active scanner (§3.10).
 *
 *   mcpwn scan [options] -- <server> [args...]      (stdio)
 *   mcpwn scan --http <url> [options]               (streamable HTTP)
 *
 * Unlike the proxy, scan is itself the MCP *client*: it points at a server,
 * drives the full handshake, enumerates every surface (tools/resources/prompts,
 * paginated), samples resource/prompt content, and — behind `--fuzz` — calls
 * each tool with payloads from the bundled libraries. There is NO agent in the
 * loop; findings fall straight out of the same passive detectors the proxy uses.
 *
 * Design invariants carried over from the proxy:
 *   - Detectors stay READ-ONLY and run via the shared {@link MessagePipeline},
 *     so scan and proxy report identically. We reuse the Correlator + pipeline
 *     rather than reinventing JSON-RPC id matching.
 *   - Scope-aware: `--scope-tool` / `--scope-method` gate which surfaces get
 *     actively probed (passive detection always runs on whatever the server
 *     volunteers).
 *   - Never hangs: every request is bounded by a per-call timeout, the whole
 *     run by an overall budget, and the target is always killed/closed on exit.
 *   - Good MCP client: proper id correlation, answers server pings, declines
 *     other server-initiated requests (so the server never blocks on us).
 */

const PROTOCOL_VERSION = "2024-11-05";
const CLIENT_INFO = { name: "mcpwn-scan", version: "0.0.0" };

/** Payload libraries the fuzzer cycles through, in order. */
const FUZZ_CATEGORIES = [
  "prompt-injection",
  "command-injection",
  "path-traversal",
  "ssrf",
  "sqli",
] as const;

/** Most-severe → least, mirroring findings.ts (kept local so findings.ts stays
 *  a pure writer module). */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Defensive ceiling on list pagination so a server that always returns a
 *  nextCursor can never spin the scanner forever. */
const MAX_PAGES = 50;

export class ScanArgError extends Error {}

export interface ScanArgs {
  /** HTTP target URL; mutually exclusive with a stdio command. */
  http?: string;
  command?: string;
  commandArgs: string[];
  /** Enable active tool fuzzing (default OFF). */
  fuzz: boolean;
  findingsOut?: string;
  /** Record a JSONL session log of every probe. */
  logFile?: string;
  verbose: boolean;
  /** Exit nonzero if any finding is at or above this severity (CI gate). */
  failOn: Severity;
  /** Per-call timeout (ms). */
  timeoutMs: number;
  /** Overall deadline for the whole scan (ms). */
  budgetMs: number;
  /** Max payloads per library, per fuzzed string parameter. */
  fuzzMax: number;
  /** Max resources/prompts to sample content from. */
  sampleMax: number;
  scopeMethods: string[];
  scopeTools: string[];
  /** Custom passive detectors to load (`--detector <file.mjs>`, repeatable). */
  detectorPlugins: string[];
  /** Rug-pull PIN lockfile (`--pin <file>`, §3.14/A3): diff the enumerated
   *  tool/resource/prompt surface against a committed mcpwn.lock. */
  pinFile?: string;
  /** Provenance tainting (`--taint`, §3.14/A4). */
  taint: boolean;
  /** Emit a static SVG findings badge to this file (`--badge <file.svg>`). */
  badge?: string;
  /** One-line notice to log when a config file was loaded (§3.13). */
  configNotice?: string;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function parseScanArgs(argv: string[]): ScanArgs {
  const out: ScanArgs = {
    commandArgs: [],
    fuzz: false,
    verbose: false,
    failOn: "high",
    timeoutMs: 8000,
    budgetMs: 60000,
    fuzzMax: 3,
    sampleMax: 3,
    scopeMethods: [],
    scopeTools: [],
    detectorPlugins: [],
    taint: false,
  };

  // Config seeds the defaults BEFORE flag parsing, so CLI flags still override
  // it (defaults < config < flags, §3.13). Covers the scan-relevant keys.
  const pre = preScanConfigFlags(argv);
  const chosen = resolveConfigPath({ explicit: pre.configFile, noAuto: pre.noAuto });
  if (chosen) {
    let config;
    try {
      config = loadConfig(chosen.path);
    } catch (err) {
      throw new ScanArgError((err as Error).message);
    }
    if (config.failOn) out.failOn = config.failOn;
    if (config.findingsOut) out.findingsOut = config.findingsOut;
    if (config.scope?.methods) out.scopeMethods.push(...config.scope.methods);
    if (config.scope?.tools) out.scopeTools.push(...config.scope.tools);
    if (config.log) out.logFile = config.log;
    if (config.verbose) out.verbose = true;
    out.configNotice = chosen.auto
      ? `loaded ${chosen.path} (auto; pass --no-auto-config to skip)`
      : `loaded config ${chosen.path}`;
  }

  let i = 0;
  const value = (flag: string): string => {
    const v = argv[++i];
    if (v === undefined) throw new ScanArgError(`option ${flag} requires an argument`);
    return v;
  };
  const posInt = (flag: string): number => {
    const n = Number(value(flag));
    if (!Number.isInteger(n) || n < 0)
      throw new ScanArgError(`option ${flag} must be a non-negative integer`);
    return n;
  };
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      i++;
      break;
    }
    switch (a) {
      case "--http":
        out.http = value(a);
        break;
      case "--fuzz":
        out.fuzz = true;
        break;
      case "--findings-out":
        out.findingsOut = value(a);
        break;
      case "-l":
      case "--log":
        out.logFile = value(a);
        break;
      case "-v":
      case "--verbose":
        out.verbose = true;
        break;
      case "--fail-on": {
        const v = value(a) as Severity;
        if (!SEVERITIES.includes(v)) {
          throw new ScanArgError(
            `option --fail-on must be one of ${SEVERITIES.join("|")} (got "${v}")`
          );
        }
        out.failOn = v;
        break;
      }
      case "--timeout":
        out.timeoutMs = posInt(a);
        break;
      case "--budget":
        out.budgetMs = posInt(a);
        break;
      case "--fuzz-max":
        out.fuzzMax = posInt(a);
        break;
      case "--sample-max":
        out.sampleMax = posInt(a);
        break;
      case "--scope-method":
        out.scopeMethods.push(value(a));
        break;
      case "--scope-tool":
        out.scopeTools.push(value(a));
        break;
      case "--detector":
        out.detectorPlugins.push(value(a));
        break;
      case "--pin":
        out.pinFile = value(a);
        break;
      case "--taint":
        out.taint = true;
        break;
      case "--badge":
        out.badge = value(a);
        break;
      // Resolved in the pre-scan above; consume the tokens so they are not
      // mistaken for the server command.
      case "--config":
        value(a);
        break;
      case "--no-auto-config":
        break;
      default:
        if (a.startsWith("-")) {
          throw new ScanArgError(
            `unknown option "${a}" — put the server command (and its flags) after "--"`
          );
        }
        // First bare token (no "--" required) starts the stdio server command.
        out.command = a;
        out.commandArgs = argv.slice(i + 1);
        return out;
    }
  }
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

/** A thin MCP client the scanner drives. Both transports funnel every message
 *  through the shared pipeline for detection + correlation. */
interface ScanClient {
  /** Send a request and await its correlated reply (resolved via the
   *  correlator). Rejects on the per-call timeout. */
  request(method: string, params: unknown, timeoutMs: number): Promise<FlowMessage>;
  /** Fire-and-forget notification (no reply expected). */
  notify(method: string, params: unknown): void;
  /** Clean shutdown — kill the child / release resources. Never hangs. */
  close(): Promise<void>;
}

/** Raised when a request outlives its per-call timeout. */
class ScanTimeout extends Error {
  constructor(method: string) {
    super(`no response for ${method} within timeout`);
  }
}

// --- stdio client ----------------------------------------------------------

/**
 * Spawn a stdio MCP server and drive it directly (like baseline/replay). The
 * child's own stderr is inherited so server logs survive; its stdout is the
 * JSON-RPC channel. Server-initiated requests are answered inline (ping) or
 * politely declined, so the server never blocks waiting on the scanner.
 */
async function makeStdioClient(
  command: string,
  args: string[],
  pipeline: MessagePipeline,
  logger: Logger
): Promise<ScanClient> {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
  const framer = new LineFramer();
  const pending = new Map<string, (flow: FlowMessage) => void>();
  let nextId = 1;
  let serverChain: Promise<void> = Promise.resolve();

  const send = (obj: unknown): void => {
    try {
      child.stdin.write(JSON.stringify(obj) + "\n");
    } catch {
      /* child stdin gone */
    }
  };

  const answerServerRequest = (flow: FlowMessage): void => {
    // A good client replies to pings; it declines anything else (sampling,
    // roots/list, elicitation) with an error so the server never hangs on us.
    if (flow.method === "ping") {
      send({ jsonrpc: "2.0", id: flow.id, result: {} });
    } else {
      send({
        jsonrpc: "2.0",
        id: flow.id,
        error: { code: -32601, message: "mcpwn scan declines server-initiated requests" },
      });
    }
  };

  const onLine = async (line: string): Promise<void> => {
    const { flow } = await pipeline.process(line, "server->client");
    if (!flow.json) return;
    if (flow.kind === "request") {
      answerServerRequest(flow);
      return;
    }
    if ((flow.kind === "response" || flow.kind === "error") && flow.id !== undefined) {
      const resolve = pending.get(JSON.stringify(flow.id));
      if (resolve) {
        pending.delete(JSON.stringify(flow.id));
        resolve(flow);
      }
    }
  };

  child.stdout.on("data", (chunk: Buffer) => {
    for (const line of framer.push(chunk)) {
      serverChain = serverChain.then(() => onLine(line)).catch(() => undefined);
    }
  });

  // Surface a spawn failure (ENOENT) before we hand back the client.
  await new Promise<void>((resolve, reject) => {
    child.once("spawn", () => resolve());
    child.once("error", (err) => reject(err));
  });
  // Late spawn/stream errors must not crash the process.
  child.on("error", (err) => logger.error(`target stream error: ${(err as Error).message}`));

  return {
    async request(method, params, timeoutMs) {
      const id = nextId++;
      const obj = { jsonrpc: "2.0", id, method, params };
      // Note correlation + log the C→S line (rules are empty here, so the
      // pipeline forwards the bytes unchanged — we only want the side effects).
      await pipeline.process(JSON.stringify(obj), "client->server");
      return await new Promise<FlowMessage>((resolve, reject) => {
        const key = JSON.stringify(id);
        const timer = setTimeout(() => {
          pending.delete(key);
          reject(new ScanTimeout(method));
        }, timeoutMs);
        timer.unref();
        pending.set(key, (flow) => {
          clearTimeout(timer);
          resolve(flow);
        });
        send(obj);
      });
    },
    notify(method, params) {
      const obj = { jsonrpc: "2.0", method, params };
      void pipeline.process(JSON.stringify(obj), "client->server");
      send(obj);
    },
    async close() {
      try {
        child.stdin.end();
      } catch {
        /* already gone */
      }
      try {
        child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
          resolve();
        }, 500);
        t.unref();
        child.once("close", () => {
          clearTimeout(t);
          resolve();
        });
      });
    },
  };
}

// --- http client -----------------------------------------------------------

interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/**
 * Minimal streamable-HTTP MCP client (node:http/https, zero deps). One POST per
 * message; the reply is read as `application/json` or parsed out of a
 * `text/event-stream`. Session id + negotiated protocol version are echoed back
 * on later requests, as a well-behaved client should.
 */
async function makeHttpClient(urlStr: string, pipeline: MessagePipeline): Promise<ScanClient> {
  const url = new URL(urlStr);
  const isHttps = url.protocol === "https:";
  const mod = isHttps ? https : http;
  let sessionId: string | undefined;
  let protocolVersion: string | undefined;
  let nextId = 1;

  const post = (body: string, timeoutMs: number): Promise<HttpResponse> =>
    new Promise<HttpResponse>((resolve, reject) => {
      const headers: Record<string, string | number> = {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "content-length": Buffer.byteLength(body),
      };
      if (sessionId) headers["mcp-session-id"] = sessionId;
      if (protocolVersion) headers["mcp-protocol-version"] = protocolVersion;
      const req = mod.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method: "POST",
          headers,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks).toString("utf8"),
            })
          );
          res.on("error", reject);
        }
      );
      req.on("error", reject);
      req.setTimeout(timeoutMs, () => req.destroy(new Error("http request timed out")));
      req.write(body);
      req.end();
    });

  return {
    async request(method, params, timeoutMs) {
      const id = nextId++;
      const obj = { jsonrpc: "2.0", id, method, params };
      await pipeline.process(JSON.stringify(obj), "client->server");
      const res = await post(JSON.stringify(obj), timeoutMs);
      const sid = res.headers["mcp-session-id"];
      if (typeof sid === "string") sessionId = sid;
      const msgLine = extractJsonRpc(String(res.headers["content-type"] ?? ""), res.body);
      if (msgLine === null) {
        throw new Error(`no JSON-RPC reply for ${method} (HTTP ${res.status})`);
      }
      const { flow } = await pipeline.process(msgLine, "server->client");
      if (method === "initialize") {
        const pv = flow.json?.result?.protocolVersion;
        if (typeof pv === "string") protocolVersion = pv;
      }
      return flow;
    },
    notify(method, params) {
      const obj = { jsonrpc: "2.0", method, params };
      void pipeline.process(JSON.stringify(obj), "client->server");
      // 202 Accepted, empty body — fire and forget.
      void post(JSON.stringify(obj), 3000).catch(() => undefined);
    },
    async close() {
      /* nothing persistent to tear down */
    },
  };
}

/** Pull the JSON-RPC message string out of an HTTP reply: the body verbatim for
 *  `application/json`, or the first JSON-RPC `data:` payload of an SSE stream. */
function extractJsonRpc(contentType: string, body: string): string | null {
  if (contentType.toLowerCase().includes("text/event-stream")) {
    for (const block of body.split(/\r\n\r\n|\n\n|\r\r/)) {
      const payload = block
        .split(/\r\n|\n|\r/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.replace(/^data: ?/, ""))
        .join("\n")
        .trim();
      if (!payload) continue;
      try {
        const j = JSON.parse(payload);
        if (j && typeof j === "object" && !Array.isArray(j)) return payload;
      } catch {
        /* keep scanning events */
      }
    }
    return null;
  }
  const trimmed = body.trim();
  return trimmed.length ? trimmed : null;
}

// --- scope helpers (reuse scope.ts globbing) -------------------------------

function methodAllowed(scope: Scope | undefined, method: string): boolean {
  if (!scope?.methods?.length) return true;
  const flow = {
    method,
    direction: "client->server",
    kind: "request",
    raw: "",
    ts: 0,
  } as FlowMessage;
  return inScope({ methods: scope.methods }, flow);
}

function toolCallAllowed(scope: Scope | undefined, tool: string): boolean {
  if (!scope) return true;
  const flow = {
    method: "tools/call",
    json: { params: { name: tool } },
    direction: "client->server",
    kind: "request",
    raw: "",
    ts: 0,
  } as FlowMessage;
  return inScope({ methods: scope.methods, tools: scope.tools }, flow);
}

// --- enumeration + sampling + fuzzing --------------------------------------

/** Enumerate one list surface, following nextCursor. Tolerates a server that
 *  does not support the method (JSON-RPC error) or times out → returns what it
 *  gathered so far. Detection runs automatically as each reply flows through
 *  the pipeline. */
async function enumerate(
  client: ScanClient,
  method: string,
  key: string,
  timeoutMs: number,
  deadline: number
): Promise<any[]> {
  const out: any[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    if (Date.now() > deadline) break;
    let flow: FlowMessage;
    try {
      flow = await client.request(method, cursor ? { cursor } : {}, timeoutMs);
    } catch {
      break; // timeout — stop enumerating this surface
    }
    const json = flow.json;
    if (!json || json.error) break; // unsupported method / error → skip gracefully
    const arr = json.result?.[key];
    if (Array.isArray(arr)) out.push(...arr);
    cursor = typeof json.result?.nextCursor === "string" ? json.result.nextCursor : undefined;
    if (!cursor) break;
  }
  return out;
}

/** Cheaply fetch a sample of resource/prompt content so detectors see their
 *  text too, not just the listings. */
async function sampleContent(
  client: ScanClient,
  items: any[],
  method: string,
  buildParams: (item: any) => Record<string, unknown> | null,
  args: ScanArgs,
  deadline: number,
  scope: Scope | undefined
): Promise<void> {
  if (!methodAllowed(scope, method)) return;
  let n = 0;
  for (const item of items) {
    if (n >= args.sampleMax || Date.now() > deadline) break;
    const params = buildParams(item);
    if (!params) continue;
    try {
      await client.request(method, params, args.timeoutMs);
    } catch {
      /* skip this sample */
    }
    n++;
  }
}

/** String property names of a tool's inputSchema (the fuzz targets). */
function stringParamsOf(tool: any): string[] {
  const props = tool?.inputSchema?.properties;
  if (!props || typeof props !== "object") return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(props)) {
    const t = (v as any)?.type;
    if (t === "string" || (Array.isArray(t) && t.includes("string"))) out.push(k);
  }
  return out;
}

/** A well-formed, benign argument object for a tool (every declared property
 *  filled with a type-appropriate placeholder). The fuzzer overrides one string
 *  param at a time with a payload. */
function benignArgs(tool: any): Record<string, unknown> {
  const props = tool?.inputSchema?.properties;
  const out: Record<string, unknown> = {};
  if (props && typeof props === "object") {
    for (const [k, v] of Object.entries(props)) {
      const t = (v as any)?.type;
      if (t === "string" || (Array.isArray(t) && t.includes("string"))) out[k] = "mcpwn-scan";
      else if (t === "number" || t === "integer") out[k] = 0;
      else if (t === "boolean") out[k] = false;
      else if (t === "array") out[k] = [];
      else if (t === "object") out[k] = {};
    }
  }
  return out;
}

/** Load the bundled payload libraries, capped at `fuzzMax` each. A missing
 *  library is logged and skipped (never aborts the scan). */
function loadFuzzPayloads(logger: Logger, fuzzMax: number): Array<[string, string[]]> {
  const out: Array<[string, string[]]> = [];
  for (const cat of FUZZ_CATEGORIES) {
    try {
      const lines = loadPayloads(cat).slice(0, fuzzMax);
      if (lines.length) out.push([cat, lines]);
    } catch (err) {
      logger.error(`could not load payload library "${cat}": ${(err as Error).message}`);
    }
  }
  return out;
}

/** Active tool fuzzing: schema-aware, scope-aware, budget-bounded. For each
 *  in-scope tool, cycle every payload library through each string parameter and
 *  let the detectors inspect the responses. */
async function fuzzTools(
  client: ScanClient,
  tools: any[],
  args: ScanArgs,
  deadline: number,
  scope: Scope | undefined,
  logger: Logger
): Promise<void> {
  if (!methodAllowed(scope, "tools/call")) return;
  const libraries = loadFuzzPayloads(logger, args.fuzzMax);
  if (libraries.length === 0) return;
  for (const tool of tools) {
    if (Date.now() > deadline) {
      logger.info("fuzz budget exhausted — stopping");
      return;
    }
    const name = tool?.name;
    if (typeof name !== "string" || !toolCallAllowed(scope, name)) continue;
    const params = stringParamsOf(tool);
    if (params.length === 0) continue;
    const base = benignArgs(tool);
    for (const param of params) {
      for (const [, payloads] of libraries) {
        for (const payload of payloads) {
          if (Date.now() > deadline) return;
          try {
            await client.request(
              "tools/call",
              { name, arguments: { ...base, [param]: payload } },
              args.timeoutMs
            );
          } catch {
            /* per-call timeout / error → move on */
          }
        }
      }
    }
  }
}

// --- reporting -------------------------------------------------------------

interface SurfaceCounts {
  tools: number;
  resources: number;
  prompts: number;
}

function capabilityList(caps: any): string {
  if (!caps || typeof caps !== "object") return "(none)";
  const keys = Object.keys(caps);
  return keys.length ? keys.join(", ") : "(none)";
}

/** Concise stderr summary table (greppable), independent of the per-message
 *  pipeline log lines. */
function printSummary(counts: SurfaceCounts, items: Finding[], args: ScanArgs): void {
  const bySev: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of items) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const lines = [
    "",
    "mcpwn scan summary",
    `  surfaces: tools=${counts.tools} resources=${counts.resources} prompts=${counts.prompts}`,
    `  findings: ${items.length} total — critical=${bySev.critical} high=${bySev.high} ` +
      `medium=${bySev.medium} low=${bySev.low} info=${bySev.info}`,
    `  fail-on:  ${args.failOn} (exit nonzero if any finding is at or above this severity)`,
    "",
  ];
  process.stderr.write(lines.join("\n") + "\n");
}

/** Build a scope only from the scan-relevant criteria (method glob + tool name);
 *  direction/onlyTampered are not meaningful for an active client. */
function buildScanScope(args: ScanArgs): Scope | undefined {
  if (args.scopeMethods.length === 0 && args.scopeTools.length === 0) return undefined;
  return {
    methods: args.scopeMethods.length ? args.scopeMethods : undefined,
    tools: args.scopeTools.length ? args.scopeTools : undefined,
  };
}

/** `mcpwn scan [options] -- <server> [args...]` / `mcpwn scan --http <url>`. */
export async function runScan(argv: string[]): Promise<number> {
  let args: ScanArgs;
  try {
    args = parseScanArgs(argv);
  } catch (err) {
    if (err instanceof ScanArgError) {
      process.stderr.write(`mcpwn scan: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  if (args.http && args.command) {
    process.stderr.write("mcpwn scan: use either --http <url> OR a -- <command>, not both\n");
    return 2;
  }
  if (!args.http && !args.command) {
    process.stderr.write(
      'mcpwn scan: missing target — give --http <url> or a server command after "--"\n'
    );
    return 2;
  }

  const logger = new Logger({ verbose: args.verbose, logFile: args.logFile });
  if (args.configNotice) logger.info(args.configNotice);
  const findings = new ArrayFindingsSink();
  const scope = buildScanScope(args);

  // Custom detectors (§3.11) run alongside the built-ins. Loading one RUNS LOCAL
  // CODE (see plugins/index.ts) — only explicit --detector paths are loaded, and
  // each is announced on startup. The pipeline isolates every detector call.
  const detectors: Detector[] = builtinLinters();
  // Opt-in detectors (§3.14): cross-session pin diff + provenance taint. Both are
  // read-only and run alongside the built-ins; neither is in builtinLinters().
  if (args.pinFile) {
    try {
      detectors.push(new PinDetector(loadPin(args.pinFile)));
    } catch (err) {
      logger.error(`could not load pin lock: ${(err as Error).message}`);
      return 2;
    }
  }
  if (args.taint) detectors.push(new TaintDetector());
  for (const p of args.detectorPlugins) {
    let d: Detector & { name: string };
    try {
      d = await loadDetectorPlugin(p);
    } catch (err) {
      logger.error((err as Error).message);
      return 2;
    }
    logger.info(
      `detector plugin loaded: ${d.name} <- ${p} (runs local code — trusted sources only)`
    );
    detectors.push(d);
  }

  const pipeline = new MessagePipeline({
    rules: [],
    logger,
    detectors,
    findings,
    scope,
  });

  const deadline = Date.now() + args.budgetMs;
  const counts: SurfaceCounts = { tools: 0, resources: 0, prompts: 0 };

  let client: ScanClient;
  try {
    client = args.http
      ? await makeHttpClient(args.http, pipeline)
      : await makeStdioClient(args.command!, args.commandArgs, pipeline, logger);
  } catch (err) {
    logger.error(`could not start target: ${(err as Error).message}`);
    return 1;
  }

  let exitCode = 0;
  try {
    logger.info(
      args.http
        ? `scanning ${args.http}`
        : `scanning ${args.command} ${args.commandArgs.join(" ")}`.trim()
    );

    // 1) Handshake.
    const init = await client.request(
      "initialize",
      {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {}, resources: {}, prompts: {}, sampling: {} },
        clientInfo: CLIENT_INFO,
      },
      args.timeoutMs
    );
    if (!init.json || init.json.error) {
      throw new Error("server did not complete the initialize handshake");
    }
    client.notify("notifications/initialized", {});
    logger.info(`handshake ok — capabilities: ${capabilityList(init.json?.result?.capabilities)}`);

    // 2) Enumerate every surface (paginated, error-tolerant).
    const tools = await enumerate(client, "tools/list", "tools", args.timeoutMs, deadline);
    const resources = await enumerate(
      client,
      "resources/list",
      "resources",
      args.timeoutMs,
      deadline
    );
    const prompts = await enumerate(client, "prompts/list", "prompts", args.timeoutMs, deadline);
    counts.tools = tools.length;
    counts.resources = resources.length;
    counts.prompts = prompts.length;

    // 3) Sample resource/prompt content so detectors see their text too.
    await sampleContent(
      client,
      resources,
      "resources/read",
      (r) => (typeof r?.uri === "string" ? { uri: r.uri } : null),
      args,
      deadline,
      scope
    );
    await sampleContent(
      client,
      prompts,
      "prompts/get",
      (p) => (typeof p?.name === "string" ? { name: p.name, arguments: {} } : null),
      args,
      deadline,
      scope
    );

    // 4) Optional active fuzzing.
    if (args.fuzz) {
      await fuzzTools(client, tools, args, deadline, scope, logger);
    }
  } catch (err) {
    logger.error(`scan aborted: ${(err as Error).message}`);
    exitCode = 1;
  } finally {
    await client.close();
  }

  // 5) Emit findings + summary.
  const items = findings.all();
  if (args.findingsOut) {
    try {
      writeFindingsDir(args.findingsOut, items);
      logger.info(`wrote ${items.length} finding(s) -> ${args.findingsOut}`);
    } catch (err) {
      logger.error(`could not write findings: ${(err as Error).message}`);
    }
  }
  if (args.badge) {
    try {
      writeFileSync(args.badge, findingsBadge(items.length));
      logger.info(`wrote badge (${items.length} finding(s)) -> ${args.badge}`);
    } catch (err) {
      logger.error(`could not write badge: ${(err as Error).message}`);
    }
  }
  printSummary(counts, items, args);

  // 6) CI gate: nonzero if any finding is at or above the fail-on severity.
  const threshold = SEVERITY_RANK[args.failOn];
  const gate = items.some((f) => (SEVERITY_RANK[f.severity] ?? 99) <= threshold);
  if (gate && exitCode === 0) exitCode = 1;
  return exitCode;
}
