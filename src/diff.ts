import { readFileSync } from "node:fs";
import { parseLine } from "./engine/parser.js";
import { parsePath } from "./engine/jsonpath.js";
import { MessagePipeline } from "./core/pipeline.js";
import { makeStdioClient, makeHttpClient, type ScanClient } from "./core/scan.js";
import { builtinLinters } from "./detect/linter.js";
import {
  ArrayFindingsSink,
  writeFindingsDir,
  bySeverity,
  fingerprint,
  type Finding,
  type Severity,
} from "./findings.js";
import { Logger } from "./logger.js";
import type { FlowMessage } from "./types.js";

/**
 * Differential record/replay (Phase 10 / D1).
 *
 *   mcpwn diff <golden-session.jsonl> [options] -- <server> [args...]
 *   mcpwn diff <golden-session.jsonl> --http <url> [options]
 *
 * Replays the client->server requests captured in a golden session JSONL against
 * a (possibly updated) server, captures the LIVE responses, and diffs them vs the
 * golden responses — surfacing changed shapes/values, added/removed tools or
 * fields, and NEWLY-INTRODUCED injection surfaces (detectors run over the live
 * responses; any finding absent from the golden run is reported).
 *
 * A golden session is any JSONL recorded by mcpwn (the proxy's `--log`, or
 * `mcpwn scan --log <file>`): each line carries `direction`, `kind` and the exact
 * `raw` wire bytes, so we can both replay the requests and recover the golden
 * responses by JSON-RPC id.
 *
 * It REUSES scan.ts's MCP client (handshake/id-correlation/ping/timeouts/clean
 * shutdown) so a drifted or non-responding server can never hang the diff: every
 * request is bounded by a per-call timeout and the target is always killed on
 * exit. Normalising volatile fields (ids, timestamps, a configurable `--ignore`
 * list) before diffing keeps non-determinism from showing up as false drift.
 */

export class DiffArgError extends Error {}

export interface DiffArgs {
  goldenFile?: string;
  /** HTTP target URL; mutually exclusive with a stdio command. */
  http?: string;
  command?: string;
  commandArgs: string[];
  /** JSON paths (dotted/bracket, relative to each response message) to drop
   *  before diffing — volatile fields that would otherwise read as false drift. */
  ignore: string[];
  findingsOut?: string;
  /** Exit nonzero if any drift/injection finding is at or above this severity. */
  failOn: Severity;
  /** Per-call timeout (ms). */
  timeoutMs: number;
  verbose: boolean;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function parseDiffArgs(argv: string[]): DiffArgs {
  const out: DiffArgs = {
    commandArgs: [],
    ignore: [],
    failOn: "medium",
    timeoutMs: 8000,
    verbose: false,
  };
  let i = 0;
  const value = (flag: string): string => {
    const v = argv[++i];
    if (v === undefined) throw new DiffArgError(`option ${flag} requires an argument`);
    return v;
  };
  const posInt = (flag: string): number => {
    const n = Number(value(flag));
    if (!Number.isInteger(n) || n < 0)
      throw new DiffArgError(`option ${flag} must be a non-negative integer`);
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
      case "--ignore":
        out.ignore.push(value(a));
        break;
      case "--findings-out":
        out.findingsOut = value(a);
        break;
      case "--fail-on": {
        const v = value(a) as Severity;
        if (!SEVERITIES.includes(v)) {
          throw new DiffArgError(
            `option --fail-on must be one of ${SEVERITIES.join("|")} (got "${v}")`
          );
        }
        out.failOn = v;
        break;
      }
      case "--timeout":
        out.timeoutMs = posInt(a);
        break;
      case "-v":
      case "--verbose":
        out.verbose = true;
        break;
      default:
        if (a.startsWith("-")) {
          throw new DiffArgError(
            `unknown option "${a}" - put the server command (and its flags) after "--"`
          );
        }
        if (out.goldenFile === undefined) {
          out.goldenFile = a;
          break;
        }
        // Second bare token starts the server command (no "--" required).
        out.command = a;
        out.commandArgs = argv.slice(i + 1);
        return out;
    }
  }
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

interface SessionRecord {
  raw: string;
  direction?: string;
  kind?: string;
  method?: string;
}

interface GoldenRequest {
  raw: string;
  method: string;
  id?: unknown;
  params: unknown;
  isNotification: boolean;
}

/** Extract the client->server requests/notifications to replay, in order, plus
 *  a by-id index of the golden server->client responses to diff against. */
function parseGolden(records: SessionRecord[]): {
  requests: GoldenRequest[];
  responses: Map<string, any>;
} {
  const requests: GoldenRequest[] = [];
  const responses = new Map<string, any>();
  for (const r of records) {
    if (typeof r.raw !== "string") continue;
    const parsed = parseLine(r.raw);
    const kind = r.kind ?? parsed.kind;
    if (r.direction === "client->server" && (kind === "request" || kind === "notification")) {
      const method = r.method ?? parsed.method;
      if (typeof method !== "string") continue;
      requests.push({
        raw: r.raw,
        method,
        id: parsed.json?.id,
        params: parsed.json?.params,
        isNotification: kind === "notification" || parsed.json?.id === undefined,
      });
    } else if (r.direction === "server->client" && (kind === "response" || kind === "error")) {
      if (parsed.json && parsed.json.id !== undefined) {
        responses.set(JSON.stringify(parsed.json.id), parsed.json);
      }
    }
  }
  return { requests, responses };
}

// --- normalisation (defeat false-positive non-determinism) -----------------

const ISO_TS = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/g;

/** Recursively replace ISO-8601 timestamps inside string values with a stable
 *  placeholder so a changing clock never reads as drift. */
function scrubTimestamps(v: any): any {
  if (typeof v === "string") return v.replace(ISO_TS, "<ts>");
  if (Array.isArray(v)) return v.map(scrubTimestamps);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v)) out[k] = scrubTimestamps(v[k]);
    return out;
  }
  return v;
}

/** Delete a dotted/bracket path from a cloned object (no-op if it is absent). */
function deletePath(root: any, path: string): void {
  let segs: (string | number)[];
  try {
    segs = parsePath(path);
  } catch {
    return; // malformed ignore path: skip rather than abort the diff
  }
  let node: any = root;
  for (let i = 0; i < segs.length - 1; i++) {
    if (node === null || typeof node !== "object") return;
    node = node[segs[i] as any];
  }
  if (node === null || typeof node !== "object") return;
  const last = segs[segs.length - 1];
  if (Array.isArray(node) && typeof last === "number") node.splice(last, 1);
  else delete node[last as any];
}

/** Re-key the known list surfaces by item name/uri so added/removed items show
 *  by name instead of by brittle array index. */
function canonicalizeSurfaces(method: string | undefined, json: any): any {
  const result = json?.result;
  if (!method || !result || typeof result !== "object") return json;
  const rekey = (key: string, idField: string) => {
    const arr = result[key];
    if (!Array.isArray(arr)) return;
    const map: Record<string, unknown> = {};
    for (const item of arr) {
      const name = item && typeof item === "object" ? item[idField] : undefined;
      map[typeof name === "string" ? name : JSON.stringify(item)] = item;
    }
    result[key] = map;
  };
  if (method === "tools/list") rekey("tools", "name");
  else if (method === "resources/list") rekey("resources", "uri");
  else if (method === "prompts/list") rekey("prompts", "name");
  return json;
}

/** Normalise a response for diffing: drop ignored paths, null the JSON-RPC id,
 *  scrub timestamps, and re-key list surfaces. Operates on a deep clone. */
function normalizeResponse(method: string | undefined, json: any, ignore: string[]): any {
  let clone = JSON.parse(JSON.stringify(json));
  for (const p of ignore) deletePath(clone, p);
  if (clone && typeof clone === "object" && "id" in clone) clone.id = null;
  clone = scrubTimestamps(clone);
  clone = canonicalizeSurfaces(method, clone);
  return clone;
}

// --- structural diff --------------------------------------------------------

type ChangeType = "changed" | "added" | "removed";

interface Change {
  path: string[];
  type: ChangeType;
  old?: unknown;
  new?: unknown;
}

function deepDiff(golden: any, live: any, path: string[], out: Change[]): void {
  if (golden === live) return;
  const gObj = golden && typeof golden === "object";
  const lObj = live && typeof live === "object";
  if (!gObj || !lObj || Array.isArray(golden) !== Array.isArray(live)) {
    if (JSON.stringify(golden) !== JSON.stringify(live)) {
      out.push({ path, type: "changed", old: golden, new: live });
    }
    return;
  }
  if (Array.isArray(golden) && Array.isArray(live)) {
    const n = Math.max(golden.length, live.length);
    for (let i = 0; i < n; i++) {
      if (i >= golden.length) out.push({ path: [...path, String(i)], type: "added", new: live[i] });
      else if (i >= live.length)
        out.push({ path: [...path, String(i)], type: "removed", old: golden[i] });
      else deepDiff(golden[i], live[i], [...path, String(i)], out);
    }
    return;
  }
  const keys = new Set([...Object.keys(golden), ...Object.keys(live)]);
  for (const k of keys) {
    const inG = k in golden;
    const inL = k in live;
    if (inG && !inL) out.push({ path: [...path, k], type: "removed", old: golden[k] });
    else if (!inG && inL) out.push({ path: [...path, k], type: "added", new: live[k] });
    else deepDiff(golden[k], live[k], [...path, k], out);
  }
}

/** Is a change at the top level of a list surface (i.e. a whole tool/resource/
 *  prompt added or removed), vs a field within one? */
function isSurfaceItem(path: string[]): boolean {
  return (
    path.length === 3 &&
    path[0] === "result" &&
    (path[1] === "tools" || path[1] === "resources" || path[1] === "prompts")
  );
}

/** Classify a structural change into a finding id + severity. */
function classifyChange(change: Change): { id: string; severity: Severity } {
  if (change.type === "added" && isSurfaceItem(change.path)) {
    return { id: "surface-added", severity: "high" };
  }
  if (change.type === "removed" && isSurfaceItem(change.path)) {
    return { id: "surface-removed", severity: "low" };
  }
  return { id: "response-drift", severity: "medium" };
}

function truncate(v: unknown, max = 160): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (s === undefined) return "undefined";
  return s.length > max ? s.slice(0, max) + "…" : s;
}

// --- driver -----------------------------------------------------------------

/** Run the golden session's lines through a fresh pipeline (both directions, in
 *  order) so correlation resolves response methods, then return the findings the
 *  detectors recorded over the GOLDEN responses. */
function goldenFindings(records: SessionRecord[]): Promise<Finding[]> {
  const sink = new ArrayFindingsSink();
  const logger = new Logger({});
  const pipeline = new MessagePipeline({
    rules: [],
    logger,
    detectors: builtinLinters(),
    findings: sink,
    // A scope matching nothing keeps this replay-for-detection pass silent on
    // stderr (detectors still run — they fire before the scope gate) so the
    // golden lines are not re-printed under the live run's message log.
    scope: { methods: ["\u0000mcpwn-golden-silent"] },
  });
  return (async () => {
    for (const r of records) {
      if (typeof r.raw !== "string") continue;
      const direction = r.direction === "server->client" ? "server->client" : "client->server";
      await pipeline.process(r.raw, direction);
    }
    return sink.all();
  })();
}

export async function runDiff(argv: string[]): Promise<number> {
  let args: DiffArgs;
  try {
    args = parseDiffArgs(argv);
  } catch (err) {
    if (err instanceof DiffArgError) {
      process.stderr.write(`mcpwn diff: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  if (!args.goldenFile) {
    process.stderr.write("mcpwn diff: missing <golden-session.jsonl>\n");
    return 2;
  }
  if (args.http && args.command) {
    process.stderr.write("mcpwn diff: use either --http <url> OR a -- <command>, not both\n");
    return 2;
  }
  if (!args.http && !args.command) {
    process.stderr.write(
      'mcpwn diff: missing target - give --http <url> or a server command after "--"\n'
    );
    return 2;
  }

  const logger = new Logger({ verbose: args.verbose });

  let records: SessionRecord[];
  try {
    records = readFileSync(args.goldenFile, "utf8")
      .split(/\r?\n/)
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as SessionRecord);
  } catch (err) {
    logger.error(`could not read golden session "${args.goldenFile}": ${(err as Error).message}`);
    return 2;
  }

  const { requests, responses } = parseGolden(records);
  if (requests.length === 0) {
    logger.info("no client->server requests to replay in the golden session");
    return 0;
  }

  logger.info(
    `diffing: replaying ${requests.length} request(s) from ${args.goldenFile} against ` +
      (args.http ? args.http : `${args.command} ${args.commandArgs.join(" ")}`.trim())
  );

  // Live run: detectors attached so injection surfaces in the NEW responses are
  // recorded as findings automatically as each reply flows through the pipeline.
  const liveSink = new ArrayFindingsSink();
  const livePipeline = new MessagePipeline({
    rules: [],
    logger,
    detectors: builtinLinters(),
    findings: liveSink,
  });

  let client: ScanClient;
  try {
    client = args.http
      ? await makeHttpClient(args.http, livePipeline)
      : await makeStdioClient(args.command!, args.commandArgs, livePipeline, logger);
  } catch (err) {
    logger.error(`could not start target: ${(err as Error).message}`);
    return 1;
  }

  const changes: Array<{ method: string; change: Change }> = [];
  const driftFindings: Finding[] = [];

  try {
    for (const req of requests) {
      if (req.isNotification) {
        client.notify(req.method, req.params);
        continue;
      }
      let live: FlowMessage | undefined;
      try {
        live = await client.request(req.method, req.params, args.timeoutMs);
      } catch {
        // Golden had a response but the live server did not answer in time.
        driftFindings.push({
          id: "response-drift",
          severity: "high",
          title: `No live response for ${req.method} (golden had one)`,
          method: req.method,
          description:
            "The server returned a response for this request in the golden session but did not answer within the timeout on replay.",
          ts: Date.now(),
        });
        continue;
      }
      const golden = req.id !== undefined ? responses.get(JSON.stringify(req.id)) : undefined;
      if (golden === undefined) continue; // no recorded golden response to diff against
      const normGolden = normalizeResponse(req.method, golden, args.ignore);
      const normLive = normalizeResponse(req.method, live.json, args.ignore);
      const diff: Change[] = [];
      deepDiff(normGolden, normLive, [], diff);
      for (const c of diff) {
        changes.push({ method: req.method, change: c });
        const cls = classifyChange(c);
        const tool = isSurfaceItem(c.path) ? c.path[2] : undefined;
        driftFindings.push({
          id: cls.id,
          severity: cls.severity,
          title: `${c.type} at ${req.method} ${c.path.join(".") || "(root)"}`,
          method: req.method,
          tool,
          direction: "server->client",
          evidence:
            c.type === "changed"
              ? `- ${truncate(c.old)}\n+ ${truncate(c.new)}`
              : c.type === "added"
                ? `+ ${truncate(c.new)}`
                : `- ${truncate(c.old)}`,
          description: `Response ${c.type} vs the golden session at path "${c.path.join(".") || "(root)"}".`,
          ts: Date.now(),
        });
      }
    }
  } finally {
    await client.close();
  }

  // Newly-introduced injection surfaces: live findings whose fingerprint was not
  // present when the detectors ran over the GOLDEN responses.
  const goldenF = await goldenFindings(records);
  const goldenPrints = new Set(goldenF.map(fingerprint));
  const newFindings = liveSink.all().filter((f) => !goldenPrints.has(fingerprint(f)));

  const allFindings = [...driftFindings, ...newFindings];

  // --- readable report (stdout) ---
  const w = process.stdout;
  w.write("mcpwn diff report\n");
  w.write(`  golden:   ${args.goldenFile}\n`);
  w.write(`  target:   ${args.http ?? `${args.command} ${args.commandArgs.join(" ")}`.trim()}\n`);
  w.write(`  replayed: ${requests.length} request(s)\n`);
  w.write("\n");

  if (changes.length === 0 && driftFindings.length === 0) {
    w.write("DRIFT: none - live responses match the golden session.\n");
  } else {
    w.write(`DRIFT (${driftFindings.length} change(s))\n`);
    for (const f of bySeverity(driftFindings)) {
      w.write(`  [${f.severity}] ${f.title}\n`);
      if (f.evidence) for (const line of f.evidence.split("\n")) w.write(`      ${line}\n`);
    }
  }
  w.write("\n");

  if (newFindings.length === 0) {
    w.write("NEW INJECTION SURFACES: none.\n");
  } else {
    w.write(`NEW INJECTION SURFACES (${newFindings.length})\n`);
    for (const f of bySeverity(newFindings)) {
      w.write(`  [${f.severity}] ${f.id} - ${f.title}\n`);
      if (f.evidence) w.write(`      ${truncate(f.evidence, 200)}\n`);
    }
  }
  w.write("\n");

  if (args.findingsOut) {
    try {
      writeFindingsDir(args.findingsOut, allFindings);
      logger.info(`wrote ${allFindings.length} finding(s) -> ${args.findingsOut}`);
    } catch (err) {
      logger.error(`could not write findings: ${(err as Error).message}`);
    }
  }

  // CI gate: nonzero if any drift/injection finding is at or above --fail-on.
  const threshold = SEVERITY_RANK[args.failOn];
  const gate = allFindings.some((f) => (SEVERITY_RANK[f.severity] ?? 99) <= threshold);
  return gate ? 1 : 0;
}
