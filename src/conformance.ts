import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";
import { writeFileSync } from "node:fs";
import { LineFramer } from "./engine/parser.js";
import { ArrayFindingsSink, writeFindingsDir, type Finding } from "./findings.js";
import { Logger } from "./logger.js";

/**
 * MCP spec conformance checker (Phase 10 / D2).
 *
 *   mcpwn conformance [options] -- <server> [args...]   (stdio)
 *   mcpwn conformance --http <url> [options]            (streamable HTTP)
 *
 * Asserts a server honours the MCP / JSON-RPC 2.0 contract. Each check is
 * pass/warn/fail with a clear message:
 *   - JSON-RPC 2.0 framing (every reply carries jsonrpc:"2.0")
 *   - initialize returns protocolVersion + capabilities
 *   - responds to ping
 *   - unknown method => -32601
 *   - malformed request => -32700 / -32600 (recommended; warn if silently dropped)
 *   - response id echoes the request id
 *   - no response to a notification (response/id confusion)
 *   - NO non-JSON-RPC lines on stdout (the classic MCP stdio footgun)
 *   - capability/method consistency (advertises tools => tools/list works, …)
 *   - pagination cursor behaviour (if a list used one)
 *
 * Spec violations that are ALSO security-relevant (id confusion, replying to a
 * notification, non-JSON-RPC stdout that can desync a host) are recorded as
 * findings via findings.ts. Exits nonzero on any FAIL.
 *
 * It MIRRORS scan.ts's client discipline — spawn/frame stdout, answer pings,
 * per-call timeouts, SIGTERM→SIGKILL shutdown — so a misbehaving server can
 * never hang the checker. Unlike the scan client it also keeps RAW stdout lines
 * (to catch the non-JSON footgun) and can send RAW malformed bytes.
 */

export class ConformanceArgError extends Error {}

export interface ConformanceArgs {
  http?: string;
  command?: string;
  commandArgs: string[];
  /** Per-call timeout for a reply that IS expected (ms). */
  timeoutMs: number;
  /** Window to wait while asserting NO reply arrives (ms). */
  noReplyMs: number;
  /** Write the pass/warn/fail report as JSON to this file. */
  jsonOut?: string;
  findingsOut?: string;
  verbose: boolean;
}

export function parseConformanceArgs(argv: string[]): ConformanceArgs {
  const out: ConformanceArgs = {
    commandArgs: [],
    timeoutMs: 8000,
    noReplyMs: 800,
    verbose: false,
  };
  let i = 0;
  const value = (flag: string): string => {
    const v = argv[++i];
    if (v === undefined) throw new ConformanceArgError(`option ${flag} requires an argument`);
    return v;
  };
  const posInt = (flag: string): number => {
    const n = Number(value(flag));
    if (!Number.isInteger(n) || n < 0)
      throw new ConformanceArgError(`option ${flag} must be a non-negative integer`);
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
      case "--timeout":
        out.timeoutMs = posInt(a);
        break;
      case "--no-reply-window":
        out.noReplyMs = posInt(a);
        break;
      case "--json":
        out.jsonOut = value(a);
        break;
      case "--findings-out":
        out.findingsOut = value(a);
        break;
      case "-v":
      case "--verbose":
        out.verbose = true;
        break;
      default:
        if (a.startsWith("-")) {
          throw new ConformanceArgError(
            `unknown option "${a}" — put the server command (and its flags) after "--"`
          );
        }
        out.command = a;
        out.commandArgs = argv.slice(i + 1);
        return out;
    }
  }
  out.command = argv[i];
  out.commandArgs = argv.slice(i + 1);
  return out;
}

export type CheckStatus = "pass" | "warn" | "fail" | "skip";

export interface CheckResult {
  id: string;
  status: CheckStatus;
  message: string;
}

/** A low-level probe against the target: send JSON-RPC (or raw bytes), await a
 *  correlated reply, and (stdio only) expose any non-JSON-RPC stdout lines. */
interface Probe {
  /** Send a JSON-RPC message and await the reply (by id for stdio; the single
   *  HTTP reply otherwise). Resolves null on timeout. */
  request(obj: any, timeoutMs: number): Promise<any | null>;
  /** Send a raw line/body and await the next reply, resolving null on timeout.
   *  Used to probe malformed-input handling. */
  sendRaw(raw: string, timeoutMs: number): Promise<any | null>;
  /** Send a notification (no id) and report whether the server (wrongly) replied
   *  within the window. */
  notify(obj: any, windowMs: number): Promise<{ replied: boolean; raw?: any }>;
  /** Non-JSON-RPC lines observed on stdout (stdio only; [] for HTTP). */
  nonJsonLines(): string[];
  close(): Promise<void>;
}

// --- stdio probe (mirrors scan.ts makeStdioClient discipline) --------------

function makeStdioProbe(command: string, args: string[], logger: Logger): Promise<Probe> {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
  const framer = new LineFramer();
  const pendingById = new Map<string, (msg: any) => void>();
  const nonJson: string[] = [];
  // Responses that arrived with no id waiter (unsolicited / malformed replies).
  let anyWaiter: ((msg: any) => void) | null = null;
  const anyQueue: any[] = [];

  const send = (obj: unknown): void => {
    try {
      child.stdin.write(JSON.stringify(obj) + "\n");
    } catch {
      /* child stdin gone */
    }
  };
  const sendLine = (line: string): void => {
    try {
      child.stdin.write(line + "\n");
    } catch {
      /* child stdin gone */
    }
  };

  const deliverResponse = (msg: any): void => {
    const key = msg.id !== undefined ? JSON.stringify(msg.id) : undefined;
    if (key !== undefined && pendingById.has(key)) {
      const resolve = pendingById.get(key)!;
      pendingById.delete(key);
      resolve(msg);
      return;
    }
    if (anyWaiter) {
      const w = anyWaiter;
      anyWaiter = null;
      w(msg);
      return;
    }
    anyQueue.push(msg);
  };

  const onLine = (line: string): void => {
    let msg: any;
    try {
      msg = JSON.parse(line);
    } catch {
      nonJson.push(line); // the classic stdio footgun: non-JSON on the channel
      return;
    }
    if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
      nonJson.push(line); // valid JSON but not a JSON-RPC object
      return;
    }
    // A server-initiated request: answer ping, otherwise ignore (like scan).
    if (typeof msg.method === "string") {
      if (msg.method === "ping" && msg.id !== undefined) {
        send({ jsonrpc: "2.0", id: msg.id, result: {} });
      }
      return;
    }
    if ("result" in msg || "error" in msg) deliverResponse(msg);
  };

  child.stdout.on("data", (chunk: Buffer) => {
    for (const line of framer.push(chunk)) onLine(line);
  });

  return new Promise<Probe>((resolve, reject) => {
    child.once("spawn", () => {
      child.on("error", (err) => logger.error(`target stream error: ${(err as Error).message}`));
      resolve({
        request(obj, timeoutMs) {
          return new Promise<any | null>((res) => {
            const key = JSON.stringify(obj.id);
            const timer = setTimeout(() => {
              pendingById.delete(key);
              res(null);
            }, timeoutMs);
            timer.unref();
            pendingById.set(key, (msg) => {
              clearTimeout(timer);
              res(msg);
            });
            send(obj);
          });
        },
        sendRaw(raw, timeoutMs) {
          return new Promise<any | null>((res) => {
            if (anyQueue.length) return res(anyQueue.shift());
            const timer = setTimeout(() => {
              anyWaiter = null;
              res(null);
            }, timeoutMs);
            timer.unref();
            anyWaiter = (msg) => {
              clearTimeout(timer);
              res(msg);
            };
            sendLine(raw);
          });
        },
        notify(obj, windowMs) {
          return new Promise<{ replied: boolean; raw?: any }>((res) => {
            const timer = setTimeout(() => {
              anyWaiter = null;
              res({ replied: false });
            }, windowMs);
            timer.unref();
            anyWaiter = (msg) => {
              clearTimeout(timer);
              res({ replied: true, raw: msg });
            };
            send(obj);
          });
        },
        nonJsonLines() {
          return nonJson;
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
          await new Promise<void>((r) => {
            const t = setTimeout(() => {
              try {
                child.kill("SIGKILL");
              } catch {
                /* ignore */
              }
              r();
            }, 500);
            t.unref();
            child.once("close", () => {
              clearTimeout(t);
              r();
            });
          });
        },
      });
    });
    child.once("error", (err) => reject(err));
  });
}

// --- http probe (mirrors scan.ts makeHttpClient discipline) ----------------

function makeHttpProbe(urlStr: string): Probe {
  const url = new URL(urlStr);
  const isHttps = url.protocol === "https:";
  const mod = isHttps ? https : http;
  let sessionId: string | undefined;
  let protocolVersion: string | undefined;

  interface HttpReply {
    status: number;
    contentType: string;
    body: string;
  }
  const post = (body: string, timeoutMs: number): Promise<HttpReply> =>
    new Promise<HttpReply>((resolve, reject) => {
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
          res.on("end", () => {
            const sid = res.headers["mcp-session-id"];
            if (typeof sid === "string") sessionId = sid;
            resolve({
              status: res.statusCode ?? 0,
              contentType: String(res.headers["content-type"] ?? ""),
              body: Buffer.concat(chunks).toString("utf8"),
            });
          });
          res.on("error", reject);
        }
      );
      req.on("error", reject);
      req.setTimeout(timeoutMs, () => req.destroy(new Error("http request timed out")));
      req.write(body);
      req.end();
    });

  const extract = (reply: HttpReply): any | null => {
    if (reply.contentType.toLowerCase().includes("text/event-stream")) {
      for (const block of reply.body.split(/\r\n\r\n|\n\n|\r\r/)) {
        const payload = block
          .split(/\r\n|\n|\r/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.replace(/^data: ?/, ""))
          .join("\n")
          .trim();
        if (!payload) continue;
        try {
          return JSON.parse(payload);
        } catch {
          /* keep scanning */
        }
      }
      return null;
    }
    const t = reply.body.trim();
    if (!t) return null;
    try {
      return JSON.parse(t);
    } catch {
      return null;
    }
  };

  return {
    async request(obj, timeoutMs) {
      let reply: HttpReply;
      try {
        reply = await post(JSON.stringify(obj), timeoutMs);
      } catch {
        return null;
      }
      const msg = extract(reply);
      if (msg && obj.method === "initialize") {
        const pv = msg.result?.protocolVersion;
        if (typeof pv === "string") protocolVersion = pv;
      }
      return msg;
    },
    async sendRaw(raw, timeoutMs) {
      let reply: HttpReply;
      try {
        reply = await post(raw, timeoutMs);
      } catch {
        return null;
      }
      // A 4xx with no JSON-RPC body still means "rejected"; surface a synthetic
      // marker so the malformed check can distinguish it from silence.
      const msg = extract(reply);
      if (msg) return msg;
      if (reply.status >= 400) return { __httpStatus: reply.status };
      return null;
    },
    async notify(obj, windowMs) {
      try {
        const reply = await post(JSON.stringify(obj), windowMs);
        const msg = extract(reply);
        // Spec: a notification gets 202 Accepted with no body. A JSON-RPC reply
        // body is a violation.
        return msg ? { replied: true, raw: msg } : { replied: false };
      } catch {
        return { replied: false };
      }
    },
    nonJsonLines() {
      return [];
    },
    async close() {
      /* nothing persistent to tear down */
    },
  };
}

// --- checks -----------------------------------------------------------------

const PROTOCOL_VERSION = "2024-11-05";
const CLIENT_INFO = { name: "mcpwn-conformance", version: "0.0.0" };

function isJsonRpc(msg: any): boolean {
  return !!msg && typeof msg === "object" && msg.jsonrpc === "2.0";
}

/** Run every conformance check against the probe, returning the results and any
 *  security findings. Always bounded — never hangs. */
async function runChecks(
  probe: Probe,
  args: ConformanceArgs,
  isHttp: boolean,
  findings: ArrayFindingsSink
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const add = (id: string, status: CheckStatus, message: string) =>
    results.push({ id, status, message });

  // 1) initialize — framing + protocolVersion + capabilities.
  const initId = "mcpwn-init-1";
  const init = await probe.request(
    {
      jsonrpc: "2.0",
      id: initId,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {}, resources: {}, prompts: {}, sampling: {} },
        clientInfo: CLIENT_INFO,
      },
    },
    args.timeoutMs
  );

  if (!init) {
    add("initialize", "fail", "no response to initialize within timeout");
    add("jsonrpc-framing", "fail", "no reply to frame-check against");
    // Without a handshake most other checks are meaningless; still probe ping +
    // stdout so the report is useful, then return.
  } else {
    add(
      "jsonrpc-framing",
      isJsonRpc(init) ? "pass" : "fail",
      `initialize reply jsonrpc=${init.jsonrpc}`
    );
    const pv = init.result?.protocolVersion;
    const caps = init.result?.capabilities;
    if (typeof pv === "string" && caps && typeof caps === "object") {
      add(
        "initialize",
        "pass",
        `protocolVersion=${pv}, capabilities=[${Object.keys(caps).join(", ") || "none"}]`
      );
    } else {
      add(
        "initialize",
        "fail",
        `initialize result must carry protocolVersion (string) + capabilities (object); got pv=${typeof pv}, caps=${typeof caps}`
      );
    }
    // id echo.
    if (init.id === initId) {
      add("id-echo", "pass", "response id echoes the request id");
    } else {
      add(
        "id-echo",
        "fail",
        `response id ${JSON.stringify(init.id)} does not echo request id ${JSON.stringify(initId)}`
      );
      findings.add({
        id: "jsonrpc-id-confusion",
        severity: "high",
        title: "Response id does not echo the request id",
        method: "initialize",
        description:
          "The server returned a response whose id did not match the request id. A client correlates replies by id; a mismatched or reused id can cause response confusion (one request's result attributed to another).",
        remediation: "Echo the exact request id on every response, per JSON-RPC 2.0.",
        ts: Date.now(),
      });
    }
    // The initialized notification is a normal part of the handshake; also doubles
    // as a notification probe later.
  }

  // 2) ping.
  const ping = await probe.request(
    { jsonrpc: "2.0", id: "mcpwn-ping-1", method: "ping" },
    args.timeoutMs
  );
  if (ping && (("result" in ping && !ping.error) || isJsonRpc(ping))) {
    add(
      "ping",
      ping.error ? "warn" : "pass",
      ping.error ? `ping returned an error: ${ping.error?.code}` : "server answered ping"
    );
  } else {
    add("ping", "fail", "server did not answer ping");
  }

  // 3) unknown method => -32601.
  const unknown = await probe.request(
    { jsonrpc: "2.0", id: "mcpwn-unknown-1", method: "mcpwn/definitely/not/a/method" },
    args.timeoutMs
  );
  if (!unknown) {
    add("unknown-method", "fail", "no response to an unknown method (expected error -32601)");
  } else if (unknown.error && unknown.error.code === -32601) {
    add("unknown-method", "pass", "unknown method returns -32601 (Method not found)");
  } else if (unknown.error) {
    add(
      "unknown-method",
      "fail",
      `unknown method returned error ${unknown.error.code}, expected -32601`
    );
  } else {
    add("unknown-method", "fail", "unknown method returned a result instead of error -32601");
  }

  // 4) malformed request. Recommended -32700 (parse) / -32600 (invalid); many
  //    stdio servers silently drop it, which we only WARN on (not a hard fail).
  const malformed = await probe.sendRaw(
    isHttp ? "{ this is not valid json" : "{not valid json",
    args.noReplyMs
  );
  if (
    malformed &&
    malformed.error &&
    (malformed.error.code === -32700 || malformed.error.code === -32600)
  ) {
    add("malformed-request", "pass", `malformed input returns ${malformed.error.code}`);
  } else if (malformed && malformed.error) {
    add(
      "malformed-request",
      "warn",
      `malformed input returned error ${malformed.error.code} (spec recommends -32700/-32600)`
    );
  } else if (malformed && malformed.__httpStatus) {
    add(
      "malformed-request",
      "warn",
      `malformed input rejected with HTTP ${malformed.__httpStatus} (spec recommends a JSON-RPC -32700 body)`
    );
  } else {
    add(
      "malformed-request",
      "warn",
      "malformed input silently ignored (spec recommends replying -32700)"
    );
  }

  // 5) no reply to a notification (response/id confusion).
  const notif = await probe.notify(
    { jsonrpc: "2.0", method: "notifications/initialized" },
    args.noReplyMs
  );
  if (notif.replied) {
    add(
      "no-reply-to-notification",
      "fail",
      "server replied to a notification (which has no id) — response confusion"
    );
    findings.add({
      id: "jsonrpc-response-confusion",
      severity: "high",
      title: "Server replied to a notification",
      description:
        "The server sent a response to a JSON-RPC notification. Notifications carry no id and MUST NOT be answered; an unexpected reply can be mis-correlated with a later request (response confusion).",
      remediation: "Never emit a response for a message without an id.",
      ts: Date.now(),
    });
  } else {
    add("no-reply-to-notification", "pass", "server correctly sent no reply to a notification");
  }

  // 6) capability/method consistency + 7) pagination (needs the handshake).
  const caps = init?.result?.capabilities ?? {};
  const listChecks: Array<[string, string, string]> = [
    ["tools", "tools/list", "tools"],
    ["resources", "resources/list", "resources"],
    ["prompts", "prompts/list", "prompts"],
  ];
  let paginationNoted = false;
  for (const [cap, method, key] of listChecks) {
    if (!(cap in caps)) continue; // not advertised → nothing to assert
    const reply = await probe.request(
      { jsonrpc: "2.0", id: `mcpwn-${cap}-1`, method, params: {} },
      args.timeoutMs
    );
    if (!reply) {
      add("capability-consistency", "fail", `advertises "${cap}" but ${method} did not respond`);
      continue;
    }
    if (reply.error) {
      add(
        "capability-consistency",
        "fail",
        `advertises "${cap}" but ${method} returned error ${reply.error.code}`
      );
      continue;
    }
    if (!Array.isArray(reply.result?.[key])) {
      add(
        "capability-consistency",
        "fail",
        `advertises "${cap}" but ${method} result has no "${key}" array`
      );
      continue;
    }
    add(
      "capability-consistency",
      "pass",
      `advertises "${cap}" and ${method} returns a "${key}" array`
    );
    // Pagination: if a cursor was handed out, a follow-up must still return a result.
    const cursor = reply.result?.nextCursor;
    if (typeof cursor === "string" && cursor.length > 0) {
      paginationNoted = true;
      const next = await probe.request(
        { jsonrpc: "2.0", id: `mcpwn-${cap}-2`, method, params: { cursor } },
        args.timeoutMs
      );
      if (next && !next.error && next.result) {
        add("pagination", "pass", `${method} honoured a nextCursor follow-up`);
      } else {
        add(
          "pagination",
          "warn",
          `${method} handed out a nextCursor but the follow-up did not return a result`
        );
      }
    }
  }
  if (!results.some((r) => r.id === "capability-consistency")) {
    add(
      "capability-consistency",
      "skip",
      "server advertised no tools/resources/prompts capabilities"
    );
  }
  if (!paginationNoted) {
    add("pagination", "pass", "no pagination cursor was used");
  }

  // 8) stdout cleanliness (stdio footgun). HTTP has no stdout channel.
  if (isHttp) {
    add("stdout-clean", "skip", "not applicable over HTTP");
  } else {
    const bad = probe.nonJsonLines();
    if (bad.length === 0) {
      add("stdout-clean", "pass", "only JSON-RPC appeared on stdout");
    } else {
      add(
        "stdout-clean",
        "fail",
        `${bad.length} non-JSON-RPC line(s) on stdout — e.g. ${JSON.stringify(bad[0].slice(0, 80))}`
      );
      findings.add({
        id: "stdio-non-jsonrpc-output",
        severity: "medium",
        title: "Non-JSON-RPC output on stdout",
        direction: "server->client",
        evidence: bad.slice(0, 3).join("\n"),
        description:
          "The server wrote non-JSON-RPC text to stdout, the MCP stdio message channel. Stray stdout desynchronises the framing and can corrupt or inject into the message stream a host parses as trusted. Logs belong on stderr.",
        remediation:
          "Write all logging/banners to stderr; keep stdout exclusively for JSON-RPC messages.",
        ts: Date.now(),
      });
    }
  }

  return results;
}

const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "PASS",
  warn: "WARN",
  fail: "FAIL",
  skip: "SKIP",
};

function printReport(results: CheckResult[], target: string): void {
  const w = process.stdout;
  w.write("mcpwn conformance report\n");
  w.write(`  target: ${target}\n\n`);
  const counts: Record<CheckStatus, number> = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const r of results) {
    counts[r.status]++;
    w.write(`  [${STATUS_LABEL[r.status]}] ${r.id}: ${r.message}\n`);
  }
  w.write(
    `\n  summary: ${counts.pass} pass, ${counts.warn} warn, ${counts.fail} fail, ${counts.skip} skip\n`
  );
}

export async function runConformance(argv: string[]): Promise<number> {
  let args: ConformanceArgs;
  try {
    args = parseConformanceArgs(argv);
  } catch (err) {
    if (err instanceof ConformanceArgError) {
      process.stderr.write(`mcpwn conformance: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  if (args.http && args.command) {
    process.stderr.write(
      "mcpwn conformance: use either --http <url> OR a -- <command>, not both\n"
    );
    return 2;
  }
  if (!args.http && !args.command) {
    process.stderr.write(
      'mcpwn conformance: missing target — give --http <url> or a server command after "--"\n'
    );
    return 2;
  }

  const logger = new Logger({ verbose: args.verbose });
  const findings = new ArrayFindingsSink();
  const target = args.http ?? `${args.command} ${args.commandArgs.join(" ")}`.trim();
  logger.info(`checking conformance of ${target}`);

  let probe: Probe;
  try {
    probe = args.http
      ? makeHttpProbe(args.http)
      : await makeStdioProbe(args.command!, args.commandArgs, logger);
  } catch (err) {
    logger.error(`could not start target: ${(err as Error).message}`);
    return 1;
  }

  let results: CheckResult[];
  try {
    results = await runChecks(probe, args, !!args.http, findings);
  } catch (err) {
    logger.error(`conformance aborted: ${(err as Error).message}`);
    results = [];
  } finally {
    await probe.close();
  }

  printReport(results, target);

  if (args.jsonOut) {
    try {
      writeFileSync(args.jsonOut, JSON.stringify({ target, checks: results }, null, 2) + "\n");
      logger.info(`wrote conformance report -> ${args.jsonOut}`);
    } catch (err) {
      logger.error(`could not write JSON report: ${(err as Error).message}`);
    }
  }
  const items: Finding[] = findings.all();
  if (args.findingsOut) {
    try {
      writeFindingsDir(args.findingsOut, items);
      logger.info(`wrote ${items.length} finding(s) -> ${args.findingsOut}`);
    } catch (err) {
      logger.error(`could not write findings: ${(err as Error).message}`);
    }
  }

  // Nonzero exit on any FAIL (CI gate). Also nonzero if we got no results at all.
  const failed = results.some((r) => r.status === "fail");
  return failed || results.length === 0 ? 1 : 0;
}
