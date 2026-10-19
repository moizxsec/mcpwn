import type { RpcMessage, MessageKind } from "../types.js";

/** Classify a parsed JSON-RPC value. Tolerant: anything weird becomes
 *  "unknown" and is relayed opaquely (NFR-3). */
function classify(json: any): MessageKind {
  if (json == null || typeof json !== "object") return "unknown";
  // JSON-RPC 2.0 batches arrive as an array of messages. mcpwn does NOT
  // classify, correlate or tamper batch elements individually — a batch is
  // relayed opaquely (as "unknown") so the wire is never blocked or mangled.
  // Batches are rare in MCP (removed in the 2025-06-18 spec revision); detect
  // them explicitly so this is a deliberate choice, not a silent fall-through.
  // See README ("Batched messages").
  if (Array.isArray(json)) return "unknown";
  const hasId = "id" in json;
  const hasMethod = typeof json.method === "string";
  if (hasMethod && hasId) return "request";
  if (hasMethod && !hasId) return "notification";
  if (hasId && "error" in json) return "error";
  if (hasId && "result" in json) return "response";
  return "unknown";
}

/** Parse a single newline-delimited JSON-RPC line. Never throws: invalid
 *  JSON yields a message with kind="unknown" and json=undefined so the
 *  transport can fall back to opaque relay. */
export function parseLine(raw: string): RpcMessage {
  let json: any;
  try {
    json = JSON.parse(raw);
  } catch {
    return { raw, kind: "unknown" };
  }
  const kind = classify(json);
  const msg: RpcMessage = { raw, json, kind };
  if (json && typeof json === "object") {
    if ("id" in json) msg.id = json.id;
    if (typeof json.method === "string") msg.method = json.method;
  }
  return msg;
}

/** Serialize a (possibly mutated) JSON value back to a single wire line.
 *  MCP stdio framing: one JSON message per line, no embedded newlines. */
export function serialize(json: any): string {
  return JSON.stringify(json);
}

/**
 * A streaming newline framer. stdio reads arrive in arbitrary chunks; this
 * buffers partial lines and emits one complete line at a time (NFR-3).
 */
export class LineFramer {
  private buf = "";

  /** Feed a chunk; returns any complete lines (without trailing newline). */
  push(chunk: Buffer | string): string[] {
    this.buf += chunk.toString("utf8");
    const out: string[] = [];
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) !== -1) {
      let line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (line.length > 0) out.push(line);
    }
    return out;
  }

  /** Any buffered, unterminated remainder (flushed on stream end). */
  flush(): string | null {
    const rest = this.buf;
    this.buf = "";
    return rest.length > 0 ? rest : null;
  }
}
