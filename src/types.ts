/** Direction of a message relative to the proxy. */
export type Direction = "client->server" | "server->client";

/** Classification of a JSON-RPC message. */
export type MessageKind = "request" | "response" | "error" | "notification" | "unknown";

/** A parsed JSON-RPC 2.0 message. `raw` is the exact source line so we can
 *  relay byte-for-byte when no rule touches it (NFR-1 transparency). */
export interface RpcMessage {
  raw: string;
  /** Parsed JSON value, or undefined if the line was not valid JSON. */
  json?: any;
  kind: MessageKind;
  /** Present on requests, responses, and errors. */
  id?: string | number | null;
  /** Present on requests and notifications. For responses we fill this in
   *  from the correlator (responses carry no method on the wire). */
  method?: string;
}

/** A message annotated with direction + correlation for logging/rules. */
export interface FlowMessage extends RpcMessage {
  direction: Direction;
  /** Method resolved via correlation when the message itself lacks one. */
  correlatedMethod?: string;
  ts: number;
}

/** Actions a rule can apply to a matched message. */
export type RuleAction =
  | { kind: "injectToolResult"; text: string; mode?: "append" | "prepend" | "replace" }
  | {
      kind: "poisonDescription";
      tool?: string;
      text: string;
      mode?: "append" | "prepend" | "replace";
    }
  | { kind: "matchReplace"; find: string; replace: string; flags?: string }
  // --- argument tampering (§3.2) — apply only to client->server tools/call ---
  /** Set a single argument (by JSON path within params.arguments) to a value,
   *  creating it if absent. `tool` optionally restricts to one tool by name. */
  | { kind: "setArg"; tool?: string; path: string; value: unknown }
  /** Replace (or merge into) the whole params.arguments object. */
  | {
      kind: "rewriteArgs";
      tool?: string;
      args: Record<string, unknown>;
      mode?: "replace" | "merge";
    }
  /** Set an argument (by path) to the next payload from a list or payload
   *  library, cycling one payload per matching call (stateful cursor). */
  | { kind: "fuzzArgs"; tool?: string; path: string; payloads: string[] | string }
  | { kind: "drop" };

/** A headless tamper rule (NFR-7: loadable from user files). */
export interface Rule {
  name: string;
  enabled?: boolean;
  direction?: Direction;
  /** Match on JSON-RPC method (resolved via correlation for responses). */
  method?: string;
  /** Restrict to request/response/notification, etc. */
  kind?: MessageKind;
  action: RuleAction;
}

export interface RuleFile {
  rules: Rule[];
}
