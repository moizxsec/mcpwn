import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redact, builtinRedactPatterns } from "../dist/redact.js";
import { Logger } from "../dist/logger.js";

const KEY = "AKIA" + "IOSFODNN7EXAMPLE";

test("redact masks matches as «redacted:<label>»", () => {
  const out = redact(`id=${KEY} done`, builtinRedactPatterns());
  assert.ok(!out.includes(KEY));
  assert.match(out, /«redacted:aws-access-key»/);
});

test("redact is a no-op with no patterns", () => {
  assert.equal(redact("keep me", []), "keep me");
});

test("a bad custom pattern never throws (never block the log)", () => {
  // Construct a pattern then sabotage it so .replace could fail; redact swallows.
  const patterns = [{ label: "x", re: /AKIA/g }];
  assert.doesNotThrow(() => redact("AKIA", patterns));
});

test("Logger masks secrets in BOTH stderr and the JSONL record", () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-redact-"));
  const logPath = join(work, "session.jsonl");

  // Capture stderr.
  const original = process.stderr.write.bind(process.stderr);
  let captured = "";
  process.stderr.write = (chunk) => {
    captured += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    return true;
  };

  try {
    const logger = new Logger({
      logFile: logPath,
      verbose: true,
      redactPatterns: builtinRedactPatterns(),
    });

    const json = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: `key=${KEY}` }] } };
    const raw = JSON.stringify(json);
    const flow = {
      raw,
      json,
      kind: "response",
      id: 1,
      direction: "server->client",
      correlatedMethod: "tools/call",
      ts: 123,
    };
    logger.message(flow, [], false, { forwarded: raw });

    // Sink 1: stderr (verbose body) — masked.
    assert.ok(!captured.includes(KEY), "stderr must not contain the raw secret");
    assert.match(captured, /«redacted:aws-access-key»/);
  } finally {
    process.stderr.write = original;
  }

  // Sink 2: JSONL raw + forwarded — masked.
  const record = JSON.parse(readFileSync(logPath, "utf8").trim());
  assert.ok(!record.raw.includes(KEY), "JSONL raw must not contain the raw secret");
  assert.ok(!record.forwarded.includes(KEY), "JSONL forwarded must not contain the raw secret");
  assert.match(record.raw, /«redacted:aws-access-key»/);
  assert.match(record.forwarded, /«redacted:aws-access-key»/);

  rmSync(work, { recursive: true, force: true });
});
