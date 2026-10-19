import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPayloads, listPayloads } from "../dist/payloads/index.js";

// --- list -----------------------------------------------------------------

test("listPayloads reports the bundled categories", () => {
  const names = listPayloads();
  for (const expected of ["prompt-injection", "ssrf", "path-traversal", "command-injection", "sqli"]) {
    assert.ok(names.includes(expected), `expected bundled category "${expected}" in ${names.join(",")}`);
  }
});

// --- load bundled ---------------------------------------------------------

test("loadPayloads reads a bundled library and returns non-empty lines", () => {
  const lines = loadPayloads("prompt-injection");
  assert.ok(lines.length > 0);
  assert.ok(lines.every((l) => typeof l === "string" && l.length > 0));
});

// --- comment / blank stripping --------------------------------------------

test("loadPayloads strips '#' comment lines and blanks but keeps payloads verbatim", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-payloads-"));
  const file = join(dir, "custom.txt");
  writeFileSync(file, "# a comment\n\n  # indented comment\npayload one\n   spaced payload   \n# trailing comment\n");
  try {
    const lines = loadPayloads(file);
    assert.deepEqual(lines, ["payload one", "   spaced payload   "]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadPayloads also accepts a path to a .txt wordlist (disk resolution)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-payloads-"));
  const file = join(dir, "list.txt");
  writeFileSync(file, "alpha\nbravo\n");
  try {
    assert.deepEqual(loadPayloads(file), ["alpha", "bravo"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- unknown error --------------------------------------------------------

test("loadPayloads throws a friendly error for an unknown library", () => {
  assert.throws(() => loadPayloads("definitely-not-a-library"), /unknown payload library/);
});
