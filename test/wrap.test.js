import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  wrapConfigObject,
  unwrapConfigObject,
  isWrappedEntry,
  wrapFile,
  unwrapFile,
  defaultInvocation,
  nodeInvocation,
  CLIENTS,
  CLIENT_IDS,
  WrapError,
} from "../dist/wrap.js";

const INV = defaultInvocation(); // { command: "mcpwn", args: [] }

function tmpConfig(obj) {
  const dir = mkdtempSync(join(tmpdir(), "mcpwn-wrap-"));
  const path = join(dir, "claude_desktop_config.json");
  const text = JSON.stringify(obj, null, 2) + "\n";
  writeFileSync(path, text);
  return { dir, path, text, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// --- detection --------------------------------------------------------------

test("isWrappedEntry recognises wrapped and unwrapped entries", () => {
  assert.equal(isWrappedEntry({ command: "npx", args: ["-y", "@x/s"] }), false);
  assert.equal(isWrappedEntry({ command: "mcpwn", args: ["--", "npx", "-y", "@x/s"] }), true);
  assert.equal(isWrappedEntry({ command: "node", args: ["/a/dist/cli.js", "--", "node", "s.js"] }), true);
  assert.equal(isWrappedEntry({ command: "npx", args: ["-y", "@moizxsec/mcpwn", "--", "node", "s.js"] }), true);
  // a bare mcpwn command without "--" is not considered wrapped
  assert.equal(isWrappedEntry({ command: "mcpwn", args: ["scan"] }), false);
  assert.equal(isWrappedEntry({ foo: 1 }), false);
});

// --- pure transforms --------------------------------------------------------

test("wrapConfigObject routes every stdio entry through mcpwn, preserving env", () => {
  const cfg = {
    mcpServers: {
      fs: { command: "npx", args: ["-y", "@x/s", "/tmp"] },
      weather: { command: "node", args: ["w.js"], env: { KEY: "v" } },
    },
  };
  const res = wrapConfigObject(cfg, "mcpServers", INV);
  assert.deepEqual(res.changed.sort(), ["fs", "weather"]);
  assert.deepEqual(res.config.mcpServers.fs, {
    command: "mcpwn",
    args: ["--", "npx", "-y", "@x/s", "/tmp"],
  });
  // env (and other keys) survive the wrap.
  assert.deepEqual(res.config.mcpServers.weather, {
    command: "mcpwn",
    args: ["--", "node", "w.js"],
    env: { KEY: "v" },
  });
  // original object is untouched (new config returned).
  assert.equal(cfg.mcpServers.fs.command, "npx");
});

test("wrapConfigObject is idempotent — a second wrap changes nothing", () => {
  const cfg = { mcpServers: { fs: { command: "npx", args: ["@x/s"] } } };
  const once = wrapConfigObject(cfg, "mcpServers", INV);
  const twice = wrapConfigObject(once.config, "mcpServers", INV);
  assert.deepEqual(twice.changed, []);
  assert.deepEqual(twice.skipped, ["fs"]);
  assert.deepEqual(twice.config.mcpServers.fs, once.config.mcpServers.fs);
});

test("wrapConfigObject --server narrows to one entry", () => {
  const cfg = {
    mcpServers: { a: { command: "node", args: ["a.js"] }, b: { command: "node", args: ["b.js"] } },
  };
  const res = wrapConfigObject(cfg, "mcpServers", INV, "a");
  assert.deepEqual(res.changed, ["a"]);
  assert.equal(res.config.mcpServers.a.command, "mcpwn");
  assert.equal(res.config.mcpServers.b.command, "node"); // untouched
});

test("wrapConfigObject skips non-stdio (url) entries", () => {
  const cfg = { mcpServers: { remote: { url: "https://x/mcp" }, local: { command: "node", args: ["s.js"] } } };
  const res = wrapConfigObject(cfg, "mcpServers", INV);
  assert.deepEqual(res.changed, ["local"]);
  assert.deepEqual(res.skipped, ["remote"]);
});

test("wrapConfigObject throws on a missing servers key or unknown --server", () => {
  assert.throws(() => wrapConfigObject({}, "mcpServers", INV), WrapError);
  assert.throws(
    () => wrapConfigObject({ mcpServers: { a: { command: "node" } } }, "mcpServers", INV, "zzz"),
    WrapError
  );
});

test("unwrapConfigObject reverses the wrap and preserves env", () => {
  const cfg = { mcpServers: { fs: { command: "node", args: ["s.js"], env: { K: "v" } } } };
  const wrapped = wrapConfigObject(cfg, "mcpServers", INV).config;
  const back = unwrapConfigObject(wrapped, "mcpServers").config;
  assert.deepEqual(back.mcpServers.fs, { command: "node", args: ["s.js"], env: { K: "v" } });
});

test("nodeInvocation uses node + a cli.js path", () => {
  const inv = nodeInvocation();
  assert.equal(typeof inv.command, "string");
  assert.equal(inv.args.length, 1);
  assert.match(inv.args[0], /cli\.js$/);
});

// --- file-level: backup, idempotent refusal, byte-for-byte restore ----------

test("wrapFile creates a backup, routes through mcpwn, and is idempotent", () => {
  const t = tmpConfig({ mcpServers: { fs: { command: "npx", args: ["-y", "@x/s"] } } });
  try {
    const res = wrapFile({ path: t.path, serversKey: "mcpServers", invocation: INV });
    assert.equal(res.wrote, true);
    assert.deepEqual(res.changed, ["fs"]);
    // backup holds the EXACT original bytes.
    assert.ok(existsSync(t.path + ".mcpwn.bak"));
    assert.equal(readFileSync(t.path + ".mcpwn.bak", "utf8"), t.text);
    // the live file now routes through mcpwn.
    const live = JSON.parse(readFileSync(t.path, "utf8"));
    assert.equal(live.mcpServers.fs.command, "mcpwn");
    assert.deepEqual(live.mcpServers.fs.args, ["--", "npx", "-y", "@x/s"]);

    // second wrap: nothing to do, no re-write.
    const again = wrapFile({ path: t.path, serversKey: "mcpServers", invocation: INV });
    assert.equal(again.wrote, false);
    assert.deepEqual(again.changed, []);
  } finally {
    t.cleanup();
  }
});

test("wrapFile --dry-run writes nothing and makes no backup", () => {
  const t = tmpConfig({ mcpServers: { fs: { command: "node", args: ["s.js"] } } });
  try {
    const res = wrapFile({ path: t.path, serversKey: "mcpServers", invocation: INV, dryRun: true });
    assert.equal(res.wrote, false);
    assert.deepEqual(res.changed, ["fs"]); // reports what it WOULD do
    assert.ok(res.diff.includes("mcpwn"));
    assert.equal(readFileSync(t.path, "utf8"), t.text); // unchanged
    assert.equal(existsSync(t.path + ".mcpwn.bak"), false);
  } finally {
    t.cleanup();
  }
});

test("unwrapFile restores byte-for-byte from the backup and removes it", () => {
  const t = tmpConfig({ mcpServers: { fs: { command: "npx", args: ["-y", "@x/s"] } } });
  try {
    wrapFile({ path: t.path, serversKey: "mcpServers", invocation: INV });
    const res = unwrapFile({ path: t.path, serversKey: "mcpServers" });
    assert.equal(res.restoredFromBackup, true);
    // byte-for-byte identical to the pristine original.
    assert.equal(readFileSync(t.path, "utf8"), t.text);
    assert.equal(existsSync(t.path + ".mcpwn.bak"), false);
  } finally {
    t.cleanup();
  }
});

test("unwrapFile reverses the transform when no backup exists", () => {
  const t = tmpConfig({ mcpServers: { fs: { command: "node", args: ["s.js"] } } });
  try {
    wrapFile({ path: t.path, serversKey: "mcpServers", invocation: INV });
    rmSync(t.path + ".mcpwn.bak"); // simulate a lost backup
    const res = unwrapFile({ path: t.path, serversKey: "mcpServers" });
    assert.equal(res.restoredFromBackup, false);
    assert.deepEqual(res.changed, ["fs"]);
    const live = JSON.parse(readFileSync(t.path, "utf8"));
    assert.equal(live.mcpServers.fs.command, "node");
    assert.deepEqual(live.mcpServers.fs.args, ["s.js"]);
  } finally {
    t.cleanup();
  }
});

// --- per-OS config path table (platform injected, so OS-independent) ---------

test("every known client resolves a per-OS config path", () => {
  for (const id of CLIENT_IDS) assert.ok(CLIENTS[id]); // all present

  const macEnv = { HOME: "/Users/x" };
  const linEnv = { HOME: "/home/x" };
  const winEnv = { APPDATA: "C:/Users/x/AppData/Roaming", USERPROFILE: "C:/Users/x" };

  const cd = CLIENTS["claude-desktop"];
  assert.ok(cd.resolve(macEnv, "darwin").endsWith("Library/Application Support/Claude/claude_desktop_config.json"));
  assert.ok(cd.resolve(linEnv, "linux").endsWith(".config/Claude/claude_desktop_config.json"));
  assert.ok(cd.resolve(winEnv, "win32").includes("Claude"));

  assert.ok(CLIENTS.cursor.resolve(linEnv, "linux").endsWith(".cursor/mcp.json"));
  assert.ok(CLIENTS.windsurf.resolve(linEnv, "linux").endsWith(".codeium/windsurf/mcp_config.json"));
  assert.ok(CLIENTS.vscode.resolve(linEnv, "linux").endsWith("Code/User/mcp.json"));
  assert.equal(CLIENTS.vscode.serversKey, "servers"); // VS Code uses "servers"
  assert.ok(CLIENTS.cline.resolve(linEnv, "linux").endsWith("saoudrizwan.claude-dev/settings/cline_mcp_settings.json"));
});

test("vscode config uses the 'servers' key end-to-end", () => {
  const t = tmpConfig({ servers: { s: { command: "node", args: ["s.js"] } } });
  try {
    const res = wrapFile({ path: t.path, serversKey: "servers", invocation: INV });
    assert.deepEqual(res.changed, ["s"]);
    const live = JSON.parse(readFileSync(t.path, "utf8"));
    assert.equal(live.servers.s.command, "mcpwn");
  } finally {
    t.cleanup();
  }
});
