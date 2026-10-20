import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { detectClients } from "../dist/init.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const cli = join(root, "dist", "cli.js");

const SKIP_E2E =
  process.platform === "win32" ? "init spawn e2e is not run on Windows CI" : false;

// --- unit: detection with an injected HOME + platform (OS-independent) -------

test("detectClients finds a client whose config file exists", () => {
  const home = mkdtempSync(join(tmpdir(), "mcpwn-home-"));
  try {
    const dir = join(home, ".config", "Claude");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "claude_desktop_config.json"), JSON.stringify({ mcpServers: {} }));
    const found = detectClients({ HOME: home }, "linux");
    assert.ok(found.some((c) => c.id === "claude-desktop"));
    const cd = found.find((c) => c.id === "claude-desktop");
    assert.equal(cd.serversKey, "mcpServers");
    assert.ok(cd.path.endsWith("claude_desktop_config.json"));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("detectClients returns nothing for an empty HOME", () => {
  const home = mkdtempSync(join(tmpdir(), "mcpwn-home-"));
  try {
    assert.deepEqual(detectClients({ HOME: home }, "linux"), []);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// --- e2e: `mcpwn init --yes` wraps + writes starter files without hanging ----

function runInitCli(extraArgs, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "init", ...extraArgs], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("init timed out (possible hang)"));
    }, 20000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test("mcpwn init --yes wraps a fixture client config and writes starter files", { skip: SKIP_E2E }, async () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-init-"));
  try {
    const cfgPath = join(work, "claude_desktop_config.json");
    writeFileSync(
      cfgPath,
      JSON.stringify({ mcpServers: { fs: { command: "node", args: ["s.js"] } } }, null, 2) + "\n"
    );

    const { code, stdout } = await runInitCli([
      "--yes",
      "--client",
      "claude-desktop",
      "--config-path",
      cfgPath,
      "--dir",
      work,
    ]);

    assert.equal(code, 0, `init exited ${code}:\n${stdout}`);
    // The fixture config was wrapped through mcpwn.
    const live = JSON.parse(readFileSync(cfgPath, "utf8"));
    assert.equal(live.mcpServers.fs.command, "mcpwn");
    assert.deepEqual(live.mcpServers.fs.args, ["--", "node", "s.js"]);
    assert.ok(existsSync(cfgPath + ".mcpwn.bak"), "a backup was created");
    // Starter files were written into --dir.
    assert.ok(existsSync(join(work, "mcpwn.config.json")));
    assert.ok(existsSync(join(work, "mcpwn.policy.json")));
    const pol = JSON.parse(readFileSync(join(work, "mcpwn.policy.json"), "utf8"));
    assert.ok(Array.isArray(pol.rules));
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("mcpwn init (no --yes) previews without writing anything", { skip: SKIP_E2E }, async () => {
  const work = mkdtempSync(join(tmpdir(), "mcpwn-init-"));
  try {
    const cfgPath = join(work, "claude_desktop_config.json");
    const original = JSON.stringify({ mcpServers: { fs: { command: "node", args: ["s.js"] } } }, null, 2) + "\n";
    writeFileSync(cfgPath, original);

    const { code, stdout } = await runInitCli([
      "--client",
      "claude-desktop",
      "--config-path",
      cfgPath,
      "--dir",
      work,
    ]);

    assert.equal(code, 0);
    assert.ok(stdout.toLowerCase().includes("preview"));
    // Nothing was written: config unchanged, no backup, no starter files.
    assert.equal(readFileSync(cfgPath, "utf8"), original);
    assert.equal(existsSync(cfgPath + ".mcpwn.bak"), false);
    assert.equal(existsSync(join(work, "mcpwn.config.json")), false);
    assert.equal(existsSync(join(work, "mcpwn.policy.json")), false);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
