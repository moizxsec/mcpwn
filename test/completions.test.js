import test from "node:test";
import assert from "node:assert/strict";
import {
  generateCompletions,
  COMPLETION_SHELLS,
  SUBCOMMANDS,
  isCompletionShell,
} from "../dist/completions.js";

for (const shell of COMPLETION_SHELLS) {
  test(`${shell}: emits a non-empty script mentioning the subcommands`, () => {
    const script = generateCompletions(shell);
    assert.equal(typeof script, "string");
    assert.ok(script.length > 50, "script should be non-trivial");
    assert.ok(script.includes("mcpwn"), "names the program");
    // A representative set of subcommands must appear in each shell's script.
    for (const sub of ["scan", "wrap", "unwrap", "init", "completions", "badge"]) {
      assert.ok(SUBCOMMANDS.includes(sub));
      assert.ok(script.includes(sub), `${shell} script mentions "${sub}"`);
    }
  });
}

test("isCompletionShell gates valid shells", () => {
  assert.equal(isCompletionShell("bash"), true);
  assert.equal(isCompletionShell("zsh"), true);
  assert.equal(isCompletionShell("fish"), true);
  assert.equal(isCompletionShell("powershell"), false);
});

test("bash script wires completion for the mcpwn command", () => {
  const s = generateCompletions("bash");
  assert.ok(s.includes("complete -F _mcpwn mcpwn"));
});

test("zsh script carries a #compdef header", () => {
  const s = generateCompletions("zsh");
  assert.ok(s.startsWith("#compdef mcpwn"));
});

test("fish script declares completions for mcpwn", () => {
  const s = generateCompletions("fish");
  assert.ok(s.includes("complete -c mcpwn"));
});
