// A rule-action plugin that always throws, to prove the engine rolls the message
// back and forwards it untampered (same discipline built-in actions get).
export const kind = "fixtureThrow";

export function apply() {
  throw new Error("rule plugin boom");
}
