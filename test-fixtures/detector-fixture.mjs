// Custom passive detector fixture (test only). Namespace-style export: mcpwn
// uses the module's named exports directly (no default). Fires a finding when
// any agent-bound message JSON contains the marker string. Read-only.
export const name = "fixture-detector";

export function inspect(flow, sink) {
  const text = JSON.stringify(flow.json ?? {});
  if (text.includes("FIXTURE_MARKER")) {
    sink.add({
      id: "fixture-finding",
      severity: "medium",
      title: "fixture detector saw its marker",
      direction: flow.direction,
      ts: flow.ts,
    });
  }
}
