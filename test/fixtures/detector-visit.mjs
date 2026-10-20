// Detector fixture using a default export and the alternative `visit` method
// name (mcpwn accepts inspect OR visit).
export default {
  name: "fixture-visitor",
  visit(flow, sink) {
    sink.add({
      id: "visit-finding",
      severity: "low",
      title: "fixture visitor ran",
      direction: flow.direction,
      ts: flow.ts,
    });
  },
};
