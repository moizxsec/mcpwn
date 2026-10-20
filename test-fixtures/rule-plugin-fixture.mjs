// Custom tamper-action plugin fixture (test only). Registers the kind
// "fixtureUppercase": it upcases the first text block of a tools/call result.
// The handler receives a deep CLONE of the message as ctx.message and takes
// effect only by RETURNING it (functional contract); undefined means no change.
export const kind = "fixtureUppercase";

export function apply(ctx, _params) {
  const content = ctx.message?.result?.content;
  if (!Array.isArray(content)) return undefined;
  const block = content.find((b) => b?.type === "text" && typeof b.text === "string");
  if (!block) return undefined;
  block.text = block.text.toUpperCase();
  return ctx.message;
}
