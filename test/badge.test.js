import test from "node:test";
import assert from "node:assert/strict";
import { renderBadge, findingsBadge } from "../dist/badge.js";

test("badge SVG is valid-ish XML with a title", () => {
  const svg = findingsBadge(0);
  assert.ok(svg.startsWith("<svg"), "starts with an <svg> root");
  assert.ok(svg.trimEnd().endsWith("</svg>"), "closes the <svg> root");
  assert.ok(svg.includes('xmlns="http://www.w3.org/2000/svg"'), "declares the SVG namespace");
  assert.ok(/<title>.*<\/title>/.test(svg), "has a <title>");
  // Rough tag balance: equal numbers of opening <rect / <text and their closers.
  const open = (svg.match(/<svg/g) || []).length;
  const close = (svg.match(/<\/svg>/g) || []).length;
  assert.equal(open, close);
});

test("badge shows the finding count", () => {
  assert.ok(findingsBadge(0).includes("0 findings"));
  assert.ok(findingsBadge(7).includes("7 findings"));
  // singular for exactly one
  const one = findingsBadge(1);
  assert.ok(one.includes("1 finding"));
  assert.ok(!one.includes("1 findings"));
});

test("badge colour reflects zero vs nonzero", () => {
  const zero = findingsBadge(0);
  const some = findingsBadge(3);
  assert.ok(zero.includes("#4c1"), "zero findings → green");
  assert.ok(!zero.includes("#e05d44"));
  assert.ok(some.includes("#e05d44"), "nonzero findings → red");
  assert.ok(!some.includes("#4c1"));
});

test("renderBadge escapes XML-special characters in label/message", () => {
  const svg = renderBadge({ label: "a&b", message: "<x>", color: "#4c1" });
  assert.ok(svg.includes("a&amp;b"));
  assert.ok(svg.includes("&lt;x&gt;"));
  // the raw, unescaped forms must not leak into the output
  assert.ok(!svg.includes("a&b<"));
});

test("renderBadge honours a custom label colour", () => {
  const svg = renderBadge({ label: "x", message: "y", color: "#4c1", labelColor: "#123456" });
  assert.ok(svg.includes("#123456"));
});
