import test from "node:test";
import assert from "node:assert/strict";
import { parsePath, getPath, setPath } from "../dist/engine/jsonpath.js";

test("parsePath: dotted keys and bracketed indices", () => {
  assert.deepEqual(parsePath("a.b"), ["a", "b"]);
  assert.deepEqual(parsePath("items[0]"), ["items", 0]);
  assert.deepEqual(parsePath("a.b[2].c"), ["a", "b", 2, "c"]);
  assert.deepEqual(parsePath("[0].id"), [0, "id"]);
});

test("parsePath: rejects malformed syntax", () => {
  assert.throws(() => parsePath("a["), /unterminated/);
  assert.throws(() => parsePath("a[x]"), /invalid array index/);
  assert.throws(() => parsePath(""), /empty path/);
});

test("getPath: reads nested values and is total (undefined for misses)", () => {
  const root = { a: { b: [{ c: 42 }] } };
  assert.equal(getPath(root, "a.b[0].c"), 42);
  assert.equal(getPath(root, "a.b[0]").c, 42);
  assert.equal(getPath(root, "a.x"), undefined);
  // Descending through a scalar yields undefined rather than throwing.
  assert.equal(getPath(root, "a.b[0].c.d"), undefined);
  assert.equal(getPath(null, "a"), undefined);
});

test("setPath: creates intermediate objects and arrays by next-segment type", () => {
  const root = {};
  setPath(root, "a.b.c", 1);
  assert.deepEqual(root, { a: { b: { c: 1 } } });

  const arr = {};
  setPath(arr, "items[2].id", "x");
  assert.ok(Array.isArray(arr.items));
  assert.equal(arr.items[2].id, "x");
});

test("setPath: replaces a conflicting intermediate of the wrong container type", () => {
  const root = { a: "scalar" }; // need an object under `a`, but it's a string
  setPath(root, "a.b", 1);
  assert.deepEqual(root, { a: { b: 1 } });

  const root2 = { list: { not: "an array" } }; // need an array, have an object
  setPath(root2, "list[0]", "v");
  assert.ok(Array.isArray(root2.list));
  assert.equal(root2.list[0], "v");
});
