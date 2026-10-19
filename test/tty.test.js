import test from "node:test";
import assert from "node:assert/strict";
import { closeSync } from "node:fs";
import { openControllingTty } from "../dist/engine/tty.js";

// The return-shape of openControllingTty is unit-tested by injecting a fake
// `openSync` + platform, so no real console is required (interactive end-to-end
// behaviour stays a manual check).

test("openControllingTty: POSIX opens /dev/tty read + write and returns both fds", () => {
  const calls = [];
  let fd = 10;
  const fakeOpen = (path, flags) => {
    calls.push([path, flags]);
    return fd++;
  };
  const res = openControllingTty(fakeOpen, "linux");
  assert.deepEqual(res, { rfd: 10, wfd: 11 });
  assert.deepEqual(calls, [
    ["/dev/tty", "r"],
    ["/dev/tty", "w"],
  ]);
});

test("openControllingTty: Windows opens CONIN$/CONOUT$ console devices", () => {
  const calls = [];
  let fd = 3;
  const fakeOpen = (path, flags) => {
    calls.push([path, flags]);
    return fd++;
  };
  const res = openControllingTty(fakeOpen, "win32");
  assert.ok(res, "should return a descriptor pair");
  assert.equal(res.rfd, 3);
  assert.equal(res.wfd, 4);
  assert.match(calls[0][0], /CONIN\$$/);
  assert.equal(calls[0][1], "r");
  assert.match(calls[1][0], /CONOUT\$$/);
  assert.equal(calls[1][1], "w");
});

test("openControllingTty: returns null when the terminal cannot be opened (headless)", () => {
  const fakeOpen = () => {
    throw new Error("ENXIO: no such device or address");
  };
  const res = openControllingTty(fakeOpen, "linux");
  assert.equal(res, null);
});

test("openControllingTty: returns null when only the write side fails (no fd leak path)", () => {
  let n = 0;
  const fakeOpen = () => {
    n++;
    if (n === 1) return 7; // read side opens
    throw new Error("EACCES"); // write side fails
  };
  const res = openControllingTty(fakeOpen, "linux");
  assert.equal(res, null);
});

test("openControllingTty: defaults are callable (real openSync + current platform)", () => {
  // In CI/headless there is usually no controlling tty, so this returns null;
  // on a real console it returns a descriptor pair. Either way it must not throw.
  const res = openControllingTty();
  assert.ok(res === null || (typeof res.rfd === "number" && typeof res.wfd === "number"));
  if (res) {
    // Clean up any real fds we opened.
    try {
      closeSync(res.rfd);
      closeSync(res.wfd);
    } catch {
      /* best effort */
    }
  }
});
