import { openSync, closeSync } from "node:fs";

/** A pair of file descriptors for the operator's controlling terminal. */
export interface ControllingTty {
  /** Read fd — the operator's keyboard. */
  rfd: number;
  /** Write fd — the operator's display. */
  wfd: number;
}

/** Seam for tests: the shape of `node:fs`'s `openSync` we depend on. */
export type OpenFn = (path: string, flags: string) => number;

/**
 * Open the operator's controlling terminal for interactive use, independent of
 * stdin/stdout (which carry the MCP protocol and must stay byte-clean —
 * Invariant #1).
 *
 * - **POSIX** exposes the controlling terminal as `/dev/tty`.
 * - **Windows** exposes the console as the special device names `CONIN$`
 *   (input) and `CONOUT$` (output).
 *
 * Returns `null` when no controlling terminal can be opened — e.g. the proxy
 * was spawned by a GUI client with no attached console. Callers must then
 * degrade gracefully to auto-forward rather than trapping the wire.
 *
 * `open`/`plat` are injectable so the return-shape can be unit-tested without a
 * real console (interactive end-to-end testing stays manual).
 */
export function openControllingTty(
  open: OpenFn = openSync,
  plat: NodeJS.Platform = process.platform
): ControllingTty | null {
  const [readPath, writePath] =
    plat === "win32" ? ["\\\\.\\CONIN$", "\\\\.\\CONOUT$"] : ["/dev/tty", "/dev/tty"];

  let rfd = -1;
  try {
    rfd = open(readPath, "r");
    const wfd = open(writePath, "w");
    return { rfd, wfd };
  } catch {
    // Don't leak the read fd if opening the write side failed.
    if (rfd >= 0) {
      try {
        closeSync(rfd);
      } catch {
        /* best effort */
      }
    }
    return null;
  }
}
