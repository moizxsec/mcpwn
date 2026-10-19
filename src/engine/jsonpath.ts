/**
 * Minimal, zero-dependency JSON path access for argument tampering (§3.2).
 *
 * Supports the two forms real tool arguments need: dotted object keys and
 * bracketed array indices — e.g. `a.b`, `items[0]`, `a.b[2].c`, `[0].id`. No
 * wildcards, filters, or quoting: this is deliberately tiny so the headless
 * tamper core stays auditable and never pulls in a JSONPath runtime.
 *
 * `getPath` is read-only and total (returns undefined for anything missing).
 * `setPath` is write-through and creates intermediate containers as needed,
 * choosing an array when the next segment is an index and an object otherwise;
 * a conflicting intermediate (wrong container type) is replaced.
 */

type Segment = string | number;

/** Tokenize a path string into object-key / array-index segments. Throws on
 *  malformed syntax (unterminated "[", non-numeric index) so the caller's
 *  per-rule safety net logs it and forwards the message untampered. */
export function parsePath(path: string): Segment[] {
  const segs: Segment[] = [];
  let cur = "";
  let i = 0;
  const flush = () => {
    if (cur.length > 0) {
      segs.push(cur);
      cur = "";
    }
  };
  while (i < path.length) {
    const ch = path[i];
    if (ch === ".") {
      flush();
      i++;
    } else if (ch === "[") {
      flush();
      const close = path.indexOf("]", i);
      if (close === -1) throw new Error(`unterminated "[" in path "${path}"`);
      const idx = path.slice(i + 1, close);
      if (!/^\d+$/.test(idx)) throw new Error(`invalid array index "[${idx}]" in path "${path}"`);
      segs.push(Number(idx));
      i = close + 1;
    } else {
      cur += ch;
      i++;
    }
  }
  flush();
  if (segs.length === 0) throw new Error(`empty path`);
  return segs;
}

/** Read the value at `path` within `root`, or undefined if it does not resolve. */
export function getPath(root: unknown, path: string): unknown {
  const segs = parsePath(path);
  let node: any = root;
  for (const seg of segs) {
    if (node === null || typeof node !== "object") return undefined;
    node = node[seg as any];
  }
  return node;
}

/** Set the value at `path` within `root`, creating intermediate objects/arrays
 *  as the segment types dictate. `root` must already be a container. */
export function setPath(root: any, path: string, value: unknown): void {
  const segs = parsePath(path);
  let node: any = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const seg = segs[i];
    const nextIsIndex = typeof segs[i + 1] === "number";
    const child = node[seg];
    const wrongType = nextIsIndex
      ? !Array.isArray(child)
      : child === null || typeof child !== "object" || Array.isArray(child);
    if (wrongType) {
      node[seg] = nextIsIndex ? [] : {};
    }
    node = node[seg];
  }
  node[segs[segs.length - 1]] = value;
}
