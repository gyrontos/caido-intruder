import type { AttackMode, PayloadSource } from "../shared/types";

/**
 * Split the raw template on § markers. Returns alternating plain-text / marker slots:
 * text, marker, text, marker, ..., text. `parts.length` slots, `positionCount` markers.
 */
export function splitTemplate(template: string): { parts: string[]; positionCount: number } {
  const parts = template.split("§");
  return { parts, positionCount: Math.floor(parts.length / 2) };
}

/** Expand one payload source into a concrete list of strings, or an error message. */
export function materializePayloads(src: PayloadSource): string[] | string {
  if (src == null) return "Missing payload set";
  switch (src.type) {
    case "list":
      return src.items;
    case "numbers": {
      const out: string[] = [];
      const step = src.step || 1;
      if (step === 0) return "Number step cannot be 0";
      if ((step > 0 && src.to < src.from) || (step < 0 && src.to > src.from)) {
        return "Number range is empty (from/to and step disagree)";
      }
      for (let n = src.from; step > 0 ? n <= src.to : n >= src.to; n += step) {
        out.push(padNumber(n, src.pad));
        if (out.length > 100000) return "Number range too large (limit 100000)";
      }
      return out;
    }
    case "fuzz": {
      const set = src.charset ?? "";
      if (!set) return "Fuzz charset is empty";
      const out: string[] = [];
      const max = 20000;
      for (let len = Math.max(1, src.minLength); len <= src.maxLength; len++) {
        const count = Math.pow(set.length, len);
        if (out.length + count > max) {
          return `Fuzz set too large (${out.length + count} strings); reduce the charset or lengths`;
        }
        const indices = new Array<number>(len).fill(0);
        for (let i = 0; i < count; i++) {
          let s = "";
          for (let j = 0; j < len; j++) s += set[indices[j]];
          out.push(s);
          for (let j = len - 1; j >= 0; j--) {
            indices[j] = (indices[j] + 1) % set.length;
            if (indices[j] !== 0) break;
          }
        }
      }
      return out;
    }
  }
}

function padNumber(n: number, width?: number): string {
  const s = String(n);
  if (!width || s.length >= width) return s;
  return "0".repeat(width - s.length) + s;
}

export function generateTuples(mode: AttackMode, lists: string[][], positionCount: number): string[][] | string {
  if (positionCount === 0) return "No §positions§ marked in the template";
  if (mode === "sniper" || mode === "battering-ram") {
    const list = lists[0];
    if (!list || list.length === 0) return "Payload set is empty";
    const tuples: string[][] = [];
    if (mode === "sniper") {
      // Attack each position in turn with the single payload set.
      for (let pos = 0; pos < positionCount; pos++) {
        for (const v of list) {
          const t = new Array<string>(positionCount).fill("");
          t[pos] = v;
          tuples.push(t);
        }
      }
    } else {
      // Battering ram: same payload into every marked position at once.
      for (const v of list) tuples.push(new Array<string>(positionCount).fill(v));
    }
    return tuples;
  }

  if (lists.length !== positionCount) {
    return `${mode === "pitchfork" ? "Pitchfork" : "Cluster bomb"} needs exactly one payload list per position (need ${positionCount}, got ${lists.length})`;
  }
  if (lists.some((l) => l.length === 0)) return "Payload sets are empty";

  if (mode === "pitchfork") {
    // Pair the lists by index; stop when the shortest list is exhausted.
    const k = Math.min(...lists.map((l) => l.length));
    const tuples: string[][] = [];
    for (let i = 0; i < k; i++) tuples.push(lists.map((l) => l[i]));
    return tuples;
  }

  // Cluster bomb: Cartesian product.
  const tuples: string[][] = [];
  const counters = lists.map(() => 0);
  const total = lists.reduce((acc, l) => acc * l.length, 1);
  for (let n = 0; n < total; n++) {
    tuples.push(counters.map((c, i) => lists[i][c]));
    for (let j = counters.length - 1; j >= 0; j--) {
      counters[j] = (counters[j] + 1) % lists[j].length;
      if (counters[j] !== 0) break;
    }
  }
  return tuples;
}

/** Rebuild the raw request by replacing marker slots with encoded/plain payload values. */
export function composeRequest(parts: string[], values: string[], encode: boolean): string {
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 0) {
      out.push(parts[i]);
    } else {
      const v = values[(i - 1) / 2] ?? "";
      out.push(encode ? encodeURIComponent(v) : v);
    }
  }
  return out.join("");
}

export interface ParsedRawRequest {
  method: string;
  path: string;
  headers: { name: string; value: string }[];
  body: string;
  host: string;
}

/** Parse a raw HTTP request (request line, headers, blank line, body). Accepts origin-form or absolute-form targets. */
export function parseRawRequest(raw: string): ParsedRawRequest {
  const result: ParsedRawRequest = { method: "GET", path: "/", headers: [], body: "", host: "" };
  const nl = raw.indexOf("\r\n");
  const sepHeaders = nl >= 0 ? raw.indexOf("\n\n") : -1; // rare, CRLF expected
  let head = raw;
  let body = "";
  if (nl >= 0) {
    const doubleCR = raw.indexOf("\r\n\r\n");
    if (doubleCR >= 0) {
      head = raw.slice(0, doubleCR);
      body = raw.slice(doubleCR + 4);
    } else {
      head = raw.split(/\r?\n/)[0];
      body = raw.slice(raw.indexOf("\n") + 1);
      // no header separator: the template may be request-line only
    }
  }
  const lines = head.split(/\r?\n/);
  const m = /^(\S+)\s+(\S+)(?:\s+HTTP\/\S+)?$/.exec(lines[0].trim());
  if (!m) return result;
  result.method = m[1];
  let target = m[2];
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (name.toLowerCase() === "host") result.host = value;
    result.headers.push({ name, value });
  }
  const abs = /^https?:\/\//i.exec(target);
  if (abs) {
    try {
      const u = new URL(target);
      target = u.pathname + (u.search || "");
      result.host = u.host;
    } catch {
      /* keep as-is */
    }
  }
  result.path = target.startsWith("/") ? target : "/" + target;
  result.body = body;
  return result;
}

/** Normalize the body line endings to CRLF for a valid raw HTTP request. */
export function normalizeRawHttp(raw: string): string {
  const parts = raw.split(/\r?\n/);
  const sepIdx = parts.findIndex((p, i) => p.trim() === "" && i > 0);
  if (sepIdx < 0) return parts.join("\r\n") + "\r\n\r\n";
  const head = parts.slice(0, sepIdx).join("\r\n");
  const body = parts.slice(sepIdx + 1).join("\r\n");
  return body ? `${head}\r\n\r\n${body}\r\n` : `${head}\r\n\r\n`;
}
