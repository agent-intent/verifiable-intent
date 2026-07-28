/**
 * Python-parity re-encoding of a *previously signed* JSON segment.
 *
 * Signature verification re-encodes the decoded header/payload objects (never
 * the raw signed bytes) so in-memory mutations are caught. Python's
 * `json.loads`/`json.dumps` round-trip preserves the int/float distinction
 * (`1.0` → `1.0`), but JS `JSON.parse` collapses `1.0` to `1` and rounds
 * integers beyond ±2^53, so a plain `JSON.stringify` re-encode diverges from
 * the signed bytes for those numbers and verification silently fails on
 * credentials Python accepts.
 *
 * This module closes that gap: {@link parsePySegment} re-parses the raw
 * segment text capturing each number's original lexeme (via `JSON.parse`
 * source access), and re-serializes the value exactly as Python's
 * `json.dumps(obj, separators=(",", ":"))` would — `1.0` stays `1.0`, `1e2`
 * becomes `100.0`, big integers keep all their digits, floats outside
 * [1e-4, 1e16) use Python's `e±NN` notation. The caller only uses this
 * re-encoding when the in-memory object is still deep-equal to the parsed
 * segment ({@link pyDeepEqual}), so mutation detection is preserved: any
 * value change falls back to the strict `compactJson` path and the signature
 * check fails, exactly as it does in Python.
 *
 * On runtimes without `JSON.parse` source access (pre-V8 12 / Node < 21),
 * {@link parsePySegment} returns null and callers keep today's stricter
 * behavior (such credentials verify as false instead of matching Python).
 */

import { asciiEscape } from './json.js';

/** A number captured with its original JSON lexeme. */
class PyNum {
  constructor(
    readonly value: number,
    readonly source: string,
  ) {}
}

// Feature-detect JSON.parse source access (the `context` reviver parameter).
const HAS_SOURCE_ACCESS = ((): boolean => {
  let seen = false;
  try {
    JSON.parse('1', ((_k: string, v: unknown, ctx?: { source?: string }) => {
      seen = typeof ctx?.source === 'string';
      return v;
    }) as unknown as (key: string, value: unknown) => unknown);
  } catch {
    return false;
  }
  return seen;
})();

export interface ParsedSegment {
  /** The parsed value, identical to what `JSON.parse(text)` yields. */
  value: unknown;
  /** The segment re-serialized as Python `json.dumps(separators=(",", ":"))` would. */
  pyText: string;
}

/**
 * Parse a JSON segment and compute its Python-compact re-serialization.
 * Returns null when the runtime lacks source access or the text is not JSON.
 */
export function parsePySegment(text: string): ParsedSegment | null {
  if (!HAS_SOURCE_ACCESS) return null;
  let tree: unknown;
  try {
    tree = JSON.parse(text, ((_k: string, v: unknown, ctx?: { source?: string }) =>
      typeof v === 'number' && typeof ctx?.source === 'string' ? new PyNum(v, ctx.source) : v) as unknown as (
      key: string,
      value: unknown,
    ) => unknown);
  } catch {
    return null;
  }
  return walk(tree);
}

function walk(node: unknown): ParsedSegment {
  if (node instanceof PyNum) {
    return { value: node.value, pyText: pyNumberText(node) };
  }
  if (node === null || typeof node === 'boolean') {
    return { value: node, pyText: String(node) };
  }
  if (typeof node === 'string') {
    return { value: node, pyText: asciiEscape(JSON.stringify(node)) };
  }
  if (Array.isArray(node)) {
    const items = node.map(walk);
    return { value: items.map((i) => i.value), pyText: `[${items.map((i) => i.pyText).join(',')}]` };
  }
  // JSON.parse can only produce plain objects beyond the cases above.
  const obj = node as Record<string, unknown>;
  const value: Record<string, unknown> = {};
  const parts: string[] = [];
  for (const key of Object.keys(obj)) {
    const item = walk(obj[key]);
    value[key] = item.value;
    parts.push(`${asciiEscape(JSON.stringify(key))}:${item.pyText}`);
  }
  return { value, pyText: `{${parts.join(',')}}` };
}

/**
 * Render a parsed number as Python `json.dumps` would.
 *
 * A lexeme without `.`/`e`/`E` is a Python int: all digits are kept exactly
 * (BigInt, so nothing rounds) and `-0` canonicalizes to `0`. Anything else is
 * a Python float, rendered with `repr` semantics: shortest round-trip digits
 * (shared with JS), `.0` suffix on integral values, and `e±NN` scientific
 * notation only outside [1e-4, 1e16) — where JS `String()` would disagree.
 */
function pyNumberText(num: PyNum): string {
  const { value, source } = num;
  if (!/[.eE]/.test(source)) {
    return BigInt(source).toString();
  }
  if (Object.is(value, -0)) return '-0.0';
  if (Number.isInteger(value) && Math.abs(value) < 1e16) return `${value}.0`;
  const [mantissa, expPart] = value.toExponential().split('e') as [string, string];
  const exp = Number(expPart);
  if (exp < -4 || exp >= 16) {
    return `${mantissa}e${exp < 0 ? '-' : '+'}${String(Math.abs(exp)).padStart(2, '0')}`;
  }
  return String(value);
}

/**
 * Order-sensitive deep equality between a parsed segment value and a live
 * object. Numbers compare with `Object.is` so a `-0` → `0` mutation is caught
 * (Python re-encodes the mutated value and the signature fails). Object key
 * *order* participates because Python's `json.dumps` serializes dicts in
 * insertion order — reordered keys change the signed bytes.
 */
export function pyDeepEqual(a: unknown, b: unknown): boolean {
  if (typeof a === 'number' || typeof b === 'number') {
    return Object.is(a, b);
  }
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
    return a === b;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => pyDeepEqual(v, b[i]));
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((k, i) => k === bKeys[i] && pyDeepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}
