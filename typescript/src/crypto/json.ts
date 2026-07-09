/**
 * Compact JSON serialization matching Python's
 * `json.dumps(obj, separators=(",", ":"))` (the default `ensure_ascii=True`).
 *
 * `JSON.stringify` matches Python for separators, control-character escaping,
 * and `"`/`\` escaping. Two divergences are handled explicitly:
 *
 *  1. Non-ASCII: Python escapes every code point above U+007E as `\uXXXX`,
 *     whereas `JSON.stringify` emits them raw. We reproduce that escaping.
 *
 *  2. Numbers: `JSON.stringify` and Python `json.dumps` agree on integers within
 *     the safe range and on ordinary decimals (e.g. `279.99` → `"279.99"` in
 *     both), but diverge on a few edge classes: integers beyond ±(2^53 − 1)
 *     lose precision in JS, and floats that one side renders in scientific
 *     notation (`1e20` → `100000000000000000000` vs `1e+20`; `1e-7` → `1e-7`
 *     vs `1e-07`). For the agreeing cases we pass the value through untouched
 *     (byte-identical to Python). For the genuinely-divergent edge cases — which
 *     would silently break cross-impl `sd_hash`/signature verification — we
 *     reject, since the VI spec only ever calls for integers in minor units and
 *     integer Unix timestamps anyway. Ordinary non-integer numbers that
 *     serialize identically in both runtimes are allowed (a generic serializer
 *     cannot assume every number is a VI amount).
 *
 * Note on key order: both impls rely on insertion order for *string* keys.
 * ECMAScript additionally hoists integer-index keys (decimal-string keys like
 * `"10"`) ahead of string keys and sorts them numerically, which Python does
 * not. VI's serialized structures use only fixed non-numeric schema field
 * names, so this never arises — but callers MUST NOT serialize objects with
 * purely-decimal-integer string keys through this function.
 */
export function compactJson(value: unknown): string {
  return asciiEscape(JSON.stringify(value, numberGuard));
}

// Reject only numbers whose textual form actually diverges from Python's
// `json.dumps`; pass through every number that both runtimes serialize the same
// way (so a legitimate decimal like 279.99 is preserved). Divergent classes:
//   - NaN / Infinity            — not representable in JSON (JS emits `null`).
//   - non-safe integers         — |n| ≥ 2^53 loses precision / Python prints all digits.
//   - floats in scientific form — |n| < 1e-4 or ≥ 1e16, or any value JS prints
//                                 with an exponent, where JS and Python differ.
function numberGuard(_key: string, v: unknown): unknown {
  if (typeof v !== 'number') return v;
  if (!Number.isFinite(v)) {
    throw new Error(`compactJson: ${v} is not representable in JSON`);
  }
  if (Number.isInteger(v)) {
    if (!Number.isSafeInteger(v)) {
      throw new Error(
        `compactJson: integer ${v} exceeds the safe range (±2^53) and would serialize differently from the Python reference`,
      );
    }
    return v;
  }
  const abs = Math.abs(v);
  if (abs < 1e-4 || abs >= 1e16 || String(v).includes('e')) {
    throw new Error(
      `compactJson: float ${v} would serialize in scientific notation differently from the Python reference; ` +
        'use integer minor units per the VI spec.',
    );
  }
  return v;
}

// Every code point in U+007F..U+FFFF (built from escapes to avoid literal
// non-ASCII bytes in this source file). Astral characters are escaped via their
// surrogate halves, which also fall in this range — matching Python.
const NON_ASCII = new RegExp('[\\u007f-\\uffff]', 'g');

/** Escape non-ASCII as `\uXXXX`, matching Python's `ensure_ascii=True`. */
export function asciiEscape(s: string): string {
  return s.replace(NON_ASCII, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}
