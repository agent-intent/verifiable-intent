/**
 * base64url (unpadded) helpers, matching the Python reference byte-for-byte.
 *
 * Pure-JS over Uint8Array — no Buffer, no btoa/atob — so the package runs in
 * any Web-standard runtime (browsers and Node >= 20 alike).
 */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Reverse lookup over ASCII: 6-bit value per code point, -1 for non-alphabet.
// Both base64 alphabets are accepted ('+/' map to the same values as '-_'),
// matching Node's base64url decoder (and Python's urlsafe b64decode, which
// only ever translates -_ back to +/).
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) {
  DECODE_TABLE[B64URL_ALPHABET.charCodeAt(i)] = i;
}
DECODE_TABLE[0x2b] = 62; // '+'
DECODE_TABLE[0x2f] = 63; // '/'

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function b64urlEncode(data: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64URL_ALPHABET[(acc >> bits) & 0x3f];
    }
  }
  if (bits > 0) {
    out += B64URL_ALPHABET[(acc << (6 - bits)) & 0x3f];
  }
  return out;
}

export function b64urlDecode(s: string): Uint8Array {
  // Match Python's `urlsafe_b64decode` (after its padding fixup), which raises
  // on a length that is 1 more than a multiple of 4 (an impossible base64
  // length). Lenient decoders would otherwise silently return empty/garbage
  // bytes for such input.
  if (s.length % 4 === 1) {
    throw new Error(`Invalid base64url string: length ${s.length} is not a valid base64 length`);
  }
  // Python's `urlsafe_b64decode(str)` first does `.encode('ascii')`, raising on
  // any non-ASCII character. Lenient decoders would silently skip them as
  // non-alphabet.
  if (NON_ASCII_CHAR.test(s)) {
    throw new Error('Invalid base64url string: contains non-ASCII characters');
  }
  // Lenient core, byte-compatible with the previous Node-Buffer decoder (which
  // the parity tests pin): non-alphabet ASCII characters are skipped, decoding
  // stops at the first '=' padding character, and a trailing partial byte is
  // dropped.
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x3d) break; // '=': padding — stop decoding.
    const value = DECODE_TABLE[code] ?? -1;
    if (value < 0) continue;
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** UTF-8 encode a string to bytes (compact JSON is ASCII, so this equals the ASCII bytes). */
export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

/**
 * UTF-8 decode bytes to a string, replacing malformed sequences with U+FFFD —
 * the same lossy behavior as Node's `Buffer.toString('utf8')`.
 */
export function utf8Decode(data: Uint8Array): string {
  return textDecoder.decode(data);
}

const NON_ASCII_CHAR = /[\u0080-\uffff]/;

/**
 * Encode an ASCII string to bytes (used for hashing disclosure strings and
 * sd_hash / checkout_hash inputs). Throws on any code point above 0x7F,
 * matching Python's `str.encode('ascii')` — Node's `'ascii'` encoding would
 * instead silently mangle non-ASCII input (latin1-style), which made TS accept
 * hash bindings over bytes Python refuses to produce.
 */
export function asciiBytes(s: string): Uint8Array {
  if (NON_ASCII_CHAR.test(s)) {
    throw new Error('asciiBytes: input contains non-ASCII characters');
  }
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }
  return out;
}
