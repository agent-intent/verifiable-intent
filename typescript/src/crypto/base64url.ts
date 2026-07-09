/** base64url (unpadded) helpers, matching the Python reference byte-for-byte. */

export function b64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

export function b64urlDecode(s: string): Uint8Array {
  // Match Python's `urlsafe_b64decode`, which raises on a length that is 1 more
  // than a multiple of 4 (an impossible base64 length). Node's decoder would
  // otherwise silently return empty/garbage bytes for such input.
  if (s.length % 4 === 1) {
    throw new Error(`Invalid base64url string: length ${s.length} is not a valid base64 length`);
  }
  // Python's `urlsafe_b64decode(str)` first does `.encode('ascii')`, raising on
  // any non-ASCII character. Node would silently skip them as non-alphabet.
  if (NON_ASCII_CHAR.test(s)) {
    throw new Error('Invalid base64url string: contains non-ASCII characters');
  }
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

/** UTF-8 encode a string to bytes (compact JSON is ASCII, so this equals the ASCII bytes). */
export function utf8(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'utf8'));
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
  return new Uint8Array(Buffer.from(s, 'ascii'));
}
