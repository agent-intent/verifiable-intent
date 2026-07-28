/** SD-JWT selective-disclosure utilities, matching the Python reference byte-for-byte. */

import { asciiBytes, b64urlDecode, b64urlEncode, utf8, utf8Decode } from './base64url.js';
import { compactJson } from './json.js';

/** A delegate-payload reference: `{"...": "<disclosure-hash>"}`. */
export interface DelegateRef {
  '...': string;
}

/**
 * A decoded disclosure, per RFC 9901 §4.2: `[salt, claimName, claimValue]`
 * (object property) or `[salt, claimValue]` (array element). Only the arity is
 * checked at decode time (parity with the Python reference, which returns the
 * raw list); consumers keep their per-element runtime guards for hostile input.
 */
export type DecodedDisclosure = [salt: string, claimName: string, claimValue: unknown] | [salt: string, claimValue: unknown];

/** Random 128-bit disclosure salt, base64url-encoded (16 bytes, as in the Python reference). */
export async function generateSalt(): Promise<string> {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * Create an SD-JWT disclosure.
 *  - object property: `[salt, claimName, claimValue]`
 *  - array element:   `[salt, claimValue]` (pass `claimName = null`)
 */
export async function createDisclosure(claimName: string | null, claimValue: unknown, salt?: string): Promise<string> {
  const s = salt ?? (await generateSalt());
  const arr = claimName !== null ? [s, claimName, claimValue] : [s, claimValue];
  return b64urlEncode(utf8(compactJson(arr)));
}

export function decodeDisclosure(disclosureB64: string): DecodedDisclosure {
  // Route through b64urlDecode so impossible base64 lengths and non-ASCII input
  // are rejected, matching Python's urlsafe_b64decode.
  const parsed = JSON.parse(utf8Decode(b64urlDecode(disclosureB64))) as unknown;
  // Per SD-JWT, a disclosure is [salt, value] (array element) or [salt, name, value] (object property).
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new Error('Invalid disclosure: expected a 2- or 3-element array');
  }
  return parsed as DecodedDisclosure;
}

/**
 * SHA-256 of the ASCII base64url disclosure *string* (not its decoded bytes), per SD-JWT.
 *
 * Not declared `async` on purpose: the non-ASCII guard must throw SYNCHRONOUSLY
 * (parity with Python's `str.encode('ascii')` UnicodeEncodeError, pinned by the
 * parity tests), which an `async` function would convert into a rejection.
 */
export function hashDisclosure(disclosureB64: string): Promise<string> {
  return hashBytes(asciiBytes(disclosureB64));
}

export async function createSdArray(disclosures: string[]): Promise<string[]> {
  return Promise.all(disclosures.map(hashDisclosure));
}

/** SHA-256 of raw bytes, base64url-encoded. */
export async function hashBytes(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64urlEncode(new Uint8Array(digest));
}

/**
 * SHA-256 of an ASCII string, base64url-encoded (used for sd_hash / checkout_hash).
 * Throws synchronously on non-ASCII input — see `hashDisclosure`.
 */
export function hashAscii(s: string): Promise<string> {
  return hashBytes(asciiBytes(s));
}

export function createDelegateRef(disclosureHash: string): DelegateRef {
  return { '...': disclosureHash };
}

/**
 * Build a selective SD-JWT presentation string `<baseJwt>~<d1>~<d2>~...~`.
 * Used to compute the per-recipient L3 `sd_hash`.
 */
export function buildSelectivePresentation(baseJwt: string, disclosures: string[]): string {
  return [baseJwt, ...disclosures].join('~') + '~';
}
