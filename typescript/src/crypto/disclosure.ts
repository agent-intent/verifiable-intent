/** SD-JWT selective-disclosure utilities, matching the Python reference byte-for-byte. */

import { createHash, randomBytes } from 'node:crypto';

import { asciiBytes, b64urlDecode, b64urlEncode, utf8 } from './base64url.js';
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

export function generateSalt(): string {
  return b64urlEncode(new Uint8Array(randomBytes(16)));
}

/**
 * Create an SD-JWT disclosure.
 *  - object property: `[salt, claimName, claimValue]`
 *  - array element:   `[salt, claimValue]` (pass `claimName = null`)
 */
export function createDisclosure(claimName: string | null, claimValue: unknown, salt?: string): string {
  const s = salt ?? generateSalt();
  const arr = claimName !== null ? [s, claimName, claimValue] : [s, claimValue];
  return b64urlEncode(utf8(compactJson(arr)));
}

export function decodeDisclosure(disclosureB64: string): DecodedDisclosure {
  // Route through b64urlDecode (not Buffer.from directly) so impossible base64
  // lengths and non-ASCII input are rejected, matching Python's urlsafe_b64decode.
  const parsed = JSON.parse(Buffer.from(b64urlDecode(disclosureB64)).toString('utf8')) as unknown;
  // Per SD-JWT, a disclosure is [salt, value] (array element) or [salt, name, value] (object property).
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new Error('Invalid disclosure: expected a 2- or 3-element array');
  }
  return parsed as DecodedDisclosure;
}

/** SHA-256 of the ASCII base64url disclosure *string* (not its decoded bytes), per SD-JWT. */
export function hashDisclosure(disclosureB64: string): string {
  const digest = createHash('sha256').update(asciiBytes(disclosureB64)).digest();
  return b64urlEncode(new Uint8Array(digest));
}

export function createSdArray(disclosures: string[]): string[] {
  return disclosures.map(hashDisclosure);
}

/** SHA-256 of raw bytes, base64url-encoded. */
export function hashBytes(data: Uint8Array): string {
  const digest = createHash('sha256').update(data).digest();
  return b64urlEncode(new Uint8Array(digest));
}

/** SHA-256 of an ASCII string, base64url-encoded (used for sd_hash / checkout_hash). */
export function hashAscii(s: string): string {
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
