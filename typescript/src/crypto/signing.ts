/**
 * ES256 (ECDSA P-256) signing built on WebCrypto (`crypto.subtle` — a global in
 * browsers and Node >= 20 alike), plus the compact JWT encode/decode used
 * throughout the Verifiable Intent layers.
 *
 * The signer returns a base64url-encoded raw 64-byte (r‖s) JOSE signature —
 * exactly what WebCrypto's ECDSA produces (IEEE P1363 form) and the same form
 * the Python reference produces — so signatures verify across both
 * implementations.
 */

import { b64urlDecode, b64urlEncode, utf8, utf8Decode } from './base64url.js';
import { compactJson } from './json.js';

/** An EC P-256 JSON Web Key. `d` is present only for private keys. */
export interface Es256Jwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
  kid?: string;
  [key: string]: unknown;
}

export const ALG = 'ES256';

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

/**
 * JOSE header for JWTs this library constructs. `alg` is pinned to ES256 —
 * the spec's whitelist — so a widened algorithm can't compile on the issuance
 * path. Inbound headers on the verification path are untrusted and stay
 * `unknown` until `validateHeader` runs.
 */
export interface IssuanceHeader {
  alg: typeof ALG;
  typ: string;
  kid?: string;
  [param: string]: unknown;
}

export type Signer = (data: string) => Promise<string>;
export type Verifier = (data: string, signatureBase64url: string) => Promise<boolean>;

export async function makeSigner(privateJwk: Es256Jwk): Promise<Signer> {
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, ECDSA_P256, false, ['sign']);
  return async (data: string): Promise<string> => {
    const signature = await crypto.subtle.sign(ECDSA_SHA256, privateKey, utf8(data));
    return b64urlEncode(new Uint8Array(signature));
  };
}

export async function makeVerifier(publicJwk: Es256Jwk): Promise<Verifier> {
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, ECDSA_P256, false, ['verify']);
  return async (data: string, signatureBase64url: string): Promise<boolean> => {
    return crypto.subtle.verify(ECDSA_SHA256, publicKey, b64urlDecode(signatureBase64url), utf8(data));
  };
}

export async function generateEs256Key(): Promise<{ publicKey: Es256Jwk; privateKey: Es256Jwk }> {
  const keyPair = await crypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const publicKey = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as Es256Jwk;
  const privateKey = (await crypto.subtle.exportKey('jwk', keyPair.privateKey)) as Es256Jwk;
  return { publicKey, privateKey };
}

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
}

/** Encode and ES256-sign a compact JWT: `b64url(header).b64url(payload).b64url(sig)`. */
export async function jwtEncode(header: object, payload: object, signer: Signer): Promise<string> {
  const h = b64urlEncode(utf8(compactJson(header)));
  const p = b64urlEncode(utf8(compactJson(payload)));
  const sig = await signer(`${h}.${p}`);
  return `${h}.${p}.${sig}`;
}

export function jwtDecodeParts(token: string): JwtParts {
  const parts = token.split('.');
  const [headerB64, payloadB64, sigB64] = parts;
  if (parts.length !== 3 || headerB64 === undefined || payloadB64 === undefined || sigB64 === undefined) {
    throw new Error(`Invalid JWT: expected 3 parts, got ${parts.length}`);
  }
  // All three segments go through b64urlDecode so impossible base64 lengths and
  // non-ASCII input are rejected, matching Python's urlsafe_b64decode.
  const header = JSON.parse(utf8Decode(b64urlDecode(headerB64))) as Record<string, unknown>;
  const payload = JSON.parse(utf8Decode(b64urlDecode(payloadB64))) as Record<string, unknown>;
  const signature = b64urlDecode(sigB64);
  return { header, payload, signature };
}

/**
 * Verify a detached ES256 signature over `signingInput` (raw bytes), given a public JWK.
 * Returns false (never rejects) on a malformed key or signature.
 */
export async function es256Verify(signingInput: string, signature: Uint8Array, publicJwk: Es256Jwk): Promise<boolean> {
  if (signature.length !== 64) return false;
  try {
    const verifier = await makeVerifier(publicJwk);
    return await verifier(signingInput, b64urlEncode(signature));
  } catch {
    // A malformed/non-P-256 public JWK makes importKey reject; fail closed, don't throw.
    return false;
  }
}
