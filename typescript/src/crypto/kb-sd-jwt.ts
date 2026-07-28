/** Key-Bound SD-JWT (KB-SD-JWT) operations.
 *
 * Exposed for completeness/interoperability. The Verifiable Intent L2/L3 flows
 * embed the holder-binding claims directly in the SD-JWT payload (see issuance/)
 * rather than appending a trailing KB-JWT, so these helpers are not used by the
 * main pipeline.
 */

import { b64urlEncode, utf8 } from './base64url.js';
import { hashAscii } from './disclosure.js';
import { compactJson } from './json.js';
import { SdJwt } from './sd-jwt.js';
import { type Es256Jwk, type IssuanceHeader, jwtDecodeParts, jwtEncode, makeSigner, makeVerifier } from './signing.js';

/**
 * KB-JWT payload per RFC 9901: `iat`, `aud`, `nonce`, and `sd_hash` are
 * REQUIRED in the signed payload; additional claims are permitted (open index
 * signature). `sd_hash` may be omitted on input — `createKbSdJwt` computes it
 * from the presentation. Applies to the construction path only; inbound
 * KB-JWTs are untrusted and stay `unknown` until verification passes.
 */
export interface KbJwtPayload {
  iat: number;
  aud: string;
  nonce: string;
  sd_hash?: string;
  [claim: string]: unknown;
}

/** The holder-binding proof appended to an SD-JWT. */
export class KbSdJwt {
  constructor(
    public header: Record<string, unknown>,
    public payload: Record<string, unknown>,
    public signature: Uint8Array,
  ) {}

  get jwt(): string {
    const h = b64urlEncode(utf8(compactJson(this.header)));
    const p = b64urlEncode(utf8(compactJson(this.payload)));
    return `${h}.${p}.${b64urlEncode(this.signature)}`;
  }
}

/** A complete SD-JWT presentation with a key-binding proof. */
export class SdJwtWithKb {
  constructor(
    public sdJwt: SdJwt,
    public kbJwt: KbSdJwt,
    public disclosedIndices: number[] | null = null,
  ) {}

  serialize(): string {
    const sdPart = this.sdJwt.serialize(this.disclosedIndices ?? undefined);
    return sdPart + this.kbJwt.jwt;
  }
}

export async function createKbSdJwt(
  sdJwt: SdJwt,
  holderHeader: IssuanceHeader,
  holderPayload: KbJwtPayload,
  holderPrivateJwk: Es256Jwk,
  disclosedIndices: number[] | null = null,
): Promise<SdJwtWithKb> {
  const payload: Record<string, unknown> = { ...holderPayload };
  if (!('sd_hash' in payload)) {
    payload['sd_hash'] = await hashAscii(sdJwt.serialize(disclosedIndices ?? undefined));
  }
  const signer = await makeSigner(holderPrivateJwk);
  const token = await jwtEncode(holderHeader, payload, signer);
  const decoded = jwtDecodeParts(token);
  const kb = new KbSdJwt(decoded.header, decoded.payload, decoded.signature);
  return new SdJwtWithKb(sdJwt, kb, disclosedIndices);
}

/** Verify a key-binding JWT signature. Returns false (never rejects) on any invalid input. */
export async function verifyKbJwt(kbJwt: KbSdJwt, publicJwk: Es256Jwk): Promise<boolean> {
  if (kbJwt.signature.length !== 64) return false;
  try {
    const h = b64urlEncode(utf8(compactJson(kbJwt.header)));
    const p = b64urlEncode(utf8(compactJson(kbJwt.payload)));
    const verifier = await makeVerifier(publicJwk);
    return await verifier(`${h}.${p}`, b64urlEncode(kbJwt.signature));
  } catch {
    // Malformed/non-P-256 public JWK (importKey reject): fail closed.
    return false;
  }
}
