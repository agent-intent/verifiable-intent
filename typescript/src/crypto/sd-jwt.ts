/** SD-JWT creation, parsing, signature verification, and disclosure resolution. */

import { b64urlDecode, b64urlEncode, utf8, utf8Decode } from './base64url.js';
import { type DecodedDisclosure, decodeDisclosure, hashDisclosure } from './disclosure.js';
import { compactJson } from './json.js';
import { parsePySegment, pyDeepEqual } from './py-json.js';
import { type Es256Jwk, jwtDecodeParts, jwtEncode, makeSigner, makeVerifier } from './signing.js';

export interface SdJwtInit {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
  disclosures?: string[];
  disclosureValues?: DecodedDisclosure[];
  rawHeaderB64?: string | null;
  rawPayloadB64?: string | null;
}

/** A parsed SD-JWT with its disclosures. */
export class SdJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
  disclosures: string[];
  disclosureValues: DecodedDisclosure[];
  rawHeaderB64: string | null;
  rawPayloadB64: string | null;

  constructor(init: SdJwtInit) {
    this.header = init.header;
    this.payload = init.payload;
    this.signature = init.signature;
    this.disclosures = init.disclosures ?? [];
    this.disclosureValues = init.disclosureValues ?? [];
    this.rawHeaderB64 = init.rawHeaderB64 ?? null;
    this.rawPayloadB64 = init.rawPayloadB64 ?? null;
  }

  /** `<header>.<payload>.<sig>` — prefers captured raw segments for round-trip stability. */
  get issuerJwt(): string {
    const h = this.rawHeaderB64 ?? b64urlEncode(utf8(compactJson(this.header)));
    const p = this.rawPayloadB64 ?? b64urlEncode(utf8(compactJson(this.payload)));
    return `${h}.${p}.${b64urlEncode(this.signature)}`;
  }

  /**
   * Serialize to `<jwt>~<d1>~<d2>~`. If `includeDisclosures` is given, only
   * those indices — with Python list semantics: negative indices count from
   * the end, and an out-of-range index throws (Python raises IndexError)
   * rather than being silently skipped, since a dropped disclosure would
   * change the produced presentation bytes.
   */
  serialize(includeDisclosures?: number[]): string {
    const parts = [this.issuerJwt];
    if (includeDisclosures !== undefined) {
      for (const i of includeDisclosures) {
        const d = this.disclosures.at(i);
        if (d === undefined) {
          throw new RangeError(`Disclosure index ${i} out of range (have ${this.disclosures.length})`);
        }
        parts.push(d);
      }
    } else {
      parts.push(...this.disclosures);
    }
    return parts.join('~') + '~';
  }
}

/** Create an SD-JWT. The payload must already include `_sd`/`_sd_alg` as needed. */
export async function createSdJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  disclosures: string[],
  privateJwk: Es256Jwk,
): Promise<SdJwt> {
  const signer = await makeSigner(privateJwk);
  const token = await jwtEncode(header, payload, signer);
  const [rawHeaderB64, rawPayloadB64] = token.split('.');
  const decoded = jwtDecodeParts(token);
  const disclosureValues = disclosures.map(decodeDisclosure);
  return new SdJwt({
    header: decoded.header,
    payload: decoded.payload,
    signature: decoded.signature,
    disclosures,
    disclosureValues,
    rawHeaderB64: rawHeaderB64 ?? null,
    rawPayloadB64: rawPayloadB64 ?? null,
  });
}

/** Parse a serialized SD-JWT. Throws on malformed input. */
export function decodeSdJwt(serialized: string): SdJwt {
  try {
    const parts = serialized.split('~');
    const jwtPart = parts[0] ?? '';
    const disclosures = parts.slice(1).filter((d) => d.length > 0);
    const decoded = jwtDecodeParts(jwtPart);
    const seg = jwtPart.split('.');
    const disclosureValues = disclosures.map(decodeDisclosure);
    return new SdJwt({
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      disclosures,
      disclosureValues,
      rawHeaderB64: seg[0] ?? null,
      rawPayloadB64: seg[1] ?? null,
    });
  } catch (e) {
    throw new Error(`Invalid SD-JWT: ${(e as Error).message}`);
  }
}

/**
 * Verify the issuer signature. Always re-encodes from the current header/payload
 * objects (never the cached raw segments) so in-memory mutations are caught.
 * Returns false (never rejects) on a malformed key or signature.
 */
export async function verifySdJwtSignature(sdJwt: SdJwt, publicJwk: Es256Jwk): Promise<boolean> {
  try {
    const h = reencodeSegmentB64(sdJwt.rawHeaderB64, sdJwt.header);
    const p = reencodeSegmentB64(sdJwt.rawPayloadB64, sdJwt.payload);
    if (sdJwt.signature.length !== 64) return false;
    const verifier = await makeVerifier(publicJwk);
    return await verifier(`${h}.${p}`, b64urlEncode(sdJwt.signature));
  } catch {
    // Re-encoding failure or a malformed public JWK (importKey reject): fail closed.
    return false;
  }
}

/**
 * Re-encode one JWT segment for signature verification, as Python's
 * `json.dumps(current_object)` would.
 *
 * Python's loads/dumps round-trip preserves number spellings JS can't hold in
 * a `number` (`1.0`, big integers), so a plain `compactJson` re-encode falsely
 * fails on such credentials. When the current object is still deep-equal to
 * what the raw segment parses to (i.e. unmutated), we re-serialize the segment
 * with Python semantics — its number lexemes tell us int vs float. Any
 * mutation makes the deep-equal fail and drops to the strict `compactJson`
 * path, whose output then mismatches the signed bytes — same rejection Python
 * produces by re-encoding the mutated object.
 */
function reencodeSegmentB64(rawB64: string | null, current: Record<string, unknown>): string {
  if (rawB64 !== null) {
    const seg = parsePySegment(utf8Decode(b64urlDecode(rawB64)));
    if (seg !== null && pyDeepEqual(seg.value, current)) {
      return b64urlEncode(utf8(seg.pyText));
    }
  }
  return b64urlEncode(utf8(compactJson(current)));
}

/** Resolve all disclosures into the payload, returning a full claim set. */
export async function resolveDisclosures(sdJwt: SdJwt): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = { ...sdJwt.payload };

  const sdRaw = result['_sd'];
  const sdHashes = new Set(Array.isArray(sdRaw) ? sdRaw.filter((v): v is string => typeof v === 'string') : []);

  // Object-property disclosures (3-element) whose digest is listed in `_sd`
  // become payload claims, applied in *presentation order* — on a claim-name
  // collision the last presented disclosure wins, matching Python's
  // `zip(disclosures, disclosure_values)` loop (NOT the `_sd` array order,
  // which can resolve a different value for identical hostile input).
  // length-2 array-element disclosures are resolved via delegate_payload below.
  const valueByHash = new Map<string, DecodedDisclosure>();
  for (let i = 0; i < sdJwt.disclosures.length; i++) {
    const disc = sdJwt.disclosures[i];
    const dv = sdJwt.disclosureValues[i];
    if (disc === undefined || dv === undefined) continue;
    const discHash = await hashDisclosure(disc);
    valueByHash.set(discHash, dv);
    if (sdHashes.has(discHash) && dv.length === 3 && typeof dv[1] === 'string') {
      result[dv[1]] = dv[2];
    }
  }

  // Array-element disclosures referenced by `delegate_payload` resolve to their value.
  const delegatePayload = result['delegate_payload'];
  if (Array.isArray(delegatePayload) && delegatePayload.length > 0) {
    result['delegate_payload'] = delegatePayload.map((item: unknown) => {
      if (item && typeof item === 'object' && '...' in item) {
        const refHash: unknown = (item as Record<string, unknown>)['...'];
        const dv = typeof refHash === 'string' ? valueByHash.get(refHash) : undefined;
        return dv ? dv[dv.length - 1] : item;
      }
      return item;
    });
  }

  return result;
}
