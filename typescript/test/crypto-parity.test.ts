/**
 * Crypto-layer Python-parity fixes: locks in a set of just-applied fixes to the
 * TypeScript port so the SDK rejects (or accepts) exactly what the authoritative
 * Python reference does. Each `describe` maps to one fix; fixtures marked
 * "Python-verified" were confirmed against the Python implementation out of band.
 *
 * These tests never invoke Python — they assert the TS behavior that must match.
 */

import { describe, expect, it } from 'vitest';

import {
  asciiBytes,
  b64urlDecode,
  b64urlEncode,
  type DecodedDisclosure,
  decodeDisclosure,
  decodeSdJwt,
  type Es256Jwk,
  hashDisclosure,
  jwtDecodeParts,
  resolveDisclosures,
  SdJwt,
  utf8,
  verifyCheckoutHashBinding,
  verifySdJwtSignature,
} from '../src/index.js';
// py-json is deliberately NOT re-exported from the public barrel; import direct.
import { parsePySegment, pyDeepEqual } from '../src/crypto/py-json.js';

// A non-ASCII string built from escapes so this source file stays ASCII (as the
// library sources deliberately are); at runtime it holds an actual "café".
const CAFE = 'café';

describe('b64urlDecode hardening (parity with Python urlsafe_b64decode)', () => {
  it('throws on length % 4 === 1 (an impossible base64 length)', () => {
    // 'AAAAA' is 5 chars, 5 % 4 === 1 — Python raises binascii.Error.
    expect(() => b64urlDecode('AAAAA')).toThrow();
  });

  it('throws on non-ASCII input (Python .encode("ascii") raises)', () => {
    // length 4 (so the length guard does not fire first) but contains a
    // non-ASCII code point, which Python rejects and Node would silently skip.
    expect(() => b64urlDecode(CAFE)).toThrow();
  });

  it('round-trips a valid encoded string', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    expect(Array.from(b64urlDecode(b64urlEncode(bytes)))).toEqual([1, 2, 3, 4, 5]);
  });
});

describe('decodeDisclosure hardening', () => {
  it('throws on a length % 4 === 1 disclosure (Python raises binascii.Error)', () => {
    // 37 chars, 37 % 4 === 1.
    expect(() => decodeDisclosure('WyJzYWx0MTIzNDU2NzgiLCJ4bmFtIiwidiJdA')).toThrow();
  });

  it('still decodes a valid disclosure', () => {
    // ["salt-aaaa-1234","vct","AAA"]
    expect(decodeDisclosure('WyJzYWx0LWFhYWEtMTIzNCIsInZjdCIsIkFBQSJd')).toEqual(['salt-aaaa-1234', 'vct', 'AAA']);
  });
});

describe('jwtDecodeParts hardening', () => {
  it('throws when the payload segment has length % 4 === 1', () => {
    const header = b64urlEncode(utf8('{"alg":"ES256","typ":"JWT"}'));
    // Payload segment 'AAAAA' is 5 chars (5 % 4 === 1); header decodes fine
    // first, then the payload decode must reject.
    const token = `${header}.AAAAA.AA`;
    expect(() => jwtDecodeParts(token)).toThrow();
  });
});

describe('asciiBytes / non-ASCII bindings (parity with Python str.encode("ascii"))', () => {
  it('asciiBytes throws on non-ASCII', () => {
    expect(() => asciiBytes(CAFE)).toThrow();
  });

  it('hashDisclosure throws on a non-ASCII disclosure string', () => {
    expect(() => hashDisclosure(CAFE)).toThrow();
  });

  it('encodes a plain ASCII string', () => {
    expect(Array.from(asciiBytes('AB'))).toEqual([0x41, 0x42]);
  });

  it('verifyCheckoutHashBinding PROPAGATES on a non-ASCII checkout_jwt (matches Python UnicodeEncodeError)', () => {
    // Previously returned a verdict; the fix lets asciiBytes' error propagate,
    // matching Python's uncaught UnicodeEncodeError rather than failing open.
    expect(() => verifyCheckoutHashBinding({ checkout_jwt: CAFE, checkout_hash: 'x' }, {})).toThrow();
  });
});

describe('SdJwt.serialize — Python list-index semantics', () => {
  // Deterministic issuer JWT via raw segments + a fixed 3-byte signature.
  // b64urlEncode([1,2,3]) === 'AQID', so issuerJwt === 'hdr.pl.AQID'.
  function makeSdJwt(): SdJwt {
    return new SdJwt({
      header: {},
      payload: {},
      signature: new Uint8Array([1, 2, 3]),
      disclosures: ['d0', 'd1', 'd2'],
      rawHeaderB64: 'hdr',
      rawPayloadB64: 'pl',
    });
  }

  it('negative indices wrap: serialize([-1]) picks the last disclosure', () => {
    expect(makeSdJwt().serialize([-1])).toBe('hdr.pl.AQID~d2~');
  });

  it('serializes selected indices in the given order', () => {
    expect(makeSdJwt().serialize([0, 2])).toBe('hdr.pl.AQID~d0~d2~');
  });

  it('serialize() with no argument includes every disclosure', () => {
    expect(makeSdJwt().serialize()).toBe('hdr.pl.AQID~d0~d1~d2~');
  });

  it('out-of-range positive index throws RangeError (Python raises IndexError)', () => {
    expect(() => makeSdJwt().serialize([3])).toThrow(RangeError);
  });

  it('out-of-range negative index throws RangeError', () => {
    expect(() => makeSdJwt().serialize([-4])).toThrow(RangeError);
  });
});

describe('resolveDisclosures — presentation-order resolution (last PRESENTED wins)', () => {
  it('resolves the claim to the last presented disclosure, not the last _sd entry', async () => {
    // dA/dB both disclose claim `vct`. `_sd` lists [hash(dA), hash(dB)] but the
    // disclosures are PRESENTED as [dB, dA]. Python's zip(disclosures, values)
    // loop applies them in presentation order, so dA (last presented) wins → 'AAA'.
    // Resolving by `_sd` order instead would wrongly yield 'BBB'.
    const dA = 'WyJzYWx0LWFhYWEtMTIzNCIsInZjdCIsIkFBQSJd'; // [salt-aaaa-1234, vct, AAA]
    const dB = 'WyJzYWx0LWJiYmItNTY3OCIsInZjdCIsIkJCQiJd'; // [salt-bbbb-5678, vct, BBB]

    const sdJwt = new SdJwt({
      header: {},
      payload: { _sd: [await hashDisclosure(dA), await hashDisclosure(dB)] },
      signature: new Uint8Array(64),
      disclosures: [dB, dA],
      disclosureValues: [decodeDisclosure(dB), decodeDisclosure(dA)] as DecodedDisclosure[],
    });

    expect((await resolveDisclosures(sdJwt)).vct).toBe('AAA');
  });
});

describe('verifySdJwtSignature — Python-number parity', () => {
  // Real Python-signed fixture. Payload holds 1.0, a big int beyond 2^53, and
  // 1e-05 — number spellings that a naive JS re-encode would mangle, causing a
  // false rejection of a valid credential.
  const SERIALIZED =
    'eyJhbGciOiJFUzI1NiIsInR5cCI6InRlc3QifQ.eyJpc3MiOiJ0ZXN0IiwiYW1vdW50IjoxLjAsImJpZyI6OTAwNzE5OTI1NDc0MDk5MywidGlueSI6MWUtMDUsInBsYWluIjoyNzkuOTl9.6amVMsxxixBc_vZJFqqkcbtQqIgs5PCUWxbm_YTfLax6YnhK9JG95DVo25V8Cn3OTdppZs0YVA86tkfKIgQTXg~';
  const PUBLIC_JWK: Es256Jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'PWZ7juBr2AJA-6S76KenML2WIQX3nf9aJ4ArD3eF6cU',
    y: 'a6YQP3NuxdS5WgXDG7kB5zkb6vXKrIGXKPSjHM07kHU',
  };

  it('verifies a valid Python-signed credential with tricky number spellings', async () => {
    const sd = decodeSdJwt(SERIALIZED);
    expect(await verifySdJwtSignature(sd, PUBLIC_JWK)).toBe(true);
  });

  it('rejects a mutated numeric claim (amount → 2)', async () => {
    const sd = decodeSdJwt(SERIALIZED);
    sd.payload.amount = 2;
    expect(await verifySdJwtSignature(sd, PUBLIC_JWK)).toBe(false);
  });

  it('rejects a mutated string claim (iss → evil)', async () => {
    const sd = decodeSdJwt(SERIALIZED);
    sd.payload.iss = 'evil';
    expect(await verifySdJwtSignature(sd, PUBLIC_JWK)).toBe(false);
  });

  it('rejects reordered payload keys (Python dumps preserves insertion order)', async () => {
    const sd = decodeSdJwt(SERIALIZED);
    const { iss, ...rest } = sd.payload;
    sd.payload = { ...rest, iss };
    expect(await verifySdJwtSignature(sd, PUBLIC_JWK)).toBe(false);
  });
});

describe('py-json internals — parsePySegment.pyText matches Python json.dumps', () => {
  // Each pair is [raw JSON segment, Python json.dumps(json.loads(raw),
  // separators=(",",":"))]. All Python-verified.
  const cases: Array<[string, string]> = [
    ['1.0', '1.0'],
    ['1.00', '1.0'],
    ['-0.0', '-0.0'],
    ['1e2', '100.0'],
    ['1e16', '1e+16'],
    ['0.00001', '1e-05'],
    ['1e-4', '0.0001'],
    ['-0', '0'],
    ['9007199254740993', '9007199254740993'],
    ['123456789012345678901234567890', '123456789012345678901234567890'],
    ['5e-324', '5e-324'],
    ['1.7976931348623157e308', '1.7976931348623157e+308'],
    ['279.99', '279.99'],
    // Python ensure_ascii escapes every non-ASCII code point as \uXXXX.
    ['{"s":"literal café 中"}', '{"s":"literal caf\\u00e9 \\u4e2d"}'],
    // JSON duplicate keys: last value wins.
    ['{"dup":1,"dup":2.5}', '{"dup":2.5}'],
  ];

  for (const [raw, expected] of cases) {
    it(`${JSON.stringify(raw)} -> ${JSON.stringify(expected)}`, () => {
      const seg = parsePySegment(raw);
      expect(seg).not.toBeNull();
      expect(seg?.pyText).toBe(expected);
    });
  }
});

describe('py-json internals — pyDeepEqual (Object.is + order-sensitive)', () => {
  it('equal trees compare true', () => {
    expect(pyDeepEqual({ a: 1, b: [2, 3], c: 'x' }, { a: 1, b: [2, 3], c: 'x' })).toBe(true);
  });

  it('-0 vs 0 is FALSE (Object.is semantics)', () => {
    expect(pyDeepEqual(-0, 0)).toBe(false);
  });

  it('reordered object keys are FALSE', () => {
    expect(pyDeepEqual({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(false);
  });

  it('nested value mismatch is FALSE', () => {
    expect(pyDeepEqual({ a: { b: 1 } }, { a: { b: 2 } })).toBe(false);
  });
});
