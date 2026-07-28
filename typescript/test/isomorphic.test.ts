/**
 * Browser-readiness proof: the whole issue → verify pipeline must run with no
 * Node-only globals. `globalThis.Buffer` is deleted for the duration of the
 * test (and restored afterwards) so any accidental Buffer dependency in the
 * library would throw here. The package now relies only on Web-standard
 * globals — `crypto.subtle`, `crypto.getRandomValues`, `TextEncoder`,
 * `TextDecoder` — which exist in Node >= 20 and modern browsers alike.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createLayer1,
  decodeSdJwt,
  generateEs256Key,
  hashAscii,
  IssuerCredential,
  resolveDisclosures,
  verifySdJwtSignature,
} from '../src/index.js';

const g = globalThis as { Buffer?: unknown };

describe('isomorphic runtime (no Node Buffer global)', () => {
  let savedBuffer: unknown;

  beforeEach(() => {
    savedBuffer = g.Buffer;
    delete g.Buffer;
  });

  afterEach(() => {
    g.Buffer = savedBuffer;
  });

  it('issues and verifies an L1 credential with Buffer undefined', async () => {
    expect(g.Buffer).toBeUndefined();

    const now = Math.floor(Date.now() / 1000);
    const issuer = await generateEs256Key();
    const user = await generateEs256Key();

    const l1 = await createLayer1(
      new IssuerCredential({
        iss: 'https://www.mastercard.com',
        sub: 'user-123',
        iat: now,
        exp: now + 3600,
        cnfJwk: user.publicKey,
        email: 'user@example.com',
        panLastFour: '1234',
        scheme: 'Mastercard',
      }),
      issuer.privateKey,
    );

    const parsed = decodeSdJwt(l1.serialize());
    expect(await verifySdJwtSignature(parsed, issuer.publicKey)).toBe(true);

    const resolved = await resolveDisclosures(parsed);
    expect(resolved.email).toBe('user@example.com');

    // Hashing path (sd_hash / checkout_hash primitive) works without Buffer too.
    expect(await hashAscii(l1.serialize())).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
