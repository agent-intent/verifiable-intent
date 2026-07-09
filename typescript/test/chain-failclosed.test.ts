/**
 * Fail-closed regression tests for L1 header/claim validation in verifyChain.
 *
 * The chain verifier enforces several spec-mandated, security-critical rules at
 * Layer 1 that are NOT exercised by the golden conformance vectors:
 *   - algorithm confusion  (alg MUST be ES256)
 *   - type confusion       (typ MUST be 'sd+jwt')
 *   - credential-type lock  (vct MUST be the expected issuer VCT)
 *   - hash-algorithm lock   (_sd_alg, when present, MUST be 'sha-256')
 *
 * Each rule is checked BEFORE the L2 signature step, so we take the known-valid
 * `immediate_valid` golden chain, skip issuer signature verification, and apply a
 * single in-memory mutation to the decoded L1. A regression that turned any of
 * these guards into a fail-OPEN would flip one of these expectations to valid.
 *
 * These inputs are non-conformant by construction; a well-formed signed chain is
 * unaffected (see the baseline test).
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { decodeSdJwt, type Es256Jwk, verifySdJwtSignature, type VerifyChainOptions, verifyChain } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const V: any = JSON.parse(readFileSync(join(here, '../../test-vectors/vectors.json'), 'utf8'));
const SCENARIO = V.verification_conformance.chain_scenarios.find((s: any) => s.name === 'immediate_valid');

/** Fresh decode each call so per-test mutations never leak between cases. */
const freshL1 = () => decodeSdJwt(SCENARIO.l1);
const freshL2 = () => decodeSdJwt(SCENARIO.l2);

/** Skip only the issuer signature so L1 header/claim checks run against our mutation. */
const opts = (): VerifyChainOptions => ({ skipIssuerVerification: true, currentTime: SCENARIO.current_time });

describe('fail-closed: L1 header/claim validation (uncovered by golden vectors)', () => {
  it('baseline: the unmutated immediate chain is valid when issuer sig is skipped', async () => {
    const res = await verifyChain(freshL1(), freshL2(), opts());
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });

  it('rejects algorithm confusion (alg=HS256, not ES256)', async () => {
    const l1 = freshL1();
    (l1.header as Record<string, unknown>).alg = 'HS256';
    const res = await verifyChain(l1, freshL2(), opts());
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => /alg must be one of/i.test(e))).toBe(true);
  });

  it('rejects algorithm stripping (alg=none)', async () => {
    const l1 = freshL1();
    (l1.header as Record<string, unknown>).alg = 'none';
    const res = await verifyChain(l1, freshL2(), opts());
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => /alg must be one of/i.test(e))).toBe(true);
  });

  it("rejects type confusion (typ != 'sd+jwt')", async () => {
    const l1 = freshL1();
    (l1.header as Record<string, unknown>).typ = 'jwt';
    const res = await verifyChain(l1, freshL2(), opts());
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => /header typ must be/i.test(e))).toBe(true);
  });

  it('rejects an unexpected credential type (vct mismatch)', async () => {
    const l1 = freshL1();
    (l1.payload as Record<string, unknown>).vct = 'https://evil.example.com/card';
    const res = await verifyChain(l1, freshL2(), opts());
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => /vct must be/i.test(e))).toBe(true);
  });

  it("rejects a non-sha-256 hash algorithm (_sd_alg='sha-512')", async () => {
    const l1 = freshL1();
    (l1.payload as Record<string, unknown>)._sd_alg = 'sha-512';
    const res = await verifyChain(l1, freshL2(), opts());
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => /_sd_alg must be 'sha-256'/i.test(e))).toBe(true);
  });
});

describe('fail-closed: verifySdJwtSignature returns false (never throws) on a hostile public key', () => {
  it('resolves to false for a non-importable JWK instead of rejecting', async () => {
    const sj = freshL1();
    // x/y are not valid base64url EC coordinates → WebCrypto importKey rejects.
    const badJwk = { kty: 'EC', crv: 'P-256', x: '!!!not-base64!!!', y: '!!!not-base64!!!' } as Es256Jwk;
    await expect(verifySdJwtSignature(sj, badJwk)).resolves.toBe(false);
  });
});
