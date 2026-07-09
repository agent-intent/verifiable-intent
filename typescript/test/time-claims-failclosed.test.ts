/**
 * Fail-closed regression tests for the malformed time-claim guards
 * (`isExpired` / `isFutureDated` in src/verification/chain.ts).
 *
 * These two helpers implement a security-critical rule: a malformed `exp` is
 * treated as EXPIRED and a malformed `iat` is treated as FUTURE-DATED, so the
 * credential is REJECTED. The dangerous refactor this file guards against is one
 * that turns "malformed exp → reject" into "malformed exp → skip the check",
 * which would fail OPEN. The golden conformance vectors never carry a malformed
 * time claim, so without these tests that regression would ship silently.
 *
 * Two harnesses, mirroring the Python reference tests in
 * python/tests/test_verification_hardening.py:
 *
 *   L1: the `exp`/`iat` checks run BEFORE the L2 signature and sd_hash-binding
 *       steps, so we take the golden `immediate_valid` L1, mutate the decoded
 *       payload in memory, skip issuer verification, and pin `l1Serialized` to
 *       the original bytes so the (unmutated) L2 binding still holds. A reject
 *       returns at the time check; the accept path exercises the whole chain.
 *
 *   L2/L3: their signatures are ALWAYS verified, so an in-memory mutation would
 *       fail the signature check first and never reach the time guard. Instead
 *       we RE-SIGN the layer (exactly as the Python tests do with create_sd_jwt)
 *       using the standard user/agent private keys the golden vectors were signed
 *       with — the golden L1's cnf.jwk is the standard user key, and the L2
 *       mandate cnf.jwk is the standard agent key — so a re-signed layer still
 *       verifies against the rest of the golden chain.
 *
 * Where JS `String(value)` renders a mutated claim identically to Python's
 * `str(value)` (plain strings, integers) we assert the FULL error byte-for-byte.
 * For values whose textual form is language-specific (`true`→`True`, `NaN`→`nan`,
 * `{}`→`[object Object]`, `Infinity`→a huge int) only the rendered value differs;
 * the accept/reject DECISION is identical, so we assert the byte-identical error
 * prefix plus `valid === false`. None of these is a behavioral divergence.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createSdJwt, decodeSdJwt, type Es256Jwk, type SdJwt, type VerifyChainOptions, verifyChain } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const V: any = JSON.parse(readFileSync(join(here, '../../test-vectors/vectors.json'), 'utf8'));
const C = V.verification_conformance;

const IMM = C.chain_scenarios.find((s: any) => s.name === 'immediate_valid');
const AUTO = C.chain_scenarios.find((s: any) => s.name === 'autonomous_valid');

/** The golden chains were signed with these standard keys (verified: L1 cnf.jwk == user pub). */
const USER_PRIV = V.keys.user.private as Es256Jwk;
const AGENT_PRIV = V.keys.agent.private as Es256Jwk;

/** Default clock skew used by verifyChain when `clockSkewSeconds` is unset. */
const SKEW = 300;

type Payload = Record<string, unknown>;
type Mutate = (payload: Payload) => void;

// --- L1 harness: in-memory mutation, issuer sig skipped, L1 serialization pinned. ---

const freshImmL1 = () => decodeSdJwt(IMM.l1);
const freshImmL2 = () => decodeSdJwt(IMM.l2);

/** Pinning `l1Serialized` keeps the L2→L1 sd_hash binding valid while we mutate L1's decoded payload. */
const immOpts = (): VerifyChainOptions => ({
  skipIssuerVerification: true,
  currentTime: IMM.current_time,
  l1Serialized: IMM.l1,
});

/** Decode the golden immediate L2, mutate its payload, and re-sign with the user key. */
async function resignImmL2(mutate: Mutate): Promise<SdJwt> {
  const l2 = decodeSdJwt(IMM.l2);
  const payload: Payload = { ...l2.payload };
  mutate(payload);
  return createSdJwt({ ...l2.header }, payload, [...l2.disclosures], USER_PRIV);
}

// --- L3 harness: re-sign the autonomous L3a (payment) with the agent key. ---

function autoOpts(l3Payment: SdJwt | null, l3Checkout: SdJwt | null): VerifyChainOptions {
  return {
    skipIssuerVerification: true,
    currentTime: AUTO.current_time,
    l1Serialized: AUTO.l1,
    l2Serialized: AUTO.l2,
    splitL3s: [
      {
        l3Payment,
        l3Checkout,
        l2PaymentSerialized: AUTO.l2_payment_serialized ?? null,
        l2CheckoutSerialized: AUTO.l2_checkout_serialized ?? null,
      },
    ],
  };
}

async function resignAutoL3Payment(mutate: Mutate): Promise<SdJwt> {
  const l3 = decodeSdJwt(AUTO.l3_payment);
  const payload: Payload = { ...l3.payload };
  mutate(payload);
  return createSdJwt({ ...l3.header }, payload, [...l3.disclosures], AGENT_PRIV);
}

const freshAutoL3Checkout = () => decodeSdJwt(AUTO.l3_checkout);

describe('fail-closed: malformed time claims (isExpired / isFutureDated)', () => {
  it('baseline: unmutated immediate chain is valid (anchors the L1 harness)', async () => {
    const res = await verifyChain(freshImmL1(), freshImmL2(), immOpts());
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });

  it('baseline: unmutated autonomous chain is valid (anchors the L3 harness)', async () => {
    const res = await verifyChain(
      decodeSdJwt(AUTO.l1),
      decodeSdJwt(AUTO.l2),
      autoOpts(decodeSdJwt(AUTO.l3_payment), freshAutoL3Checkout()),
    );
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });

  // --- L1 exp: every malformed exp is treated as expired → reject. ---

  describe('L1 exp malformed → treated as expired', () => {
    it('rejects a non-numeric string exp (byte-exact) [test_non_numeric_exp_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = 'never';
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L1 credential expired at never');
    });

    it('rejects a numeric-looking string exp (byte-exact)', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = '123';
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L1 credential expired at 123');
    });

    it('rejects an object exp [test_dict_exp_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = { value: 9999999999 };
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      // JS renders the object as "[object Object]" vs Python "{'value': 9999999999}"; only the prefix is portable.
      expect(res.errors.some((e) => e.startsWith('L1 credential expired at '))).toBe(true);
    });

    it('rejects an empty-object exp', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = {};
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential expired at '))).toBe(true);
    });

    it('rejects a NaN exp [test_nan_exp_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = NaN;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential expired at '))).toBe(true);
    });

    it('rejects exp=true [test_l1_exp_bool_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = true;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential expired at '))).toBe(true);
    });

    it('rejects exp=false (a boolean is not a valid timestamp, regardless of value)', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = false;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential expired at '))).toBe(true);
    });

    it('treats exp=0 as expired at the epoch, not as absent (byte-exact) [test_l1_exp_zero_treated_as_expired]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).exp = 0;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L1 credential expired at 0');
    });
  });

  // --- L1 iat: every malformed iat is treated as future-dated → reject. ---

  describe('L1 iat malformed → treated as future-dated', () => {
    it('rejects a non-numeric string iat (byte-exact) [test_l1_iat_string_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = 'tomorrow';
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L1 credential iat is in the future: tomorrow');
    });

    it('rejects a numeric-looking string iat (byte-exact)', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = '123';
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L1 credential iat is in the future: 123');
    });

    it('rejects iat=true [test_l1_iat_bool_rejected]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = true;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential iat is in the future: '))).toBe(true);
    });

    it('rejects iat=false', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = false;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential iat is in the future: '))).toBe(true);
    });

    it('rejects a NaN iat', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = NaN;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential iat is in the future: '))).toBe(true);
    });

    it('rejects an object iat', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = {};
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential iat is in the future: '))).toBe(true);
    });

    it('rejects a huge iat without overflow (1e309 → Infinity) [test_l1_iat_huge_integer_rejected_without_overflow]', async () => {
      const l1 = freshImmL1();
      // A JSON number like 1e309 parses to Infinity in JS (and to inf in Python); the
      // non-finite guard rejects it. Python's synthetic 10**400 also rejects (> now).
      (l1.payload as Payload).iat = Infinity;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L1 credential iat is in the future: '))).toBe(true);
    });
  });

  // --- L1 clock-skew boundary: at the boundary accept, one second past reject. ---

  describe('L1 iat clock-skew boundary', () => {
    it('accepts iat exactly at now + skew [test_l1_iat_at_skew_boundary_accepted]', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = IMM.current_time + SKEW;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(true);
      expect(res.errors).toEqual([]);
    });

    it('rejects iat one second past the skew boundary (guards an off-by-one fail-open)', async () => {
      const l1 = freshImmL1();
      (l1.payload as Payload).iat = IMM.current_time + SKEW + 1;
      const res = await verifyChain(l1, freshImmL2(), immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain(`L1 credential iat is in the future: ${IMM.current_time + SKEW + 1}`);
    });
  });

  // --- L2 (top-level) exp/iat via re-signed immediate L2. ---

  describe('L2 exp malformed → treated as expired', () => {
    it('rejects a string exp (byte-exact)', async () => {
      const l2 = await resignImmL2((p) => { p.exp = 'never'; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L2 expired at never');
    });

    it('rejects exp=true', async () => {
      const l2 = await resignImmL2((p) => { p.exp = true; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L2 expired at '))).toBe(true);
    });

    it('rejects an object exp', async () => {
      const l2 = await resignImmL2((p) => { p.exp = {}; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L2 expired at '))).toBe(true);
    });

    it('treats exp=0 as expired (byte-exact)', async () => {
      const l2 = await resignImmL2((p) => { p.exp = 0; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L2 expired at 0');
    });
  });

  describe('L2 iat malformed → treated as future-dated', () => {
    it('rejects a string iat (byte-exact)', async () => {
      const l2 = await resignImmL2((p) => { p.iat = 'later'; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L2 iat is in the future: later');
    });

    it('rejects iat=false', async () => {
      const l2 = await resignImmL2((p) => { p.iat = false; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.startsWith('L2 iat is in the future: '))).toBe(true);
    });

    // Note: NaN / Infinity are intentionally NOT tested at L2/L3. The signer
    // (compactJson) refuses to serialize non-finite numbers, and JSON.parse has
    // no NaN/Infinity literal, so a validly-signed L2/L3 carrying one is
    // unconstructible — the credential fails closed at issuance/parse instead of
    // at the time guard. The non-finite branch of the guard is exercised at L1.
  });

  describe('L2 clock-skew boundary and absent exp', () => {
    it('accepts top-level iat exactly at now + skew [test_l2_top_level_iat_at_skew_boundary_accepted]', async () => {
      const l2 = await resignImmL2((p) => { p.iat = IMM.current_time + SKEW; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(true);
      expect(res.errors).toEqual([]);
    });

    it('accepts an absent exp (backward compat) [test_l2_l3_exp_absent_passes]', async () => {
      const l2 = await resignImmL2((p) => { delete p.exp; });
      const res = await verifyChain(freshImmL1(), l2, immOpts());
      expect(res.valid).toBe(true);
      expect(res.errors.some((e) => e.toLowerCase().includes('expired'))).toBe(false);
    });
  });

  // --- L3a (payment) exp/iat via re-signed autonomous L3. ---

  describe('L3 exp/iat malformed → rejected', () => {
    it('rejects a string exp (byte-exact)', async () => {
      const l3 = await resignAutoL3Payment((p) => { p.exp = 'never'; });
      const res = await verifyChain(decodeSdJwt(AUTO.l1), decodeSdJwt(AUTO.l2), autoOpts(l3, freshAutoL3Checkout()));
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L3a (payment) expired at never');
    });

    it('rejects a string iat (byte-exact)', async () => {
      const l3 = await resignAutoL3Payment((p) => { p.iat = 'soon'; });
      const res = await verifyChain(decodeSdJwt(AUTO.l1), decodeSdJwt(AUTO.l2), autoOpts(l3, freshAutoL3Checkout()));
      expect(res.valid).toBe(false);
      expect(res.errors).toContain('L3a (payment) iat is in the future: soon');
    });
  });

  describe('L3 clock-skew boundary and absent exp', () => {
    it('accepts top-level iat exactly at now + skew [test_l3_top_level_iat_at_skew_boundary_accepted]', async () => {
      const l3 = await resignAutoL3Payment((p) => { p.iat = AUTO.current_time + SKEW; });
      const res = await verifyChain(decodeSdJwt(AUTO.l1), decodeSdJwt(AUTO.l2), autoOpts(l3, freshAutoL3Checkout()));
      expect(res.valid).toBe(true);
      expect(res.errors).toEqual([]);
    });

    it('accepts an absent exp (backward compat) [test_l2_l3_exp_absent_passes]', async () => {
      const l3 = await resignAutoL3Payment((p) => { delete p.exp; });
      const res = await verifyChain(decodeSdJwt(AUTO.l1), decodeSdJwt(AUTO.l2), autoOpts(l3, freshAutoL3Checkout()));
      expect(res.valid).toBe(true);
      expect(res.errors.some((e) => e.toLowerCase().includes('expired'))).toBe(false);
    });
  });
});
