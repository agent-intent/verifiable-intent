/**
 * Verification conformance: replays the scenarios in
 * ../../test-vectors/vectors.json (verification_conformance) through the
 * TypeScript verifier and asserts the result matches the Python reference.
 *
 * The clock is injected via `currentTime` so the fixed-timestamp vectors
 * verify deterministically.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  checkConstraints,
  decodeSdJwt,
  StrictnessMode,
  type VerifyChainOptions,
  verifyChain,
  verifyCheckoutHashBinding,
  verifyL2ReferenceBinding,
  verifyL3CrossReference,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const V: any = JSON.parse(readFileSync(join(here, '../../test-vectors/vectors.json'), 'utf8'));
const C = V.verification_conformance;

function runScenario(s: any) {
  const opts: VerifyChainOptions = {
    issuerPublicJwk: s.issuer_public ?? undefined,
    skipIssuerVerification: s.skip_issuer_verification,
    l1Serialized: s.l1,
    l2Serialized: s.l2,
    currentTime: s.current_time,
    expectedL2Aud: s.expected_l2_aud ?? undefined,
    expectedL2Nonce: s.expected_l2_nonce ?? undefined,
    expectedL3PaymentAud: s.expected_l3_payment_aud ?? undefined,
    expectedL3PaymentNonce: s.expected_l3_payment_nonce ?? undefined,
    expectedL3CheckoutAud: s.expected_l3_checkout_aud ?? undefined,
    expectedL3CheckoutNonce: s.expected_l3_checkout_nonce ?? undefined,
  };
  if (s.l3_payment || s.l3_checkout) {
    opts.splitL3s = [
      {
        l3Payment: s.l3_payment ? decodeSdJwt(s.l3_payment) : null,
        l3Checkout: s.l3_checkout ? decodeSdJwt(s.l3_checkout) : null,
        l2PaymentSerialized: s.l2_payment_serialized ?? null,
        l2CheckoutSerialized: s.l2_checkout_serialized ?? null,
      },
    ];
  }
  return verifyChain(decodeSdJwt(s.l1), decodeSdJwt(s.l2), opts);
}

describe('verification: chain scenarios (TS verdict matches Python)', () => {
  for (const s of C.chain_scenarios) {
    it(`${s.name} → valid=${s.expected_valid}`, async () => {
      const res = await runScenario(s);
      expect(res.valid).toBe(s.expected_valid);
      // Exact, order-sensitive error parity with the Python reference. A
      // rejection with the *wrong* error would mean the intended guard failed
      // open and something else coincidentally rejected — that must fail here,
      // not pass. If a string diverges, fix src to match Python; never weaken
      // this assertion.
      expect(res.errors).toEqual(s.expected_errors);
    });
  }

  it('a valid autonomous chain exposes one verified mandate pair', async () => {
    const s = C.chain_scenarios.find((x: any) => x.name === 'autonomous_valid');
    const res = await runScenario(s);
    expect(res.valid).toBe(true);
    expect(res.mandatePairCount).toBe(1);
    expect(res.pairResults.length).toBe(1);
    expect(res.l2PaymentDisclosed).toBe(true);
    expect(res.l2CheckoutDisclosed).toBe(true);
  });
});

describe('verification: constraint checker (counts match Python)', () => {
  for (const c of C.constraint_cases) {
    it(c.name, () => {
      const res = checkConstraints(c.constraints, c.fulfillment, {
        mode: c.mode === 'strict' ? StrictnessMode.STRICT : StrictnessMode.PERMISSIVE,
        isOpenMandate: c.is_open_mandate,
      });
      expect(res.satisfied).toBe(c.expected.satisfied);
      expect(res.violations.length).toBe(c.expected.violations);
      expect(res.checked.length).toBe(c.expected.checked);
      expect(res.skipped.length).toBe(c.expected.skipped);
    });
  }
});

describe('verification: integrity', () => {
  for (const c of C.integrity_cases) {
    it(c.name, async () => {
      let valid: boolean;
      if (c.kind === 'checkout_hash') {
        valid = (await verifyCheckoutHashBinding(c.checkout_mandate, c.payment_mandate)).valid;
      } else if (c.kind === 'l2_ref') {
        valid = (await verifyL2ReferenceBinding({}, c.payment_mandate, c.checkout_disclosure)).valid;
      } else {
        valid = verifyL3CrossReference(c.l3_payment_claims, c.l3_checkout_claims).valid;
      }
      expect(valid).toBe(c.expected_valid);
    });
  }
});
