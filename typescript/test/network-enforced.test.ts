/**
 * `ChainVerificationResult.networkEnforced` surfacing.
 *
 * The spec assigns `mandate.payment.budget` / `.recurrence` / `.agent_recurrence`
 * to the payment NETWORK (they are stateful), so the stateless verifier parses
 * but never evaluates them — the constraint checker only records them in
 * `checked[]`. `verifyChain` additionally surfaces them on the result so the
 * caller knows what it still must enforce. These tests pin that surfacing:
 * additive only — verdicts, errors, and all other result fields are unchanged.
 */

import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  AllowedPayeeConstraint,
  CheckoutLineItemsConstraint,
  CheckoutMandate,
  createLayer1,
  createLayer2Autonomous,
  createLayer2Immediate,
  generateEs256Key,
  hashAscii,
  IssuerCredential,
  type JsonObject,
  jwtEncode,
  makeSigner,
  MandateMode,
  PaymentBudgetConstraint,
  PaymentMandate,
  PaymentRecurrenceConstraint,
  UserMandate,
  verifyChain,
} from '../src/index.js';

const TENNIS_WAREHOUSE = { id: 'merchant-uuid-1', name: 'Tennis Warehouse', website: 'https://tennis-warehouse.com' };

const PAYMENT_INSTRUMENT = {
  type: 'mastercard.srcDigitalCard',
  id: 'f199c3dd-7106-478b-9b5f-7af9ca725170',
  description: 'Mastercard **** 1234',
};

const L2_AUD = 'https://agent.verifiable-intent.example';

async function makeCheckoutJwt(merchantPrivateJwk: Parameters<typeof makeSigner>[0], now: number): Promise<string> {
  const signer = await makeSigner(merchantPrivateJwk);
  const payload = {
    iss: 'https://tennis-warehouse.com',
    sub: 'cart_checkout',
    iat: now,
    exp: now + 3600,
    cart: { items: [{ sku: 'BAB86345', quantity: 1 }], subTotal: { amount: 279.99, currencyCode: 'USD' } },
  };
  return jwtEncode({ alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' }, payload, signer);
}

async function makeL1(issuer: Awaited<ReturnType<typeof generateEs256Key>>, userCnfJwk: JsonObject, now: number) {
  const cred = new IssuerCredential({
    iss: 'https://www.mastercard.com',
    sub: 'user-alice-001',
    iat: now,
    exp: now + 86400,
    aud: 'https://wallet.example.com',
    cnfJwk: userCnfJwk,
    email: 'alice@example.com',
    panLastFour: '1234',
    scheme: 'Mastercard',
  });
  return createLayer1(cred, issuer.privateKey);
}

describe('networkEnforced surfacing', () => {
  it('surfaces budget/recurrence constraints from an autonomous open payment mandate', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issuer = await generateEs256Key();
    const user = await generateEs256Key();
    const agent = await generateEs256Key();

    const l1 = await makeL1(issuer, user.publicKey, now);

    const l2Nonce = randomUUID();
    const mandate = new UserMandate({
      nonce: l2Nonce,
      aud: L2_AUD,
      iat: now,
      iss: 'https://wallet.example.com',
      exp: now + 86400,
      mode: MandateMode.AUTONOMOUS,
      sdHash: await hashAscii(l1.serialize()),
      promptSummary: 'Buy tennis gear, $400/month budget',
      checkoutMandate: new CheckoutMandate({
        vct: 'mandate.checkout.open.1',
        cnfJwk: agent.publicKey,
        cnfKid: 'agent-key-1',
        constraints: [new CheckoutLineItemsConstraint({ items: [] })],
      }),
      paymentMandate: new PaymentMandate({
        vct: 'mandate.payment.open.1',
        cnfJwk: agent.publicKey,
        cnfKid: 'agent-key-1',
        paymentInstrument: PAYMENT_INSTRUMENT,
        constraints: [
          new AllowedPayeeConstraint({ allowed: [TENNIS_WAREHOUSE] }),
          new PaymentBudgetConstraint({ currency: 'USD', max: 40000 }),
          new PaymentRecurrenceConstraint({ frequency: 'monthly', startDate: '2026-01-01' }),
        ],
      }),
      merchants: [TENNIS_WAREHOUSE],
      acceptableItems: [],
    });
    const l2 = await createLayer2Autonomous(mandate, user.privateKey);

    const res = await verifyChain(l1, l2, {
      issuerPublicJwk: issuer.publicKey,
      l1Serialized: l1.serialize(),
      expectedL2Aud: L2_AUD,
      expectedL2Nonce: l2Nonce,
    });

    // The network-enforced constraints do not affect the stateless verdict.
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);

    // Exactly the budget and recurrence constraints are surfaced — the
    // verifier-enforced allowed_payees and the auto-injected reference are not.
    expect(res.networkEnforced.length).toBe(2);

    const budget = res.networkEnforced.find((c) => c.type === 'mandate.payment.budget');
    expect(budget).toBeDefined();
    expect(budget?.pairIndex).toBe(0);
    expect(budget?.constraint).toEqual({ type: 'mandate.payment.budget', currency: 'USD', max: 40000 });

    const recurrence = res.networkEnforced.find((c) => c.type === 'mandate.payment.recurrence');
    expect(recurrence).toBeDefined();
    expect(recurrence?.pairIndex).toBe(0);
    expect(recurrence?.constraint).toEqual({
      type: 'mandate.payment.recurrence',
      frequency: 'monthly',
      start_date: '2026-01-01',
    });
  });

  it('is an empty array for an immediate chain', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issuer = await generateEs256Key();
    const user = await generateEs256Key();
    const merchant = await generateEs256Key();

    const l1 = await makeL1(issuer, user.publicKey, now);

    const checkoutJwt = await makeCheckoutJwt(merchant.privateKey, now);
    const l2Nonce = randomUUID();
    const mandate = new UserMandate({
      nonce: l2Nonce,
      aud: L2_AUD,
      iat: now,
      iss: 'https://wallet.example.com',
      exp: now + 900,
      mode: MandateMode.IMMEDIATE,
      sdHash: await hashAscii(l1.serialize()),
      promptSummary: 'Purchase Babolat Pure Aero racket',
      checkoutMandate: new CheckoutMandate({ vct: 'mandate.checkout.1', checkoutJwt }),
      paymentMandate: new PaymentMandate({
        vct: 'mandate.payment.1',
        paymentInstrument: PAYMENT_INSTRUMENT,
        payee: TENNIS_WAREHOUSE,
        currency: 'USD',
        amount: 27999,
      }),
    });
    const l2 = await createLayer2Immediate(mandate, user.privateKey);

    const res = await verifyChain(l1, l2.sdJwt, {
      issuerPublicJwk: issuer.publicKey,
      l1Serialized: l1.serialize(),
      expectedL2Aud: L2_AUD,
      expectedL2Nonce: l2Nonce,
    });

    expect(res.valid).toBe(true);
    expect(res.networkEnforced).toEqual([]);
  });
});
