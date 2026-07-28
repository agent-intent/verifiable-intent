/**
 * End-to-end TS-issue → TS-verify round trips using DEFAULT issuance options.
 *
 * Every other suite either byte-compares TS issuance against Python golden
 * vectors (injecting fixed salts + clock) or replays Python-signed vectors
 * through the TS verifier. None of them ever runs a credential the TypeScript
 * SDK ISSUED (with real random salts and the real wall clock) back through
 * `verifyChain`. This suite closes that gap: it builds full immediate and
 * autonomous chains with the default `generateSalt` / `Date.now()` paths and
 * asserts the TS verifier accepts its own issuance — plus negative controls and
 * a constraint check against the actually-issued open mandate.
 *
 * Determinism note: no salts or clock are injected on purpose (the point is to
 * exercise the default code paths). Outcomes stay deterministic anyway — a valid
 * chain is valid regardless of which random salts were drawn — so no assertion
 * depends on signature or disclosure bytes.
 */

import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  AllowedMerchantConstraint,
  AllowedPayeeConstraint,
  buildSelectivePresentation,
  checkConstraints,
  CheckoutL3Mandate,
  CheckoutLineItemsConstraint,
  CheckoutMandate,
  createLayer1,
  createLayer2Autonomous,
  createLayer2Immediate,
  createLayer3Checkout,
  createLayer3Payment,
  decodeSdJwt,
  FinalCheckoutMandate,
  FinalPaymentMandate,
  generateEs256Key,
  hashAscii,
  hashDisclosure,
  IssuerCredential,
  jwtEncode,
  makeSigner,
  MandateMode,
  PaymentAmountConstraint,
  PaymentL3Mandate,
  PaymentMandate,
  resolveDisclosures,
  type SdJwt,
  UserMandate,
  verifyChain,
  type VerifyChainOptions,
} from '../src/index.js';

// ---------------------------------------------------------------------------
// Scenario fixtures (mirrors python/examples/helpers.py)
// ---------------------------------------------------------------------------

const TENNIS_WAREHOUSE = { id: 'merchant-uuid-1', name: 'Tennis Warehouse', website: 'https://tennis-warehouse.com' };
const BABOLAT = { id: 'merchant-uuid-2', name: 'Babolat', website: 'https://babolat.com' };
const MERCHANTS = [TENNIS_WAREHOUSE, BABOLAT];

const ACCEPTABLE_ITEMS = [
  { id: 'BAB86345', title: 'Babolat Pure Aero Tennis Racket' },
  { id: 'HEA23102', title: 'Head Graphene 360 Speed' },
];

const PAYMENT_INSTRUMENT = {
  type: 'mastercard.srcDigitalCard',
  id: 'f199c3dd-7106-478b-9b5f-7af9ca725170',
  description: 'Mastercard **** 1234',
};

const L2_AUD = 'https://agent.verifiable-intent.example';
const L3_PAYMENT_AUD = 'https://www.mastercard.com';
const L3_CHECKOUT_AUD = 'https://tennis-warehouse.com';

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Find a disclosure string in an SdJwt whose resolved value matches a predicate. */
function findDisclosure(sj: SdJwt, predicate: (value: unknown) => boolean): string {
  for (let i = 0; i < sj.disclosures.length; i++) {
    const dv = sj.disclosureValues[i];
    const value = dv && dv.length ? dv[dv.length - 1] : null;
    if (predicate(value)) {
      const disc = sj.disclosures[i];
      if (disc !== undefined) return disc;
    }
  }
  throw new Error('disclosure not found for predicate');
}

/** A merchant-signed checkout JWT. Its signature is never verified by the chain
 * (only hashed into checkout_hash), so any real signed JWT works. */
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

// ---------------------------------------------------------------------------
// Chain builders — DEFAULT issuance options (random salts, real clock)
// ---------------------------------------------------------------------------

interface ImmediateChain {
  issuer: Awaited<ReturnType<typeof generateEs256Key>>;
  l1: SdJwt;
  l2: SdJwt;
  l2Nonce: string;
}

async function buildImmediateChain(): Promise<ImmediateChain> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = await generateEs256Key();
  const user = await generateEs256Key();
  const merchant = await generateEs256Key();

  const cred = new IssuerCredential({
    iss: 'https://www.mastercard.com',
    sub: 'user-bob-001',
    iat: now,
    exp: now + 86400,
    aud: 'https://wallet.example.com',
    cnfJwk: user.publicKey,
    email: 'bob@example.com',
    panLastFour: '5678',
    scheme: 'Mastercard',
  });
  const l1 = await createLayer1(cred, issuer.privateKey);

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
    // Final values; no cnf, no delegation. checkout_hash + transaction_id are
    // auto-computed from checkout_jwt by createLayer2Immediate (default path).
    checkoutMandate: new CheckoutMandate({ vct: 'mandate.checkout.1', checkoutJwt }),
    paymentMandate: new PaymentMandate({
      vct: 'mandate.payment.1',
      paymentInstrument: PAYMENT_INSTRUMENT,
      payee: TENNIS_WAREHOUSE,
      currency: 'USD',
      amount: 27999,
    }),
  });
  const result = await createLayer2Immediate(mandate, user.privateKey);
  return { issuer, l1, l2: result.sdJwt, l2Nonce };
}

interface AutonomousChain {
  issuer: Awaited<ReturnType<typeof generateEs256Key>>;
  l1: SdJwt;
  l2: SdJwt;
  l2Ser: string;
  l3a: SdJwt;
  l3b: SdJwt;
  l2PaymentSer: string;
  l2CheckoutSer: string;
  l2Nonce: string;
  l3Nonce: string;
}

async function buildAutonomousChain(): Promise<AutonomousChain> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = await generateEs256Key();
  const user = await generateEs256Key();
  const agent = await generateEs256Key();
  const merchant = await generateEs256Key();

  const cred = new IssuerCredential({
    iss: 'https://www.mastercard.com',
    sub: 'user-alice-001',
    iat: now,
    exp: now + 86400,
    aud: 'https://wallet.example.com',
    cnfJwk: user.publicKey,
    email: 'alice@example.com',
    panLastFour: '1234',
    scheme: 'Mastercard',
  });
  const l1 = await createLayer1(cred, issuer.privateKey);

  const l2Nonce = randomUUID();
  const mandate = new UserMandate({
    nonce: l2Nonce,
    aud: L2_AUD,
    iat: now,
    iss: 'https://wallet.example.com',
    exp: now + 86400,
    mode: MandateMode.AUTONOMOUS,
    sdHash: await hashAscii(l1.serialize()),
    promptSummary: 'Buy a Babolat tennis racket under $400',
    checkoutMandate: new CheckoutMandate({
      vct: 'mandate.checkout.open.1',
      cnfJwk: agent.publicKey,
      cnfKid: 'agent-key-1',
      constraints: [
        new AllowedMerchantConstraint({ allowed: MERCHANTS }),
        new CheckoutLineItemsConstraint({
          items: [{ id: 'line-item-1', acceptable_items: ACCEPTABLE_ITEMS, quantity: 1 }],
        }),
      ],
    }),
    paymentMandate: new PaymentMandate({
      vct: 'mandate.payment.open.1',
      cnfJwk: agent.publicKey,
      cnfKid: 'agent-key-1',
      paymentInstrument: PAYMENT_INSTRUMENT,
      constraints: [
        new AllowedPayeeConstraint({ allowed: [TENNIS_WAREHOUSE] }),
        new PaymentAmountConstraint({ currency: 'USD', min: 10000, max: 40000 }),
      ],
    }),
    merchants: MERCHANTS,
    acceptableItems: ACCEPTABLE_ITEMS,
  });
  const l2 = await createLayer2Autonomous(mandate, user.privateKey);
  const l2Ser = l2.serialize();
  const l2BaseJwt = l2Ser.split('~')[0] ?? '';

  const paymentDisc = findDisclosure(l2, (v) => isObj(v) && v.vct === 'mandate.payment.open.1');
  const checkoutDisc = findDisclosure(l2, (v) => isObj(v) && v.vct === 'mandate.checkout.open.1');
  const merchantDisc = findDisclosure(l2, (v) => isObj(v) && v.name === 'Tennis Warehouse');
  const itemDisc = findDisclosure(l2, (v) => isObj(v) && v.id === 'BAB86345');

  const checkoutJwt = await makeCheckoutJwt(merchant.privateKey, now);
  const cHash = await hashAscii(checkoutJwt);
  const l3Nonce = randomUUID();

  // L3a: payment fulfillment for the network.
  const l3a = await createLayer3Payment(
    new PaymentL3Mandate({
      nonce: l3Nonce,
      aud: L3_PAYMENT_AUD,
      iat: now,
      iss: 'https://agent.example.com',
      exp: now + 300,
      finalPayment: new FinalPaymentMandate({
        transactionId: cHash,
        payee: TENNIS_WAREHOUSE,
        paymentAmount: { currency: 'USD', amount: 27999 },
        paymentInstrument: PAYMENT_INSTRUMENT,
      }),
      finalMerchant: TENNIS_WAREHOUSE,
    }),
    agent.privateKey,
    { l2BaseJwt, paymentDisclosure: paymentDisc, merchantDisclosure: merchantDisc },
  );

  // L3b: checkout fulfillment for the merchant.
  const l3b = await createLayer3Checkout(
    new CheckoutL3Mandate({
      nonce: l3Nonce,
      aud: L3_CHECKOUT_AUD,
      iat: now,
      iss: 'https://agent.example.com',
      exp: now + 300,
      finalCheckout: new FinalCheckoutMandate({ checkoutJwt, checkoutHash: cHash }),
    }),
    agent.privateKey,
    { l2BaseJwt, checkoutDisclosure: checkoutDisc, itemDisclosure: itemDisc },
  );

  // Role-specific L2 presentations each L3 binds its sd_hash to.
  const l2PaymentSer = buildSelectivePresentation(l2BaseJwt, [paymentDisc, merchantDisc]);
  const l2CheckoutSer = buildSelectivePresentation(l2BaseJwt, [checkoutDisc, itemDisc]);

  return { issuer, l1, l2, l2Ser, l3a, l3b, l2PaymentSer, l2CheckoutSer, l2Nonce, l3Nonce };
}

/** Full verify options for an autonomous chain, using the given (possibly
 * re-decoded) L3 credentials in a single split-L3 pair. */
function autonomousVerifyOpts(c: AutonomousChain, l3a: SdJwt, l3b: SdJwt): VerifyChainOptions {
  return {
    issuerPublicJwk: c.issuer.publicKey,
    l1Serialized: c.l1.serialize(),
    l2Serialized: c.l2Ser,
    splitL3s: [
      {
        l3Payment: l3a,
        l3Checkout: l3b,
        l2PaymentSerialized: c.l2PaymentSer,
        l2CheckoutSerialized: c.l2CheckoutSer,
      },
    ],
    expectedL2Aud: L2_AUD,
    expectedL2Nonce: c.l2Nonce,
    expectedL3PaymentAud: L3_PAYMENT_AUD,
    expectedL3PaymentNonce: c.l3Nonce,
    expectedL3CheckoutAud: L3_CHECKOUT_AUD,
    expectedL3CheckoutNonce: c.l3Nonce,
  };
}

/** Flip one character in the middle of a serialized SD-JWT's payload segment,
 * leaving header, signature and disclosures intact. */
function tamperPayload(serialized: string): string {
  const tildeIdx = serialized.indexOf('~');
  const jwt = tildeIdx === -1 ? serialized : serialized.slice(0, tildeIdx);
  const rest = tildeIdx === -1 ? '' : serialized.slice(tildeIdx);
  const [h, p, s] = jwt.split('.');
  if (h === undefined || p === undefined || s === undefined) throw new Error('not a compact JWT');
  const i = Math.floor(p.length / 2);
  const flipped = p[i] === 'A' ? 'B' : 'A';
  const newP = p.slice(0, i) + flipped + p.slice(i + 1);
  return `${h}.${newP}.${s}${rest}`;
}

// ---------------------------------------------------------------------------
// Immediate mode
// ---------------------------------------------------------------------------

describe('roundtrip: immediate mode (TS issue → TS verify, default options)', () => {
  it('verifies a freshly issued immediate chain', async () => {
    const c = await buildImmediateChain();
    // Two disclosures: the checkout mandate and the payment mandate.
    expect(c.l2.disclosures.length).toBe(2);

    const res = await verifyChain(c.l1, c.l2, {
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1.serialize(),
      expectedL2Aud: L2_AUD,
      expectedL2Nonce: c.l2Nonce,
    });

    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.mandatePairCount).toBe(1);
    expect(res.pairResults.length).toBe(1);
    expect(res.l2CheckoutDisclosed).toBe(true);
    expect(res.l2PaymentDisclosed).toBe(true);
  });

  it('verifies again after a serialize → decodeSdJwt wire round-trip', async () => {
    const c = await buildImmediateChain();
    const l1 = decodeSdJwt(c.l1.serialize());
    const l2 = decodeSdJwt(c.l2.serialize());

    const res = await verifyChain(l1, l2, {
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1.serialize(),
    });
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Autonomous mode
// ---------------------------------------------------------------------------

describe('roundtrip: autonomous mode (TS issue → TS verify, default options)', () => {
  it('verifies a freshly issued 3-layer split-L3 chain', async () => {
    const c = await buildAutonomousChain();
    // Six disclosures: 2 merchants + 2 acceptable items + checkout + payment.
    expect(c.l2.disclosures.length).toBe(6);

    const res = await verifyChain(c.l1, c.l2, autonomousVerifyOpts(c, c.l3a, c.l3b));

    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.mandatePairCount).toBe(1);
    expect(res.pairResults.length).toBe(1);
    expect(res.l2CheckoutDisclosed).toBe(true);
    expect(res.l2PaymentDisclosed).toBe(true);
    // Both L3s were verified and cross-referenced.
    expect(res.checksPerformed).toContain('l3_cross_reference');
    expect(res.pairResults[0]?.l3PaymentClaims).not.toEqual({});
    expect(res.pairResults[0]?.l3CheckoutClaims).not.toEqual({});
  });

  it('verifies again after serialize → decodeSdJwt wire round-trip of every layer', async () => {
    const c = await buildAutonomousChain();
    const l1 = decodeSdJwt(c.l1.serialize());
    const l2 = decodeSdJwt(c.l2Ser);
    const l3a = decodeSdJwt(c.l3a.serialize());
    const l3b = decodeSdJwt(c.l3b.serialize());

    const res = await verifyChain(l1, l2, autonomousVerifyOpts(c, l3a, l3b));
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Negative round trips
// ---------------------------------------------------------------------------

describe('roundtrip: negative controls', () => {
  it('rejects a chain verified against the WRONG issuer public key', async () => {
    const c = await buildImmediateChain();
    const attacker = await generateEs256Key();

    const res = await verifyChain(c.l1, c.l2, {
      issuerPublicJwk: attacker.publicKey,
      l1Serialized: c.l1.serialize(),
    });
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('L1 signature verification failed');
  });

  it('rejects (or fails to decode) a tampered serialized L2', async () => {
    const c = await buildImmediateChain();
    const tampered = tamperPayload(c.l2.serialize());

    let decoded: SdJwt;
    try {
      decoded = decodeSdJwt(tampered);
    } catch {
      // A one-character flip that breaks base64url/JSON structure is rejected at
      // decode time — an acceptable fail-closed outcome.
      return;
    }
    // Otherwise it decoded to a different payload whose user signature no longer
    // matches: verification must reject, never accept.
    const res = await verifyChain(c.l1, decoded, {
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1.serialize(),
    });
    expect(res.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Constraint checking against the actually-issued open mandate
// ---------------------------------------------------------------------------

describe('roundtrip: checkConstraints against the issued open payment mandate', () => {
  it('accepts a conforming fulfillment and rejects an over-budget one', async () => {
    const c = await buildAutonomousChain();

    // Extract the payment mandate's constraints straight from the issued L2.
    const resolved = await resolveDisclosures(c.l2);
    const delegates = Array.isArray(resolved.delegate_payload) ? resolved.delegate_payload : [];
    const paymentMandate = delegates.find((d) => isObj(d) && d.vct === 'mandate.payment.open.1');
    if (!isObj(paymentMandate) || !Array.isArray(paymentMandate.constraints)) {
      throw new Error('issued L2 payment mandate / constraints not found');
    }
    const paymentConstraints = paymentMandate.constraints;

    // Resolve the allowed_payees SD refs back to merchant objects (as a network
    // verifier would, per python/examples/autonomous_flow.py).
    const valueByHash = new Map<string, unknown>();
    for (let i = 0; i < c.l2.disclosures.length; i++) {
      const disc = c.l2.disclosures[i];
      const dv = c.l2.disclosureValues[i];
      if (disc === undefined || dv === undefined) continue;
      valueByHash.set(await hashDisclosure(disc), dv[dv.length - 1]);
    }
    const allowedMerchants: unknown[] = [];
    for (const con of paymentConstraints) {
      if (isObj(con) && con.type === 'mandate.payment.allowed_payees' && Array.isArray(con.allowed)) {
        for (const ref of con.allowed) {
          const h = isObj(ref) ? ref['...'] : undefined;
          if (typeof h === 'string' && valueByHash.has(h)) allowedMerchants.push(valueByHash.get(h));
        }
      }
    }

    const okFulfillment = {
      payment_amount: { currency: 'USD', amount: 27999 },
      payee: TENNIS_WAREHOUSE,
      allowed_merchants: allowedMerchants,
    };
    const okRes = checkConstraints(paymentConstraints, okFulfillment);
    expect(okRes.satisfied).toBe(true);
    expect(okRes.violations).toEqual([]);

    // $500 exceeds the issued $100–$400 (10000–40000 cents) amount range.
    const overBudget = {
      payment_amount: { currency: 'USD', amount: 50000 },
      payee: TENNIS_WAREHOUSE,
      allowed_merchants: allowedMerchants,
    };
    const badRes = checkConstraints(paymentConstraints, overBudget);
    expect(badRes.satisfied).toBe(false);
    expect(badRes.violations.length).toBeGreaterThan(0);
  });
});
