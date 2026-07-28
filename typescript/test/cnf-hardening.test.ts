/**
 * Fail-closed tests for the cnf / agent-delegation-key hardening in
 * `src/verification/chain.ts` — the key-substitution attack surface.
 *
 * The verifier resolves three keys from confirmation (`cnf`) claims:
 *   - L1 `cnf.jwk` → the USER key that must sign L2.
 *   - the open L2 mandates' `cnf.jwk` → the AGENT key that must sign L3.
 * If any of these could be swapped, forged, or sourced from an attacker-
 * controlled disclosure, the whole delegation chain would fail open. These
 * cases lock the guards closed:
 *   - L1 `cnf` shape validation           (chain.ts §3, ~L268-282, validateEcPublicJwk ~L78)
 *   - agent-key extraction cross-checks   (extractAgentKeyFromAllPairs ~L1024)
 *   - agent key must come from the two REFERENCED open mandates, not from an
 *     unreferenced or non-mandate disclosure
 *   - L3 payloads MUST NOT carry `cnf`    (chain.ts ~L576, terminal delegation)
 *   - an in-memory L1 `cnf` swap is caught by the issuer signature
 *
 * These mirror the Python reference tests in
 * `python/tests/test_verification_hardening.py`
 * (TestDualMandateCnfCrossCheck, TestMalformedJwk, TestL3CnfRejection,
 * TestMutationDetection.test_mutated_cnf_rejected_by_chain). Chains are issued
 * fresh in-memory with a deterministic salt source and a fixed `currentTime`;
 * no network, no golden vectors.
 *
 * NOTE: one genuine TS↔Python divergence is documented below as `it.fails`
 * (L1 cnf.jwk with syntactically-present but undecodable base64 coordinates).
 */

import { describe, expect, it } from 'vitest';

import {
  AllowedMerchantConstraint,
  buildSelectivePresentation,
  CheckoutL3Mandate,
  CheckoutLineItemsConstraint,
  CheckoutMandate,
  createDisclosure,
  createLayer1,
  createLayer2Autonomous,
  createLayer2Immediate,
  createLayer3Checkout,
  createLayer3Payment,
  createSdJwt,
  type DecodedDisclosure,
  decodeDisclosure,
  decodeSdJwt,
  type Es256Jwk,
  FinalCheckoutMandate,
  FinalPaymentMandate,
  generateEs256Key,
  hashAscii,
  IssuerCredential,
  type JsonObject,
  jwtEncode,
  makeSigner,
  MandateMode,
  PaymentAmountConstraint,
  PaymentL3Mandate,
  PaymentMandate,
  type SdJwt,
  UserMandate,
  verifyChain,
  type VerifyChainOptions,
} from '../src/index.js';

// --- Fixtures (ported from python/examples/helpers.py) --------------------

const MERCHANTS: JsonObject[] = [
  { id: 'merchant-uuid-1', name: 'Tennis Warehouse', website: 'https://tennis-warehouse.com' },
  { id: 'merchant-uuid-2', name: 'Babolat', website: 'https://babolat.com' },
];
const ACCEPTABLE_ITEMS: JsonObject[] = [
  { id: 'BAB86345', title: 'Babolat Pure Aero Tennis Racket' },
  { id: 'HEA23102', title: 'Head Graphene 360 Speed' },
];
const PAYMENT_INSTRUMENT: JsonObject = {
  type: 'mastercard.srcDigitalCard',
  id: 'f199c3dd-7106-478b-9b5f-7af9ca725170',
  description: 'Mastercard **** 1234',
};

/** Fixed clock so every issued credential's iat/exp verifies deterministically. */
const NOW = 1_700_000_000;

type KeyPair = { publicKey: Es256Jwk; privateKey: Es256Jwk };
const jwkOf = (k: KeyPair): JsonObject => k.publicKey as unknown as JsonObject;

/** Monotonic FIFO salt source → unique, reproducible disclosures (no RNG). */
function deterministicSalts(): () => string {
  let n = 0;
  return () => `salt${(n++).toString().padStart(22, '0')}`;
}

/** Find an L2 disclosure whose decoded value satisfies `pred` (parity with helpers._find_disclosure). */
function findDisclosure(sd: SdJwt, pred: (v: JsonObject) => boolean): string {
  for (const disc of sd.disclosures) {
    const dv: DecodedDisclosure = decodeDisclosure(disc);
    const value = dv.length ? dv[dv.length - 1] : null;
    if (value && typeof value === 'object' && !Array.isArray(value) && pred(value as JsonObject)) return disc;
  }
  throw new Error('expected disclosure not found');
}

async function merchantCheckoutJwt(merchant: KeyPair): Promise<string> {
  const signer = await makeSigner(merchant.privateKey);
  return jwtEncode(
    { alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' },
    { iss: 'https://tennis-warehouse.com', sub: 'cart_checkout', iat: NOW, exp: NOW + 3600 },
    signer,
  );
}

interface ChainOptions {
  /** Omit the agent cnf.jwk from the open checkout mandate. */
  includeCheckoutCnf?: boolean;
  /** Omit the agent cnf.jwk from the open payment mandate. */
  includePaymentCnf?: boolean;
  /** Override the checkout mandate's cnf.jwk (defaults to the agent key). */
  checkoutCnfJwk?: JsonObject;
  /** Override the payment mandate's cnf.jwk (defaults to the agent key). */
  paymentCnfJwk?: JsonObject;
}

interface Chain {
  issuer: KeyPair;
  user: KeyPair;
  agent: KeyPair;
  l1: SdJwt;
  l1Ser: string;
  l2: SdJwt;
  l2Ser: string;
  l3a: SdJwt;
  l3b: SdJwt;
  l2PaymentSer: string;
  l2CheckoutSer: string;
}

/** Build a valid autonomous 3-layer chain (parity with helpers `_make_autonomous_chain`). */
async function makeAutonomousChain(opts: ChainOptions = {}): Promise<Chain> {
  const salts = deterministicSalts();
  const io = { saltSource: salts };

  const issuer = await generateEs256Key();
  const user = await generateEs256Key();
  const agent = await generateEs256Key();
  const merchant = await generateEs256Key();

  const l1 = await createLayer1(
    new IssuerCredential({
      iss: 'https://www.mastercard.com',
      sub: 'userCredentialId',
      iat: NOW,
      exp: NOW + 86400,
      aud: 'https://wallet.example.com',
      email: 'test@example.com',
      panLastFour: '1234',
      scheme: 'Mastercard',
      cnfJwk: jwkOf(user),
    }),
    issuer.privateKey,
    io,
  );
  const l1Ser = l1.serialize();

  const checkoutCnf = opts.includeCheckoutCnf === false ? null : (opts.checkoutCnfJwk ?? jwkOf(agent));
  const paymentCnf = opts.includePaymentCnf === false ? null : (opts.paymentCnfJwk ?? jwkOf(agent));

  const checkoutMandate = new CheckoutMandate({
    vct: 'mandate.checkout.open.1',
    cnfJwk: checkoutCnf,
    cnfKid: checkoutCnf ? 'agent-key-1' : null,
    constraints: [
      new AllowedMerchantConstraint({ allowed: MERCHANTS }),
      new CheckoutLineItemsConstraint({
        items: [{ id: 'line-item-1', acceptable_items: ACCEPTABLE_ITEMS.slice(0, 1), quantity: 1 }],
      }),
    ],
  });
  const paymentMandate = new PaymentMandate({
    vct: 'mandate.payment.open.1',
    cnfJwk: paymentCnf,
    cnfKid: paymentCnf ? 'agent-key-1' : null,
    paymentInstrument: PAYMENT_INSTRUMENT,
    constraints: [new PaymentAmountConstraint({ currency: 'USD', min: 10000, max: 40000 })],
  });
  const userMandate = new UserMandate({
    nonce: 'n-auto',
    aud: 'https://www.agent.com',
    iat: NOW,
    iss: 'https://wallet.example.com',
    exp: NOW + 86400,
    mode: MandateMode.AUTONOMOUS,
    sdHash: await hashAscii(l1Ser),
    checkoutMandate,
    paymentMandate,
    merchants: MERCHANTS,
    acceptableItems: ACCEPTABLE_ITEMS,
  });
  const l2 = await createLayer2Autonomous(userMandate, user.privateKey, io);
  const l2Ser = l2.serialize();
  const l2BaseJwt = l2Ser.split('~')[0] ?? '';

  const paymentDisc = findDisclosure(l2, (v) => v.vct === 'mandate.payment.open.1');
  const checkoutDisc = findDisclosure(l2, (v) => v.vct === 'mandate.checkout.open.1');
  const merchantDisc = findDisclosure(l2, (v) => v.name === 'Tennis Warehouse');
  const itemDisc = findDisclosure(l2, (v) => v.id === 'BAB86345');

  const checkoutJwt = await merchantCheckoutJwt(merchant);
  const cHash = await hashAscii(checkoutJwt);

  const l3a = await createLayer3Payment(
    new PaymentL3Mandate({
      nonce: 'n-l3a',
      aud: 'https://www.mastercard.com',
      iat: NOW,
      iss: 'https://agent.example.com',
      exp: NOW + 300,
      finalPayment: new FinalPaymentMandate({
        transactionId: cHash,
        payee: MERCHANTS[0],
        paymentAmount: { currency: 'USD', amount: 27999 },
        paymentInstrument: PAYMENT_INSTRUMENT,
      }),
      finalMerchant: MERCHANTS[0],
    }),
    agent.privateKey,
    { l2BaseJwt, paymentDisclosure: paymentDisc, merchantDisclosure: merchantDisc },
    io,
  );

  const l3b = await createLayer3Checkout(
    new CheckoutL3Mandate({
      nonce: 'n-l3b',
      aud: 'https://tennis-warehouse.com',
      iat: NOW,
      iss: 'https://agent.example.com',
      exp: NOW + 300,
      finalCheckout: new FinalCheckoutMandate({ checkoutJwt, checkoutHash: cHash }),
    }),
    agent.privateKey,
    { l2BaseJwt, checkoutDisclosure: checkoutDisc, itemDisclosure: itemDisc },
    io,
  );

  const l2PaymentSer = buildSelectivePresentation(l2BaseJwt, [paymentDisc, merchantDisc]);
  const l2CheckoutSer = buildSelectivePresentation(l2BaseJwt, [checkoutDisc, itemDisc]);

  return { issuer, user, agent, l1, l1Ser, l2, l2Ser, l3a, l3b, l2PaymentSer, l2CheckoutSer };
}

/** verifyChain opts for the full split-L3 autonomous chain, with the issuer key present. */
function fullVerifyOpts(c: Chain, l3Payment: SdJwt | null, l3Checkout: SdJwt | null): VerifyChainOptions {
  return {
    splitL3s: [
      {
        l3Payment,
        l3Checkout,
        l2PaymentSerialized: c.l2PaymentSer,
        l2CheckoutSerialized: c.l2CheckoutSer,
      },
    ],
    issuerPublicJwk: c.issuer.publicKey,
    l1Serialized: c.l1Ser,
    l2Serialized: c.l2Ser,
    currentTime: NOW,
  };
}

/** Re-sign an L3 with an injected `cnf` claim (parity with the Python create_sd_jwt tamper). */
async function withInjectedCnf(l3: SdJwt, agent: KeyPair): Promise<SdJwt> {
  const bad = { ...l3.payload, cnf: { jwk: jwkOf(agent) } };
  return createSdJwt(l3.header, bad, l3.disclosures, agent.privateKey);
}

/** Build a minimal L1/L2 with an arbitrary L1 `cnf` value, for cnf-shape tests. */
async function buildL1L2WithCnf(cnf: unknown): Promise<{ l1: SdJwt; l2: SdJwt }> {
  const salts = deterministicSalts();
  const issuer = await generateEs256Key();
  const user = await generateEs256Key();
  const l1 = await createSdJwt(
    { alg: 'ES256', typ: 'sd+jwt' },
    {
      iss: 'https://www.mastercard.com',
      sub: 'test',
      iat: NOW,
      exp: NOW + 86400,
      vct: 'https://credentials.mastercard.com/card',
      pan_last_four: '1234',
      scheme: 'Mastercard',
      cnf,
    },
    [],
    issuer.privateKey,
  );
  const l2 = await createSdJwt(
    { alg: 'ES256', typ: 'kb-sd-jwt' },
    { nonce: salts(), aud: 'test', iat: NOW, sd_hash: await hashAscii(l1.serialize()), delegate_payload: [] },
    [],
    user.privateKey,
  );
  return { l1, l2 };
}

describe('cnf hardening: baseline', () => {
  it('a fresh valid autonomous chain verifies (guards the test harness itself)', async () => {
    const c = await makeAutonomousChain();
    const res = await verifyChain(c.l1, c.l2, fullVerifyOpts(c, c.l3a, c.l3b));
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });
});

describe('cnf hardening: L1 cnf shape validation (chain.ts §3)', () => {
  it('rejects a non-object L1 cnf', async () => {
    const { l1, l2 } = await buildL1L2WithCnf('not-a-json-object');
    const res = await verifyChain(l1, l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('L1 cnf must be a JSON object'))).toBe(true);
  });

  it('rejects an L1 with an empty cnf (no cnf.jwk)', async () => {
    const { l1, l2 } = await buildL1L2WithCnf({});
    const res = await verifyChain(l1, l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('L1 missing cnf.jwk (user public key)'))).toBe(true);
  });

  it('rejects an L1 cnf.jwk missing the x coordinate (malformed, not a crash)', async () => {
    const user = await generateEs256Key();
    const y = (user.publicKey as unknown as JsonObject).y;
    const { l1, l2 } = await buildL1L2WithCnf({ jwk: { kty: 'EC', crv: 'P-256', y } });
    const res = await verifyChain(l1, l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(res.valid).toBe(false);
    // Python: "L1 cnf.jwk is malformed: 'x'"; TS: "...: missing x/y coordinate" — both carry "malformed".
    expect(res.errors.some((e) => e.toLowerCase().includes('malformed'))).toBe(true);
  });

  // DIVERGENCE (error string only; accept/reject verdict is identical):
  // Python's jwk_to_public_key eagerly decodes the EC point at cnf-extraction
  // time, so syntactically-present-but-undecodable base64 coordinates are
  // reported as "L1 cnf.jwk is malformed: Invalid EC key. Point is not on the
  // curve specified." TS's validateEcPublicJwk only checks that x/y are
  // non-empty strings (it never decodes them), so a bad-base64 key slips past
  // the "malformed" guard and instead fails one step later at the L2 signature
  // check with "L2 signature verification failed (user key mismatch)". Both
  // still return valid=false. This assertion is written to Python's behavior;
  // it.fails records that TS does not match the error string byte-for-byte.
  it.fails('DIVERGENCE: L1 cnf.jwk with bad-base64 coordinates → Python says "malformed", TS does not', async () => {
    const { l1, l2 } = await buildL1L2WithCnf({ jwk: { kty: 'EC', crv: 'P-256', x: '!!!invalid!!!', y: '!!!bad!!!' } });
    const res = await verifyChain(l1, l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.toLowerCase().includes('malformed'))).toBe(true);
  });
});

describe('cnf hardening: agent delegation key extraction (chain.ts §4d)', () => {
  it('rejects mismatched agent cnf.jwk across the checkout/payment mandates', async () => {
    // Checkout keeps the agent key; payment carries a DIFFERENT key. The chain
    // must refuse to guess which is the real agent, not accept either.
    const other = await generateEs256Key();
    const c = await makeAutonomousChain({ paymentCnfJwk: jwkOf(other) });
    const res = await verifyChain(c.l1, c.l2, fullVerifyOpts(c, c.l3a, c.l3b));
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('identical') || e.includes('differ'))).toBe(true);
  });

  it('rejects a disclosed open mandate that is missing its cnf.jwk', async () => {
    // Both open mandates are disclosed; the payment one drops cnf.jwk. The agent
    // key must be present on every disclosed open mandate, not just one.
    const c = await makeAutonomousChain({ includePaymentCnf: false });
    const res = await verifyChain(c.l1, c.l2, {
      l3Payment: c.l3a,
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1Ser,
      l2PaymentSerialized: c.l2PaymentSer,
      currentTime: NOW,
    });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.toLowerCase().includes('payment open mandate missing cnf.jwk'))).toBe(true);
  });

  it('rejects a cnf.jwk sourced from an UNREFERENCED extra disclosure', async () => {
    // Neither real open mandate carries cnf; an extra mandate-shaped disclosure
    // with cnf is appended to the L2 but never referenced by delegate_payload.
    // It must not satisfy agent-key extraction.
    const c = await makeAutonomousChain({ includeCheckoutCnf: false, includePaymentCnf: false });
    const fake = await createDisclosure(null, { vct: 'mandate.checkout.open.1', cnf: { jwk: jwkOf(c.agent) } });
    const tamperedL2 = decodeSdJwt(`${c.l2Ser.slice(0, -1)}~${fake}~`);
    const res = await verifyChain(c.l1, tamperedL2, {
      l3Payment: c.l3a,
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1Ser,
      l2PaymentSerialized: c.l2PaymentSer,
      currentTime: NOW,
    });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.toLowerCase().includes('missing cnf.jwk'))).toBe(true);
  });

  it('rejects a cnf.jwk sourced from a NON-mandate (merchant-shaped) disclosure', async () => {
    // Same, but the injected disclosure is a merchant/payee object carrying cnf.
    // A cnf on a non-mandate disclosure must not be used for delegation.
    const c = await makeAutonomousChain({ includeCheckoutCnf: false, includePaymentCnf: false });
    const fake = await createDisclosure(null, {
      id: 'merchant-injected',
      name: 'Injected Merchant',
      website: 'https://example.invalid',
      cnf: { jwk: jwkOf(c.agent) },
    });
    const tamperedL2 = decodeSdJwt(`${c.l2Ser.slice(0, -1)}~${fake}~`);
    const res = await verifyChain(c.l1, tamperedL2, {
      l3Payment: c.l3a,
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1Ser,
      l2PaymentSerialized: c.l2PaymentSer,
      currentTime: NOW,
    });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.toLowerCase().includes('missing cnf.jwk'))).toBe(true);
  });
});

describe('cnf hardening: L3 payloads MUST NOT carry cnf (chain.ts ~L576)', () => {
  it('rejects an L3 payment (L3a) that carries a cnf claim', async () => {
    const c = await makeAutonomousChain();
    const l3aTampered = await withInjectedCnf(c.l3a, c.agent);
    const res = await verifyChain(c.l1, c.l2, fullVerifyOpts(c, l3aTampered, c.l3b));
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('MUST NOT contain cnf'))).toBe(true);
  });

  it('rejects an L3 checkout (L3b) that carries a cnf claim', async () => {
    const c = await makeAutonomousChain();
    const l3bTampered = await withInjectedCnf(c.l3b, c.agent);
    const res = await verifyChain(c.l1, c.l2, fullVerifyOpts(c, c.l3a, l3bTampered));
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('MUST NOT contain cnf'))).toBe(true);
  });
});

describe('cnf hardening: in-memory L1 cnf swap is caught by the issuer signature', () => {
  it('rejects an L1 whose cnf.jwk was swapped to an attacker key after issuance', async () => {
    // Immediate-mode chain; the issuer key IS provided (no skip), so mutating
    // the signed L1 payload must break the L1 signature — the attacker cannot
    // rebind the credential to their own key.
    const salts = deterministicSalts();
    const io = { saltSource: salts };
    const issuer = await generateEs256Key();
    const user = await generateEs256Key();
    const attacker = await generateEs256Key();
    const merchant = await generateEs256Key();

    const l1 = await createLayer1(
      new IssuerCredential({
        iss: 'https://www.mastercard.com',
        sub: 'userCredentialId',
        iat: NOW,
        exp: NOW + 86400,
        aud: 'https://wallet.example.com',
        email: 'test@example.com',
        panLastFour: '1234',
        scheme: 'Mastercard',
        cnfJwk: jwkOf(user),
      }),
      issuer.privateKey,
      io,
    );

    const checkoutJwt = await merchantCheckoutJwt(merchant);
    const cHash = await hashAscii(checkoutJwt);
    const userMandate = new UserMandate({
      nonce: 'n-imm',
      aud: 'https://www.agent.com',
      iat: NOW,
      iss: 'https://wallet.example.com',
      exp: NOW + 900,
      mode: MandateMode.IMMEDIATE,
      sdHash: await hashAscii(l1.serialize()),
      checkoutMandate: new CheckoutMandate({ vct: 'mandate.checkout.1', checkoutJwt }),
      paymentMandate: new PaymentMandate({
        vct: 'mandate.payment.1',
        currency: 'USD',
        amount: 27999,
        payee: MERCHANTS[0],
        paymentInstrument: PAYMENT_INSTRUMENT,
        transactionId: cHash,
      }),
    });
    const l2 = (await createLayer2Immediate(userMandate, user.privateKey, io)).sdJwt;

    // Attacker swaps the confirmation key in the decoded L1 payload.
    (l1.payload as JsonObject).cnf = { jwk: jwkOf(attacker) };

    const res = await verifyChain(l1, l2, { issuerPublicJwk: issuer.publicKey, currentTime: NOW });
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('L1 signature'))).toBe(true);
  });
});
