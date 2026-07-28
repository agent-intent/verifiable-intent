/**
 * Conformance tests: validate the TypeScript port against golden vectors
 * generated from the Python reference implementation
 * (../../test-vectors/vectors.json, produced by python/scripts/generate_vectors.py).
 *
 * ECDSA signatures are randomized, so we never compare signature bytes. We
 * compare the deterministic artifacts (disclosures, hashes, the base64url
 * header/payload segments, delegate_payload, _sd) and we cross-verify the
 * Python-signed credentials with the TypeScript verifier.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  AllowedMerchantConstraint,
  AllowedPayeeConstraint,
  b64urlDecode,
  b64urlEncode,
  CheckoutL3Mandate,
  CheckoutLineItemsConstraint,
  CheckoutMandate,
  compactJson,
  createDisclosure,
  createLayer1,
  createLayer2Autonomous,
  createLayer2Immediate,
  createLayer3Checkout,
  createLayer3Payment,
  decodeSdJwt,
  FinalCheckoutMandate,
  FinalPaymentMandate,
  hashAscii,
  hashDisclosure,
  IssuerCredential,
  MandateMode,
  parseConstraint,
  PaymentAmountConstraint,
  PaymentBudgetConstraint,
  PaymentL3Mandate,
  PaymentMandate,
  resolveDisclosures,
  UserMandate,
  verifySdJwtSignature,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const V: any = JSON.parse(readFileSync(join(here, '../../test-vectors/vectors.json'), 'utf8'));

/** Deterministic FIFO salt source that mirrors Python's disclosure-creation order. */
function fifo(salts: string[]): () => string {
  let i = 0;
  return () => {
    if (i >= salts.length) throw new Error(`salt source exhausted after ${i} salts`);
    return salts[i++];
  };
}

const hexToBytes = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));

describe('primitives: base64url', () => {
  for (const c of V.primitives.b64url) {
    it(`encode/decode ${c.bytes_hex || '(empty)'}`, () => {
      expect(b64urlEncode(hexToBytes(c.bytes_hex))).toBe(c.b64url);
      expect(Buffer.from(b64urlDecode(c.b64url)).toString('hex')).toBe(c.bytes_hex);
    });
  }
});

describe('primitives: disclosures', () => {
  V.primitives.disclosures.forEach((c: any, idx: number) => {
    it(`disclosure #${idx} (${c.claim_name ?? 'array-element'})`, async () => {
      expect(await createDisclosure(c.claim_name, c.value, c.salt)).toBe(c.disclosure);
      expect(await hashDisclosure(c.disclosure)).toBe(c.hash);
    });
  });
});

describe('primitives: hash_bytes (ascii)', () => {
  V.primitives.hash_bytes.forEach((c: any, idx: number) => {
    it(`hash #${idx}`, async () => {
      expect(await hashAscii(c.input_ascii)).toBe(c.hash);
    });
  });
});

describe('models: constraints round-trip (parse → toJSON → json)', () => {
  for (const c of V.models.constraints) {
    it(c.name, () => {
      const parsed = parseConstraint(c.dict);
      expect(parsed.toJSON()).toEqual(c.dict);
      expect(compactJson(parsed.toJSON())).toBe(c.json);
    });
  }

  it('PaymentBudgetConstraint rejects non-positive max', () => {
    expect(() => new PaymentBudgetConstraint({ currency: 'USD', max: 0 })).toThrow();
    expect(() => new PaymentBudgetConstraint({ currency: 'USD', max: 100, min: 0 })).toThrow();
  });
});

describe('models: misc toJSON', () => {
  it('IssuerCredential.toJSON', () => {
    const c = V.shared.l1_credential;
    const cred = new IssuerCredential({
      iss: c.iss,
      sub: c.sub,
      iat: c.iat,
      exp: c.exp,
      vct: c.vct,
      cnfJwk: c.cnf_jwk,
      panLastFour: c.pan_last_four,
      scheme: c.scheme,
      cardId: c.card_id,
      email: c.email,
    });
    expect(cred.toJSON()).toEqual(V.models.misc.issuer_credential_to_payload.dict);
    expect(compactJson(cred.toJSON())).toBe(V.models.misc.issuer_credential_to_payload.json);
  });

  it('FinalPaymentMandate / FinalCheckoutMandate', () => {
    const fp = V.models.misc.final_payment_mandate.dict;
    const built = new FinalPaymentMandate({
      transactionId: fp.transaction_id,
      payee: fp.payee,
      paymentAmount: fp.payment_amount,
      paymentInstrument: fp.payment_instrument,
    });
    expect(built.toJSON()).toEqual(fp);

    const fc = V.models.misc.final_checkout_mandate.dict;
    const builtC = new FinalCheckoutMandate({ checkoutJwt: fc.checkout_jwt, checkoutHash: fc.checkout_hash });
    expect(builtC.toJSON()).toEqual(fc);
  });
});

describe('crypto interop: TS verifies Python-signed credentials', () => {
  it('binds checkout_hash and l1 sd_hash', async () => {
    expect(await hashAscii(V.shared.checkout_jwt)).toBe(V.shared.checkout_hash);
    expect(await hashAscii(V.shared.l1_serialized)).toBe(V.shared.l1_sd_hash);
  });

  it('verifies the Python L1 signature', async () => {
    const sj = decodeSdJwt(V.shared.l1.serialized);
    expect(await sjVerify(sj, V.keys.issuer.public)).toBe(true);
  });

  it('verifies L2 immediate / autonomous (user key)', async () => {
    expect(await sjVerify(decodeSdJwt(V.immediate.l2.serialized), V.keys.user.public)).toBe(true);
    expect(await sjVerify(decodeSdJwt(V.autonomous.l2.serialized), V.keys.user.public)).toBe(true);
  });

  it('verifies L3a / L3b (agent key)', async () => {
    expect(await sjVerify(decodeSdJwt(V.autonomous.l3a.credential.serialized), V.keys.agent.public)).toBe(true);
    expect(await sjVerify(decodeSdJwt(V.autonomous.l3b.credential.serialized), V.keys.agent.public)).toBe(true);
  });

  it('rejects a tampered Python L1 (mutated subject)', async () => {
    const sj = decodeSdJwt(V.shared.l1.serialized);
    sj.payload.sub = 'attacker';
    expect(await sjVerify(sj, V.keys.issuer.public)).toBe(false);
  });
});

describe('crypto: resolveDisclosures', () => {
  it('resolves immediate delegate_payload to the mandate dicts', async () => {
    const resolved = await resolveDisclosures(decodeSdJwt(V.immediate.l2.serialized));
    expect(resolved.delegate_payload).toEqual(V.immediate.l2.values);
  });

  it('resolves autonomous delegate_payload to checkout + payment mandates', async () => {
    const resolved = await resolveDisclosures(decodeSdJwt(V.autonomous.l2.serialized));
    const vals = V.autonomous.l2.values;
    expect(resolved.delegate_payload).toEqual([vals[vals.length - 2], vals[vals.length - 1]]);
  });
});

describe('disclosure reproduction from salt + value (array-element flows)', () => {
  const cases: Array<[string, any]> = [
    ['L2-immediate', V.immediate.l2],
    ['L2-autonomous', V.autonomous.l2],
    ['L3a', V.autonomous.l3a.credential],
    ['L3b', V.autonomous.l3b.credential],
  ];
  for (const [name, rec] of cases) {
    it(`${name}`, async () => {
      for (let i = 0; i < rec.disclosures.length; i++) {
        expect(await createDisclosure(null, rec.values[i], rec.salts[i])).toBe(rec.disclosures[i]);
        expect(await hashDisclosure(rec.disclosures[i])).toBe(rec.sd_hashes_of_disclosures[i]);
      }
    });
  }
});

describe('issuance reproduction (byte-exact payload + disclosures)', () => {
  it('L1', async () => {
    const c = V.shared.l1_credential;
    const cred = new IssuerCredential({
      iss: c.iss,
      sub: c.sub,
      iat: c.iat,
      exp: c.exp,
      vct: c.vct,
      cnfJwk: c.cnf_jwk,
      panLastFour: c.pan_last_four,
      scheme: c.scheme,
      cardId: c.card_id,
      email: c.email,
    });
    const sj = await createLayer1(cred, V.keys.issuer.private, {
      kid: V.keys.issuer.kid,
      saltSource: fifo(V.shared.l1.salts),
    });
    expect(sj.disclosures).toEqual(V.shared.l1.disclosures);
    expect(sj.rawHeaderB64).toBe(V.shared.l1.header_b64);
    expect(sj.rawPayloadB64).toBe(V.shared.l1.payload_b64);
    expect(sj.payload).toEqual(V.shared.l1.payload);
    expect(await sjVerify(sj, V.keys.issuer.public)).toBe(true);
  });

  it('L2 immediate', async () => {
    const inp = V.immediate.inputs;
    const cm = new CheckoutMandate({ vct: inp.checkout_mandate.vct, checkoutJwt: inp.checkout_mandate.checkout_jwt });
    const pm = new PaymentMandate({
      vct: inp.payment_mandate.vct,
      paymentInstrument: inp.payment_mandate.payment_instrument,
      payee: inp.payment_mandate.payee,
      currency: inp.payment_mandate.currency,
      amount: inp.payment_mandate.amount,
    });
    const mandate = new UserMandate({
      nonce: inp.nonce,
      aud: inp.aud,
      iat: inp.iat,
      mode: MandateMode.IMMEDIATE,
      iss: inp.iss,
      exp: inp.exp,
      sdHash: inp.sd_hash,
      checkoutMandate: cm,
      paymentMandate: pm,
    });
    const res = await createLayer2Immediate(mandate, V.keys.user.private, {
      kid: inp.kid,
      saltSource: fifo(V.immediate.l2.salts),
    });
    expect(res.sdJwt.disclosures).toEqual(V.immediate.l2.disclosures);
    expect(res.sdJwt.rawPayloadB64).toBe(V.immediate.l2.payload_b64);
    expect(res.sdJwt.payload).toEqual(V.immediate.l2.payload);
    // Mandate dicts (post auto-compute of checkout_hash / transaction_id)
    expect(cm.toJSON()).toEqual(V.immediate.checkout_mandate_dict);
    expect(pm.toJSON()).toEqual(V.immediate.payment_mandate_dict);
    expect(await sjVerify(res.sdJwt, V.keys.user.public)).toBe(true);
  });

  it('L2 autonomous', async () => {
    const inp = V.autonomous.inputs;
    const pi = V.immediate.inputs.payment_mandate.payment_instrument; // same PAYMENT_INSTRUMENT
    const checkout = new CheckoutMandate({
      vct: 'mandate.checkout.open.1',
      cnfJwk: inp.agent_cnf_jwk,
      cnfKid: inp.agent_cnf_kid,
      constraints: [
        new AllowedMerchantConstraint({ allowed: inp.merchants }),
        new CheckoutLineItemsConstraint({
          items: [{ id: 'line-1', acceptable_items: inp.acceptable_items, quantity: 1 }],
        }),
      ],
    });
    const payment = new PaymentMandate({
      vct: 'mandate.payment.open.1',
      cnfJwk: inp.agent_cnf_jwk,
      cnfKid: inp.agent_cnf_kid,
      constraints: [
        new AllowedPayeeConstraint({ allowed: [inp.merchants[0]] }),
        new PaymentAmountConstraint({ currency: 'USD', min: 10000, max: 40000 }),
      ],
      paymentInstrument: pi,
    });
    const mandate = new UserMandate({
      nonce: inp.nonce,
      aud: inp.aud,
      iat: inp.iat,
      mode: MandateMode.AUTONOMOUS,
      iss: inp.iss,
      exp: inp.exp,
      sdHash: inp.sd_hash,
      merchants: inp.merchants,
      acceptableItems: inp.acceptable_items,
      checkoutMandate: checkout,
      paymentMandate: payment,
    });
    const sj = await createLayer2Autonomous(mandate, V.keys.user.private, {
      kid: inp.kid,
      saltSource: fifo(V.autonomous.l2.salts),
    });
    expect(sj.disclosures).toEqual(V.autonomous.l2.disclosures);
    expect(sj.rawPayloadB64).toBe(V.autonomous.l2.payload_b64);
    expect(sj.payload).toEqual(V.autonomous.l2.payload);
    expect(await sjVerify(sj, V.keys.user.public)).toBe(true);
  });

  it('L3a payment', async () => {
    const inp = V.autonomous.l3a.inputs;
    const fp = new FinalPaymentMandate({
      transactionId: inp.final_payment.transaction_id,
      payee: inp.final_payment.payee,
      paymentAmount: inp.final_payment.payment_amount,
      paymentInstrument: inp.final_payment.payment_instrument,
    });
    const mandate = new PaymentL3Mandate({
      nonce: inp.nonce,
      aud: inp.aud,
      iat: inp.iat,
      iss: inp.iss,
      exp: inp.exp,
      finalPayment: fp,
      finalMerchant: inp.final_merchant,
    });
    const sj = await createLayer3Payment(
      mandate,
      V.keys.agent.private,
      { l2BaseJwt: inp.l2_base_jwt, paymentDisclosure: inp.payment_disclosure, merchantDisclosure: inp.merchant_disclosure },
      { kid: inp.kid, saltSource: fifo(V.autonomous.l3a.credential.salts) },
    );
    expect(sj.disclosures).toEqual(V.autonomous.l3a.credential.disclosures);
    expect(sj.payload.sd_hash).toBe(V.autonomous.l3a.sd_hash);
    expect(sj.rawPayloadB64).toBe(V.autonomous.l3a.credential.payload_b64);
    expect(sj.payload).toEqual(V.autonomous.l3a.credential.payload);
    expect(await sjVerify(sj, V.keys.agent.public)).toBe(true);
  });

  it('L3b checkout', async () => {
    const inp = V.autonomous.l3b.inputs;
    const fc = new FinalCheckoutMandate({
      checkoutJwt: inp.final_checkout.checkout_jwt,
      checkoutHash: inp.final_checkout.checkout_hash,
    });
    const mandate = new CheckoutL3Mandate({
      nonce: inp.nonce,
      aud: inp.aud,
      iat: inp.iat,
      iss: inp.iss,
      exp: inp.exp,
      finalCheckout: fc,
    });
    const sj = await createLayer3Checkout(
      mandate,
      V.keys.agent.private,
      { l2BaseJwt: inp.l2_base_jwt, checkoutDisclosure: inp.checkout_disclosure, itemDisclosure: inp.item_disclosure },
      { kid: inp.kid, saltSource: fifo(V.autonomous.l3b.credential.salts) },
    );
    expect(sj.disclosures).toEqual(V.autonomous.l3b.credential.disclosures);
    expect(sj.payload.sd_hash).toBe(V.autonomous.l3b.sd_hash);
    expect(sj.rawPayloadB64).toBe(V.autonomous.l3b.credential.payload_b64);
    expect(await sjVerify(sj, V.keys.agent.public)).toBe(true);
  });
});

function sjVerify(sj: ReturnType<typeof decodeSdJwt>, jwk: any): Promise<boolean> {
  return verifySdJwtSignature(sj, jwk);
}
