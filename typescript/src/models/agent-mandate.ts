/** Layer 3: Agent KB-SD-JWT mandate models (autonomous mode only).
 *
 * L3 is split into two credentials:
 *   PaymentL3Mandate (L3a)  → payment network, final payment values
 *   CheckoutL3Mandate (L3b) → merchant, final checkout JWT
 */

import type { JsonObject } from './constraints.js';

/** L3b final checkout mandate for the merchant. */
export class FinalCheckoutMandate {
  vct: string;
  checkoutJwt: string;
  checkoutHash: string;

  constructor(init: { vct?: string; checkoutJwt?: string; checkoutHash?: string } = {}) {
    this.vct = init.vct ?? 'mandate.checkout.1';
    this.checkoutJwt = init.checkoutJwt ?? '';
    this.checkoutHash = init.checkoutHash ?? '';
  }

  toJSON(): JsonObject {
    return { vct: this.vct, checkout_jwt: this.checkoutJwt, checkout_hash: this.checkoutHash };
  }
}

/** L3a final payment mandate for the network. */
export class FinalPaymentMandate {
  vct: string;
  transactionId: string;
  payee: JsonObject;
  paymentAmount: JsonObject;
  paymentInstrument: JsonObject;

  constructor(
    init: { vct?: string; transactionId?: string; payee?: JsonObject; paymentAmount?: JsonObject; paymentInstrument?: JsonObject } = {},
  ) {
    this.vct = init.vct ?? 'mandate.payment.1';
    this.transactionId = init.transactionId ?? '';
    this.payee = init.payee ?? {};
    this.paymentAmount = init.paymentAmount ?? {};
    this.paymentInstrument = init.paymentInstrument ?? {};
  }

  toJSON(): JsonObject {
    return {
      vct: this.vct,
      transaction_id: this.transactionId,
      payee: this.payee,
      payment_amount: this.paymentAmount,
      payment_instrument: this.paymentInstrument,
    };
  }
}

/** L3a KB-SD-JWT: the agent's payment fulfillment for the network. */
export class PaymentL3Mandate {
  nonce: string;
  aud: string;
  iat: number;
  iss: string | null;
  exp: number | null;
  sdHash: string;
  finalPayment: FinalPaymentMandate | null;
  finalMerchant: JsonObject | null;

  constructor(init: {
    nonce: string;
    aud: string;
    iat: number;
    iss?: string | null;
    exp?: number | null;
    sdHash?: string;
    finalPayment?: FinalPaymentMandate | null;
    finalMerchant?: JsonObject | null;
  }) {
    this.nonce = init.nonce;
    this.aud = init.aud;
    this.iat = init.iat;
    this.iss = init.iss ?? null;
    this.exp = init.exp ?? null;
    this.sdHash = init.sdHash ?? '';
    this.finalPayment = init.finalPayment ?? null;
    this.finalMerchant = init.finalMerchant ?? null;
  }
}

/** L3b KB-SD-JWT: the agent's checkout fulfillment for the merchant. */
export class CheckoutL3Mandate {
  nonce: string;
  aud: string;
  iat: number;
  iss: string | null;
  exp: number | null;
  sdHash: string;
  finalCheckout: FinalCheckoutMandate | null;

  constructor(init: {
    nonce: string;
    aud: string;
    iat: number;
    iss?: string | null;
    exp?: number | null;
    sdHash?: string;
    finalCheckout?: FinalCheckoutMandate | null;
  }) {
    this.nonce = init.nonce;
    this.aud = init.aud;
    this.iat = init.iat;
    this.iss = init.iss ?? null;
    this.exp = init.exp ?? null;
    this.sdHash = init.sdHash ?? '';
    this.finalCheckout = init.finalCheckout ?? null;
  }
}
