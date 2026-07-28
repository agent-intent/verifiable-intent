/** Layer 2: User KB-SD-JWT mandate models. */

import type { CnfClaim, Constraint, JsonObject } from './constraints.js';

export const MandateMode = {
  IMMEDIATE: 'IMMEDIATE',
  AUTONOMOUS: 'AUTONOMOUS',
} as const;
export type MandateMode = (typeof MandateMode)[keyof typeof MandateMode];

// Match Python's truthiness of `cnf_jwk` (`if self.cnf_jwk:`): an empty object —
// like an empty object in Python — counts as "no cnf" for emission and for the
// CheckoutMandate both-modes guard. (PaymentMandate.__post_init__ deliberately
// uses `is not None`, so its constructor guard keeps `!== null` below.)
const hasCnf = (jwk: JsonObject | null): boolean => jwk !== null && Object.keys(jwk).length > 0;

/**
 * Checkout mandate — open (L2 autonomous) or final (L2 immediate).
 *  - Autonomous: `cnfJwk` + `constraints`, vct = `mandate.checkout.open.1`
 *  - Immediate:  `checkoutJwt` + `checkoutHash`, vct = `mandate.checkout.1`
 */
export class CheckoutMandate {
  vct: string;
  cnfJwk: JsonObject | null;
  cnfKid: string | null;
  constraints: Constraint[];
  checkoutJwt: string | null;
  checkoutHash: string | null;

  constructor(
    init: {
      vct?: string;
      cnfJwk?: JsonObject | null;
      cnfKid?: string | null;
      constraints?: Constraint[];
      checkoutJwt?: string | null;
      checkoutHash?: string | null;
    } = {},
  ) {
    this.vct = init.vct ?? 'mandate.checkout.open.1';
    this.cnfJwk = init.cnfJwk ?? null;
    this.cnfKid = init.cnfKid ?? null;
    this.constraints = init.constraints ?? [];
    this.checkoutJwt = init.checkoutJwt ?? null;
    this.checkoutHash = init.checkoutHash ?? null;
    if (hasCnf(this.cnfJwk) && this.checkoutJwt !== null) {
      throw new Error('CheckoutMandate cannot have both cnf_jwk (autonomous) and checkout_jwt (immediate)');
    }
  }

  toJSON(): JsonObject {
    const d: JsonObject = { vct: this.vct };
    if (hasCnf(this.cnfJwk)) {
      const jwk: JsonObject = { ...this.cnfJwk };
      if (this.cnfKid) jwk.kid = this.cnfKid;
      d.cnf = { jwk } satisfies CnfClaim;
    }
    if (this.constraints.length) {
      d.constraints = this.constraints.map((c) => c.toJSON());
    }
    if (this.checkoutJwt !== null) d.checkout_jwt = this.checkoutJwt;
    if (this.checkoutHash !== null) d.checkout_hash = this.checkoutHash;
    return d;
  }
}

/**
 * Payment mandate — open (L2 autonomous) or final (L2 immediate).
 *  - Autonomous: `cnfJwk` + `constraints` + `paymentInstrument` + `riskData`
 *  - Immediate:  `currency` + `amount` + `payee` + `paymentInstrument` + `transactionId`
 */
export class PaymentMandate {
  vct: string;
  cnfJwk: JsonObject | null;
  cnfKid: string | null;
  constraints: Constraint[];
  paymentInstrument: JsonObject | null;
  riskData: JsonObject | null;
  payee: JsonObject | null;
  currency: string | null;
  amount: number | null;
  transactionId: string | null;

  constructor(
    init: {
      vct?: string;
      cnfJwk?: JsonObject | null;
      cnfKid?: string | null;
      constraints?: Constraint[];
      paymentInstrument?: JsonObject | null;
      riskData?: JsonObject | null;
      payee?: JsonObject | null;
      currency?: string | null;
      amount?: number | null;
      transactionId?: string | null;
    } = {},
  ) {
    this.vct = init.vct ?? 'mandate.payment.open.1';
    this.cnfJwk = init.cnfJwk ?? null;
    this.cnfKid = init.cnfKid ?? null;
    this.constraints = init.constraints ?? [];
    this.paymentInstrument = init.paymentInstrument ?? null;
    this.riskData = init.riskData ?? null;
    this.payee = init.payee ?? null;
    this.currency = init.currency ?? null;
    this.amount = init.amount ?? null;
    this.transactionId = init.transactionId ?? null;
    if (this.amount !== null && this.cnfJwk !== null) {
      throw new Error('PaymentMandate cannot have both cnf_jwk (autonomous) and amount (immediate)');
    }
  }

  toJSON(): JsonObject {
    const d: JsonObject = { vct: this.vct };
    if (hasCnf(this.cnfJwk)) {
      const jwk: JsonObject = { ...this.cnfJwk };
      if (this.cnfKid) jwk.kid = this.cnfKid;
      d.cnf = { jwk } satisfies CnfClaim;
    }
    if (this.constraints.length) {
      d.constraints = this.constraints.map((c) => c.toJSON());
    }
    if (this.paymentInstrument !== null) d.payment_instrument = this.paymentInstrument;
    if (this.riskData !== null) d.risk_data = this.riskData;
    if (this.payee !== null) d.payee = this.payee;
    if (this.currency !== null && this.amount !== null) {
      d.payment_amount = { currency: this.currency, amount: this.amount };
    }
    if (this.transactionId !== null) d.transaction_id = this.transactionId;
    return d;
  }
}

/** Layer 2 KB-SD-JWT: the user's consent with mandates. */
export class UserMandate {
  nonce: string;
  aud: string;
  iat: number;
  mode: MandateMode;
  iss: string | null;
  exp: number | null;
  sdHash: string;
  promptSummary: string | null;
  checkoutMandate: CheckoutMandate | null;
  paymentMandate: PaymentMandate | null;
  merchants: JsonObject[];
  acceptableItems: JsonObject[];

  constructor(init: {
    nonce: string;
    aud: string;
    iat: number;
    mode: MandateMode;
    iss?: string | null;
    exp?: number | null;
    sdHash?: string;
    promptSummary?: string | null;
    checkoutMandate?: CheckoutMandate | null;
    paymentMandate?: PaymentMandate | null;
    merchants?: JsonObject[];
    acceptableItems?: JsonObject[];
  }) {
    this.nonce = init.nonce;
    this.aud = init.aud;
    this.iat = init.iat;
    this.mode = init.mode;
    this.iss = init.iss ?? null;
    this.exp = init.exp ?? null;
    this.sdHash = init.sdHash ?? '';
    this.promptSummary = init.promptSummary ?? null;
    this.checkoutMandate = init.checkoutMandate ?? null;
    this.paymentMandate = init.paymentMandate ?? null;
    this.merchants = init.merchants ?? [];
    this.acceptableItems = init.acceptableItems ?? [];
  }
}
