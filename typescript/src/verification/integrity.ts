/** Checkout-payment integrity verification (SHA-256 cross-referencing). */

import { hashAscii, hashDisclosure } from '../crypto/disclosure.js';
import { isJsonObject } from '../internal/guards.js';
import type { JsonObject } from '../models/constraints.js';

/** A binding-check verdict: whether it held, and the error message when it didn't. */
export interface IntegrityResult {
  valid: boolean;
  error: string;
}

/** Verify checkout_hash = SHA-256(checkout_jwt) and transaction_id = checkout_hash. */
export function verifyCheckoutHashBinding(checkoutMandate: JsonObject, paymentMandate: JsonObject): Promise<IntegrityResult> {
  const checkoutJwt = checkoutMandate.checkout_jwt;
  if (checkoutJwt !== undefined && checkoutJwt !== null && typeof checkoutJwt !== 'string') {
    return Promise.resolve({ valid: false, error: `checkout_jwt must be a string, got ${typeof checkoutJwt}` });
  }
  if (!checkoutJwt) return Promise.resolve({ valid: true, error: '' }); // no checkout_jwt to bind

  const checkoutHash = checkoutMandate.checkout_hash;
  if (!checkoutHash) {
    return Promise.resolve({ valid: false, error: 'checkout_jwt present but checkout_hash missing from checkout mandate' });
  }

  // Deliberately NOT declared `async`: hashAscii throws synchronously on
  // non-ASCII input, and letting that propagate matches Python's uncaught
  // UnicodeEncodeError (pinned by the parity tests). An `async` function would
  // convert the throw into a rejection.
  return hashAscii(checkoutJwt as string).then((computed) => {
    if (computed !== checkoutHash) {
      return { valid: false, error: `checkout_hash mismatch: computed ${computed} != expected ${String(checkoutHash)}` };
    }

    const transactionId = paymentMandate.transaction_id;
    if (!transactionId) {
      return { valid: false, error: 'checkout_jwt present but transaction_id missing from payment mandate' };
    }
    if (transactionId !== checkoutHash) {
      return {
        valid: false,
        error: `transaction_id mismatch: ${String(transactionId)} != checkout_hash ${String(checkoutHash)}`,
      };
    }

    return { valid: true, error: '' };
  });
}

/** Verify the L2 mandate.payment.reference constraint binds to the L2 checkout disclosure. */
export async function verifyL2ReferenceBinding(
  _checkoutMandate: JsonObject,
  paymentMandate: JsonObject,
  checkoutDisclosureB64: string,
): Promise<IntegrityResult> {
  const constraints = paymentMandate.constraints;
  let refConstraint: JsonObject | null = null;
  for (const c of Array.isArray(constraints) ? constraints : []) {
    if (isJsonObject(c) && c.type === 'mandate.payment.reference') {
      refConstraint = c;
      break;
    }
  }
  if (refConstraint === null) return { valid: true, error: '' }; // no reference constraint to check

  const expectedId = (refConstraint.conditional_transaction_id as string) || '';
  if (!expectedId) {
    return { valid: false, error: 'mandate.payment.reference missing required conditional_transaction_id' };
  }

  const computedHash = await hashDisclosure(checkoutDisclosureB64);
  if (computedHash !== expectedId) {
    return { valid: false, error: `conditional_transaction_id mismatch: computed ${computedHash} != expected ${expectedId}` };
  }
  return { valid: true, error: '' };
}

/** Verify L3a transaction_id matches L3b checkout_hash. */
export function verifyL3CrossReference(l3PaymentClaims: JsonObject, l3CheckoutClaims: JsonObject): IntegrityResult {
  const l3aDelegates = l3PaymentClaims.delegate_payload;
  let transactionId: unknown = null;
  for (const d of Array.isArray(l3aDelegates) ? l3aDelegates : []) {
    if (isJsonObject(d) && d.vct === 'mandate.payment.1') {
      transactionId = d.transaction_id ?? null;
      break;
    }
  }

  const l3bDelegates = l3CheckoutClaims.delegate_payload;
  let checkoutHash: unknown = null;
  for (const d of Array.isArray(l3bDelegates) ? l3bDelegates : []) {
    if (isJsonObject(d) && d.vct === 'mandate.checkout.1') {
      checkoutHash = d.checkout_hash ?? null;
      break;
    }
  }

  if (transactionId === null) return { valid: false, error: 'L3a payment mandate missing transaction_id' };
  if (checkoutHash === null) return { valid: false, error: 'L3b checkout mandate missing checkout_hash' };
  if (transactionId !== checkoutHash) {
    return {
      valid: false,
      error: `L3 cross-reference mismatch: transaction_id=${String(transactionId)} != checkout_hash=${String(checkoutHash)}`,
    };
  }
  return { valid: true, error: '' };
}
