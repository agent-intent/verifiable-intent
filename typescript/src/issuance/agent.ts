/** Layer 3: Agent mandate creation (autonomous mode only).
 *
 * L3 is split into two credentials:
 *   createLayer3Payment()  → L3a for the payment network
 *   createLayer3Checkout() → L3b for the merchant
 */

import {
  buildSelectivePresentation,
  createDelegateRef,
  createDisclosure,
  generateSalt,
  hashAscii,
  hashDisclosure,
} from '../crypto/disclosure.js';
import { createSdJwt, SdJwt } from '../crypto/sd-jwt.js';
import type { Es256Jwk, IssuanceHeader } from '../crypto/signing.js';
import type { CheckoutL3Mandate, PaymentL3Mandate } from '../models/agent-mandate.js';
import type { IssueOptions } from './options.js';

/** The slice of the L2 presentation an L3a payment mandate's `sd_hash` binds to. */
export interface Layer3PaymentPresentation {
  /** The L2 issuer JWT (base compact JWT, without disclosures). */
  l2BaseJwt: string;
  /** The L2 payment-mandate disclosure the network receives. */
  paymentDisclosure: string;
  /** The L2 merchant disclosure the network receives. */
  merchantDisclosure: string;
}

/**
 * Create L3a: the payment mandate for the network. The `sd_hash` binds to the
 * L2 presentation as the network sees it (L2 base JWT + payment + merchant
 * disclosures).
 */
export async function createLayer3Payment(
  mandate: PaymentL3Mandate,
  agentPrivateJwk: Es256Jwk,
  presentation: Layer3PaymentPresentation,
  opts: IssueOptions = {},
): Promise<SdJwt> {
  const kid = opts.kid ?? 'agent-key-1';
  const nextSalt = opts.saltSource ?? generateSalt;

  const disclosures: string[] = [];
  if (mandate.finalMerchant) {
    disclosures.push(await createDisclosure(null, mandate.finalMerchant, await nextSalt()));
  }
  if (mandate.finalPayment) {
    disclosures.push(await createDisclosure(null, mandate.finalPayment.toJSON(), await nextSalt()));
  }

  const delegatePayload = await Promise.all(disclosures.map(async (d) => createDelegateRef(await hashDisclosure(d))));

  const selectivePresentation = buildSelectivePresentation(presentation.l2BaseJwt, [
    presentation.paymentDisclosure,
    presentation.merchantDisclosure,
  ]);
  const sdHash = await hashAscii(selectivePresentation);

  const payload: Record<string, unknown> = {
    nonce: mandate.nonce,
    aud: mandate.aud,
    sd_hash: sdHash,
    iat: mandate.iat,
    delegate_payload: delegatePayload,
    _sd_alg: 'sha-256',
  };
  if (mandate.iss !== null) payload.iss = mandate.iss;
  if (mandate.exp !== null) payload.exp = mandate.exp;

  const header: IssuanceHeader = { alg: 'ES256', typ: 'kb-sd-jwt', kid };
  return createSdJwt(header, payload, disclosures, agentPrivateJwk);
}

/** The slice of the L2 presentation an L3b checkout mandate's `sd_hash` binds to. */
export interface Layer3CheckoutPresentation {
  /** The L2 issuer JWT (base compact JWT, without disclosures). */
  l2BaseJwt: string;
  /** The L2 checkout-mandate disclosure the merchant receives. */
  checkoutDisclosure: string;
  /** The L2 line-item disclosure the merchant receives. */
  itemDisclosure: string;
}

/**
 * Create L3b: the checkout mandate for the merchant. The `sd_hash` binds to the
 * L2 presentation as the merchant sees it (L2 base JWT + checkout + item
 * disclosures).
 */
export async function createLayer3Checkout(
  mandate: CheckoutL3Mandate,
  agentPrivateJwk: Es256Jwk,
  presentation: Layer3CheckoutPresentation,
  opts: IssueOptions = {},
): Promise<SdJwt> {
  const kid = opts.kid ?? 'agent-key-1';
  const nextSalt = opts.saltSource ?? generateSalt;

  const disclosures: string[] = [];
  if (mandate.finalCheckout) {
    disclosures.push(await createDisclosure(null, mandate.finalCheckout.toJSON(), await nextSalt()));
  }

  const delegatePayload = await Promise.all(disclosures.map(async (d) => createDelegateRef(await hashDisclosure(d))));

  const selectivePresentation = buildSelectivePresentation(presentation.l2BaseJwt, [
    presentation.checkoutDisclosure,
    presentation.itemDisclosure,
  ]);
  const sdHash = await hashAscii(selectivePresentation);

  const payload: Record<string, unknown> = {
    nonce: mandate.nonce,
    aud: mandate.aud,
    sd_hash: sdHash,
    iat: mandate.iat,
    delegate_payload: delegatePayload,
    _sd_alg: 'sha-256',
  };
  if (mandate.iss !== null) payload.iss = mandate.iss;
  if (mandate.exp !== null) payload.exp = mandate.exp;

  const header: IssuanceHeader = { alg: 'ES256', typ: 'kb-sd-jwt', kid };
  return createSdJwt(header, payload, disclosures, agentPrivateJwk);
}
