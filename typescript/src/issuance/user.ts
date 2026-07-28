/** Layer 2: User mandate creation for both Immediate and Autonomous modes. */

import {
  createDelegateRef,
  createDisclosure,
  type DelegateRef,
  generateSalt,
  hashAscii,
  hashDisclosure,
} from '../crypto/disclosure.js';
import { createSdJwt, SdJwt } from '../crypto/sd-jwt.js';
import type { Es256Jwk, IssuanceHeader } from '../crypto/signing.js';
import { type JsonObject, ReferenceConstraint } from '../models/constraints.js';
import { MandateMode, type UserMandate } from '../models/user-mandate.js';
import type { IssueOptions } from './options.js';
import { asArray } from '../internal/guards.js';

/**
 * Result of Layer 2 creation in Immediate mode. The user signs final values
 * directly — there is no onward agent delegation.
 */
export class ImmediateL2Result {
  constructor(public sdJwt: SdJwt) {}

  serialize(): string {
    return this.sdJwt.serialize();
  }
}

/** Create Layer 2 KB-SD-JWT for Immediate mode (final values, no delegation). */
export async function createLayer2Immediate(
  mandate: UserMandate,
  userPrivateJwk: Es256Jwk,
  opts: IssueOptions = {},
): Promise<ImmediateL2Result> {
  if (mandate.mode !== MandateMode.IMMEDIATE) {
    throw new Error(`createLayer2Immediate() requires mode=IMMEDIATE, got ${String(mandate.mode)}`);
  }
  const kid = opts.kid ?? 'user-device-key-1';
  const nextSalt = opts.saltSource ?? generateSalt;

  const disclosures: string[] = [];

  // Auto-compute checkout_hash and transaction_id BEFORE disclosure serialization.
  const cm = mandate.checkoutMandate;
  if (cm && cm.checkoutJwt) {
    const computedHash = await hashAscii(cm.checkoutJwt);
    if (!cm.checkoutHash) cm.checkoutHash = computedHash;
    if (mandate.paymentMandate && !mandate.paymentMandate.transactionId) {
      mandate.paymentMandate.transactionId = computedHash;
    }
  }

  if (mandate.checkoutMandate) {
    disclosures.push(await createDisclosure(null, mandate.checkoutMandate.toJSON(), await nextSalt()));
  }
  if (mandate.paymentMandate) {
    disclosures.push(await createDisclosure(null, mandate.paymentMandate.toJSON(), await nextSalt()));
  }

  const delegatePayload = await Promise.all(disclosures.map(async (d) => createDelegateRef(await hashDisclosure(d))));

  const payload: Record<string, unknown> = {
    nonce: mandate.nonce,
    aud: mandate.aud,
    iat: mandate.iat,
    sd_hash: mandate.sdHash,
    delegate_payload: delegatePayload,
    _sd_alg: 'sha-256',
  };
  if (mandate.iss !== null) payload.iss = mandate.iss;
  if (mandate.exp !== null) payload.exp = mandate.exp;

  const sdHashes = await Promise.all(disclosures.map(hashDisclosure));
  if (sdHashes.length) payload._sd = sdHashes;

  const header: IssuanceHeader = { alg: 'ES256', typ: 'kb-sd-jwt', kid };
  const sdJwt = await createSdJwt(header, payload, disclosures, userPrivateJwk);
  return new ImmediateL2Result(sdJwt);
}

/** Create Layer 2 KB-SD-JWT for Autonomous mode (open mandates + nested disclosures). */
export async function createLayer2Autonomous(
  mandate: UserMandate,
  userPrivateJwk: Es256Jwk,
  opts: IssueOptions = {},
): Promise<SdJwt> {
  if (mandate.mode !== MandateMode.AUTONOMOUS) {
    throw new Error(`createLayer2Autonomous() requires mode=AUTONOMOUS, got ${String(mandate.mode)}`);
  }
  const kid = opts.kid ?? 'user-device-key-1';
  const nextSalt = opts.saltSource ?? generateSalt;

  const disclosures: string[] = [];

  // 1. Standalone merchant disclosures
  const merchantDiscHashes: string[] = [];
  for (const merchant of mandate.merchants) {
    const d = await createDisclosure(null, merchant, await nextSalt());
    disclosures.push(d);
    merchantDiscHashes.push(await hashDisclosure(d));
  }

  // 2. Standalone acceptable item disclosures
  const itemDiscHashes: string[] = [];
  for (const item of mandate.acceptableItems) {
    const d = await createDisclosure(null, item, await nextSalt());
    disclosures.push(d);
    itemDiscHashes.push(await hashDisclosure(d));
  }

  // 3. Open checkout mandate disclosure (constraint merchant/item refs scoped to subset)
  let checkoutDisc: string | null = null;
  if (mandate.checkoutMandate) {
    const checkoutObj = mandate.checkoutMandate.toJSON();
    for (const c of (checkoutObj.constraints as JsonObject[] | undefined) ?? []) {
      if (c.type === 'mandate.checkout.allowed_merchants') {
        c.allowed = matchMerchantRefs(asArray(c.allowed), mandate.merchants, merchantDiscHashes);
      } else if (c.type === 'mandate.checkout.line_items') {
        for (const itemEntry of (c.items as JsonObject[] | undefined) ?? []) {
          itemEntry.acceptable_items = matchItemRefs(asArray(itemEntry.acceptable_items), mandate.acceptableItems, itemDiscHashes);
        }
      }
    }
    checkoutDisc = await createDisclosure(null, checkoutObj, await nextSalt());
    disclosures.push(checkoutDisc);
  }

  // 4. Open payment mandate disclosure (payee refs + injected reference constraint)
  let paymentDisc: string | null = null;
  if (mandate.paymentMandate) {
    const paymentObj = mandate.paymentMandate.toJSON();
    for (const c of (paymentObj.constraints as JsonObject[] | undefined) ?? []) {
      if (c.type === 'mandate.payment.allowed_payees') {
        c.allowed = matchMerchantRefs(asArray(c.allowed), mandate.merchants, merchantDiscHashes);
      }
    }
    if (checkoutDisc !== null) {
      const refConstraint = new ReferenceConstraint({ conditionalTransactionId: await hashDisclosure(checkoutDisc) });
      if (!Array.isArray(paymentObj.constraints)) paymentObj.constraints = [];
      (paymentObj.constraints as JsonObject[]).push(refConstraint.toJSON());
    }
    paymentDisc = await createDisclosure(null, paymentObj, await nextSalt());
    disclosures.push(paymentDisc);
  }

  // 5. delegate_payload references the two mandate disclosures
  const delegatePayload: DelegateRef[] = [];
  if (checkoutDisc) delegatePayload.push(createDelegateRef(await hashDisclosure(checkoutDisc)));
  if (paymentDisc) delegatePayload.push(createDelegateRef(await hashDisclosure(paymentDisc)));

  const sdHashes = await Promise.all(disclosures.map(hashDisclosure));

  const payload: Record<string, unknown> = {
    nonce: mandate.nonce,
    aud: mandate.aud,
    iat: mandate.iat,
    sd_hash: mandate.sdHash,
    delegate_payload: delegatePayload,
    _sd_alg: 'sha-256',
  };
  if (sdHashes.length) payload._sd = sdHashes;
  if (mandate.iss !== null) payload.iss = mandate.iss;
  if (mandate.exp !== null) payload.exp = mandate.exp;

  const header: IssuanceHeader = { alg: 'ES256', typ: 'kb-sd-jwt+kb', kid };
  return createSdJwt(header, payload, disclosures, userPrivateJwk);
}

/**
 * Match a constraint's merchant list against the mandate merchants, returning
 * scoped SD refs. Empty input → empty list (fail-closed at verification).
 */
function matchMerchantRefs(originalMerchants: unknown[], mandateMerchants: JsonObject[], discHashes: string[]): DelegateRef[] {
  if (originalMerchants.length === 0) return [];
  const matched: DelegateRef[] = [];
  for (const origRaw of originalMerchants) {
    const orig = origRaw as JsonObject;
    const origId = orig.id;
    const origName = orig.name;
    if (!origId && !origName) {
      throw new Error(`Constraint merchant missing both 'id' and 'name': ${JSON.stringify(orig)}`);
    }
    let found = false;
    for (const [idx, m] of mandateMerchants.entries()) {
      const mId = m.id;
      const match = origId && mId ? mId === origId : m.name === origName && Boolean(origName);
      if (match) {
        const disc = discHashes[idx];
        if (disc !== undefined) matched.push(createDelegateRef(disc));
        found = true;
        break;
      }
    }
    if (!found) {
      throw new Error(`Constraint references unknown merchant: ${String(origId ?? origName)}`);
    }
  }
  return matched;
}

/**
 * Match a constraint's item list against the mandate items, returning scoped SD
 * refs. Empty input → empty list (any SKU allowed per spec).
 */
function matchItemRefs(originalItems: unknown[], mandateItems: JsonObject[], discHashes: string[]): DelegateRef[] {
  if (originalItems.length === 0) return [];
  const matched: DelegateRef[] = [];
  for (const origRaw of originalItems) {
    if (typeof origRaw !== 'object' || origRaw === null) {
      throw new Error(`Constraint item must be an object: ${JSON.stringify(origRaw)}`);
    }
    const orig = origRaw as JsonObject;
    const origKeys = [orig.id, orig.sku].filter((k): k is unknown => Boolean(k));
    let found = false;
    for (const [idx, item] of mandateItems.entries()) {
      const itemKeys = [item.id, item.sku].filter((k) => Boolean(k));
      if (origKeys.length > 0 && origKeys.some((k) => itemKeys.includes(k))) {
        const disc = discHashes[idx];
        if (disc !== undefined) matched.push(createDelegateRef(disc));
        found = true;
        break;
      }
    }
    if (!found) {
      throw new Error(`Constraint references unknown item: ${String(orig.id ?? orig.sku ?? JSON.stringify(orig))}`);
    }
  }
  return matched;
}
