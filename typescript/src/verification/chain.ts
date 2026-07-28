/**
 * Full chain verification (L1 → L2 → L3a/L3b).
 *
 * This file — including its 500+-line `verifyChain` and its numbered step
 * sequence — deliberately mirrors
 * python/src/verifiable_intent/verification/chain.py line-for-line for
 * auditability. Both the control flow AND the `result.errors` strings must stay
 * byte-for-byte identical to the Python reference; several of those error
 * strings are pinned by the shared golden vectors in test-vectors/vectors.json.
 * Refactor only alongside a matching change on the Python side.
 */

import { hashAscii, hashDisclosure } from '../crypto/disclosure.js';
import { type SdJwt, resolveDisclosures, verifySdJwtSignature } from '../crypto/sd-jwt.js';
import type { Es256Jwk } from '../crypto/signing.js';
import type { JsonObject, KnownConstraintType } from '../models/constraints.js';
import { asArray, isJsonObject } from '../internal/guards.js';
import { verifyCheckoutHashBinding, verifyL2ReferenceBinding, verifyL3CrossReference } from './integrity.js';

const ALLOWED_ALGS = new Set(['ES256']);

/**
 * Constraint types the spec assigns to the PAYMENT NETWORK to enforce: they are
 * stateful (spend-so-far, occurrence counts), so this stateless verifier parses
 * but never evaluates them (see constraint-checker.ts, "network-enforced
 * constraints"). They are surfaced on `ChainVerificationResult.networkEnforced`
 * so the caller/network knows what it still must enforce.
 */
const NETWORK_ENFORCED_TYPES: ReadonlySet<KnownConstraintType> = new Set([
  'mandate.payment.budget',
  'mandate.payment.recurrence',
  'mandate.payment.agent_recurrence',
]);

const L1_VCT = 'https://credentials.mastercard.com/card';
const L2_CHECKOUT_VCT_OPEN = 'mandate.checkout.open.1';
const L2_PAYMENT_VCT_OPEN = 'mandate.payment.open.1';
const L2_CHECKOUT_VCT_FINAL = 'mandate.checkout.1';
const L2_PAYMENT_VCT_FINAL = 'mandate.payment.1';
const L3_PAYMENT_VCT = 'mandate.payment.1';
const L3_CHECKOUT_VCT = 'mandate.checkout.1';

const CHECKOUT_VCTS = new Set([L2_CHECKOUT_VCT_OPEN, L2_CHECKOUT_VCT_FINAL]);
const PAYMENT_VCTS = new Set([L2_PAYMENT_VCT_OPEN, L2_PAYMENT_VCT_FINAL]);
const ALL_KNOWN_VCTS = new Set([
  L2_CHECKOUT_VCT_OPEN,
  L2_CHECKOUT_VCT_FINAL,
  L2_PAYMENT_VCT_OPEN,
  L2_PAYMENT_VCT_FINAL,
  L3_PAYMENT_VCT,
  L3_CHECKOUT_VCT,
]);

const isFiniteNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const truncate = (s: string): string => (s.length > 64 ? s.slice(0, 64) : s);

/** RFC 9901 §7.1: a digest MUST NOT appear more than once in `_sd`. Returns the first duplicate, or null. */
function duplicateSdDigest(payload: Record<string, unknown>): string | null {
  const sd = payload._sd;
  if (!Array.isArray(sd)) return null;
  const seen = new Set<string>();
  for (const h of sd) {
    if (typeof h !== 'string') continue;
    if (seen.has(h)) return h;
    seen.add(h);
  }
  return null;
}

/** True if `exp` is expired; null if absent. */
function isExpired(exp: unknown, now: number, skew: number): boolean | null {
  if (exp === undefined || exp === null) return null;
  if (typeof exp === 'boolean') return true;
  if (typeof exp !== 'number') return true;
  if (!Number.isFinite(exp)) return true;
  return now > exp + skew;
}

/** True if `iat` is in the future; null if absent. */
function isFutureDated(iat: unknown, now: number, skew: number): boolean | null {
  if (iat === undefined || iat === null) return null;
  if (typeof iat === 'boolean') return true;
  if (typeof iat !== 'number') return true;
  if (!Number.isFinite(iat)) return true;
  return iat > now + skew;
}

function validateHeader(header: unknown, layer: string, expectedTyp: string): string | null {
  if (!isJsonObject(header)) return `${layer} header must be a JSON object, got ${header === null ? 'null' : typeof header}`;
  const alg = header.alg;
  if (typeof alg !== 'string' || !ALLOWED_ALGS.has(alg)) {
    return `${layer} header alg must be one of {ES256}, got ${typeof alg} '${truncate(String(alg))}'`;
  }
  const typ = header.typ;
  if (typeof typ !== 'string' || typ !== expectedTyp) {
    return `${layer} header typ must be '${expectedTyp}', got ${typeof typ} '${truncate(String(typ))}'`;
  }
  return null;
}

function validateEcPublicJwk(jwk: unknown): string | null {
  if (!isJsonObject(jwk)) return 'cnf.jwk must be an object';
  if (typeof jwk.x !== 'string' || !jwk.x || typeof jwk.y !== 'string' || !jwk.y) {
    return 'missing x/y coordinate';
  }
  return null;
}

export interface SplitL3 {
  l3Payment?: SdJwt | null;
  l3Checkout?: SdJwt | null;
  l2PaymentSerialized?: string | null;
  l2CheckoutSerialized?: string | null;
}

export class MandatePairResult {
  pairIndex = 0;
  pairingKey = '';
  checkoutMandate: JsonObject = {};
  paymentMandate: JsonObject = {};
  l3PaymentClaims: JsonObject = {};
  l3CheckoutClaims: JsonObject = {};
  checksPerformed: string[] = [];
  checksSkipped: string[] = [];
  errors: string[] = [];
}

export class ChainVerificationResult {
  valid = false;
  errors: string[] = [];
  l1Claims: JsonObject = {};
  l2Claims: JsonObject = {};
  l3PaymentClaims: JsonObject = {};
  l3CheckoutClaims: JsonObject = {};
  l2CheckoutDisclosed = false;
  l2PaymentDisclosed = false;
  checksPerformed: string[] = [];
  checksSkipped: string[] = [];
  pairResults: MandatePairResult[] = [];
  mandatePairCount = 0;
  networkEnforced: NetworkEnforcedConstraint[] = [];
}

/**
 * A network-enforced constraint found in a mandate pair's payment mandate.
 * Purely informational: the stateless verifier did NOT evaluate it — the spec
 * assigns enforcement of budget/recurrence to the payment network.
 */
export interface NetworkEnforcedConstraint {
  /** Index of the mandate pair (into `ChainVerificationResult.pairResults`). */
  pairIndex: number;
  type: KnownConstraintType;
  /** The raw constraint object as resolved from the payment mandate. */
  constraint: JsonObject;
}

interface MandateInfo {
  resolved: JsonObject;
  refHash: string | null;
  discB64: string | null;
}

type MandatePair = [checkout: MandateInfo | null, payment: MandateInfo | null];

/** Result of grouping L2 delegate disclosures into checkout/payment mandate pairs. */
interface MandatePairsResult {
  pairs: MandatePair[];
  errors: string[];
}

/** Result of validating one mandate pair: blocking errors plus the checks run/skipped. */
interface MandatePairCheck {
  errors: string[];
  checksPerformed: string[];
  checksSkipped: string[];
}

/** The agent delegation key resolved from the L2 open mandates, or an error if inconsistent. */
interface AgentKeyResult {
  jwk: JsonObject | null;
  kid: string | null;
  error: string | null;
}

export interface VerifyChainOptions {
  l3Payment?: SdJwt | null;
  l3Checkout?: SdJwt | null;
  issuerPublicJwk?: Es256Jwk | null;
  skipIssuerVerification?: boolean;
  clockSkewSeconds?: number;
  l1Serialized?: string | null;
  l2Serialized?: string | null;
  l2PaymentSerialized?: string | null;
  l2CheckoutSerialized?: string | null;
  splitL3s?: SplitL3[] | null;
  expectedL2Aud?: string | null;
  expectedL2Nonce?: string | null;
  expectedL3PaymentAud?: string | null;
  expectedL3PaymentNonce?: string | null;
  expectedL3CheckoutAud?: string | null;
  expectedL3CheckoutNonce?: string | null;
  expectedL1Vct?: string;
  /** Unix seconds; defaults to the wall clock. Inject for deterministic verification. */
  currentTime?: number;
}

async function tryVerify(sj: SdJwt, jwk: Es256Jwk): Promise<boolean> {
  try {
    return await verifySdJwtSignature(sj, jwk);
  } catch {
    return false;
  }
}

/**
 * Verify the full VI delegation chain (split L3). Returns a result whose `valid`
 * is `false` with populated `errors` on any failure; never rejects on a malformed
 * or hostile credential (parsing with `decodeSdJwt` may throw — verification does not).
 */
export async function verifyChain(l1: SdJwt, l2: SdJwt, opts: VerifyChainOptions = {}): Promise<ChainVerificationResult> {
  const result = new ChainVerificationResult();
  const now = opts.currentTime ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSeconds ?? 300;
  const expectedL1Vct = opts.expectedL1Vct ?? L1_VCT;
  const l3Payment = opts.l3Payment ?? null;
  const l3Checkout = opts.l3Checkout ?? null;
  const splitL3s = opts.splitL3s ?? null;

  // 0. Mutual exclusion: split_l3s vs individual l3 params
  if (splitL3s !== null && (l3Payment !== null || l3Checkout !== null)) {
    // Every string pushed to result.errors in this function is parity-pinned to
    // Python (and some are pinned by test-vectors/vectors.json); never reword one
    // without changing chain.py and regenerating the vectors.
    result.errors.push('Cannot provide both split_l3s and individual l3_payment/l3_checkout parameters');
    return result;
  }

  let hasL3Args = l3Payment !== null || l3Checkout !== null;
  if (splitL3s !== null) {
    hasL3Args = hasL3Args || splitL3s.some((p) => (p.l3Payment ?? null) !== null || (p.l3Checkout ?? null) !== null);
  }

  // 0. Validate payload types are objects (fail-closed on malformed JWTs)
  if (!isJsonObject(l1.payload)) {
    result.errors.push(`L1 payload must be a JSON object, got ${typeof l1.payload}`);
    return result;
  }
  if (!isJsonObject(l2.payload)) {
    result.errors.push(`L2 payload must be a JSON object, got ${typeof l2.payload}`);
    return result;
  }

  // 1. Verify L1 signature (fail-closed: require key unless explicitly skipped)
  if (opts.issuerPublicJwk) {
    if (!(await tryVerify(l1, opts.issuerPublicJwk))) {
      result.errors.push('L1 signature verification failed');
      return result;
    }
  } else if (!opts.skipIssuerVerification) {
    result.errors.push(
      'issuer_public_key is required for chain verification (pass skip_issuer_verification=True to bypass in tests)',
    );
    return result;
  }

  // 1a0. Validate L1 header
  const l1HeaderErr = validateHeader(l1.header, 'L1', 'sd+jwt');
  if (l1HeaderErr) {
    result.errors.push(l1HeaderErr);
    return result;
  }

  // 1a. Validate L1 vct
  const l1Vct = l1.payload.vct;
  if (l1Vct !== expectedL1Vct) {
    result.errors.push(`L1 vct must be '${expectedL1Vct}', got '${String(l1Vct)}'`);
    return result;
  }

  // 1b. Validate L1 _sd_alg
  const l1SdAlg = l1.payload._sd_alg;
  if (l1SdAlg !== undefined && l1SdAlg !== null && l1SdAlg !== 'sha-256') {
    result.errors.push(`L1 _sd_alg must be 'sha-256', got '${String(l1SdAlg)}'`);
    return result;
  }

  // 1b-bis. RFC 9901 §7.1: reject duplicate disclosure digests in _sd
  const l1SdDup = duplicateSdDigest(l1.payload);
  if (l1SdDup !== null) {
    result.errors.push(`L1 _sd contains a duplicate disclosure digest (RFC 9901 section 7.1): ${l1SdDup}`);
    return result;
  }

  // 2. L1 expiration
  if (isExpired(l1.payload.exp, now, skew)) {
    result.errors.push(`L1 credential expired at ${String(l1.payload.exp)}`);
    return result;
  }
  // 2a. L1 iat not in the future
  if (isFutureDated(l1.payload.iat, now, skew)) {
    result.errors.push(`L1 credential iat is in the future: ${String(l1.payload.iat)}`);
    return result;
  }

  result.l1Claims = await resolveDisclosures(l1);

  // 3. Extract user's public key from L1 cnf
  const l1Cnf = l1.payload.cnf ?? {};
  if (!isJsonObject(l1Cnf)) {
    result.errors.push('L1 cnf must be a JSON object');
    return result;
  }
  const userJwk = l1Cnf.jwk;
  if (!userJwk || !isJsonObject(userJwk) || Object.keys(userJwk).length === 0) {
    result.errors.push('L1 missing cnf.jwk (user public key)');
    return result;
  }
  const userJwkErr = validateEcPublicJwk(userJwk);
  if (userJwkErr) {
    result.errors.push(`L1 cnf.jwk is malformed: ${userJwkErr}`);
    return result;
  }

  // 4. Verify L2 signature with user's key
  if (!(await tryVerify(l2, userJwk as Es256Jwk))) {
    result.errors.push('L2 signature verification failed (user key mismatch)');
    return result;
  }

  // 4a. Verify L2 sd_hash binds to the presented L1
  const l1Ser = opts.l1Serialized ?? l1.serialize();
  const actualHash = l2.payload.sd_hash ?? '';
  if (!actualHash) {
    result.errors.push('L2 missing required sd_hash binding to L1');
    return result;
  }
  if (actualHash !== (await hashAscii(l1Ser))) {
    result.errors.push('L2 sd_hash does not match L1 serialized form');
    return result;
  }

  // 4a2. L2 _sd_alg
  const l2SdAlg = l2.payload._sd_alg;
  if (l2SdAlg !== undefined && l2SdAlg !== null && l2SdAlg !== 'sha-256') {
    result.errors.push(`L2 _sd_alg must be 'sha-256', got '${String(l2SdAlg)}'`);
    return result;
  }

  // 4a2-bis. RFC 9901 §7.1: reject duplicate disclosure digests in _sd
  const l2SdDup = duplicateSdDigest(l2.payload);
  if (l2SdDup !== null) {
    result.errors.push(`L2 _sd contains a duplicate disclosure digest (RFC 9901 section 7.1): ${l2SdDup}`);
    return result;
  }

  // 4a3. L2 iat not in the future
  if (isFutureDated(l2.payload.iat, now, skew)) {
    result.errors.push(`L2 iat is in the future: ${String(l2.payload.iat)}`);
    return result;
  }
  // 4a4. L2 exp
  if (isExpired(l2.payload.exp, now, skew)) {
    result.errors.push(`L2 expired at ${String(l2.payload.exp)}`);
    return result;
  }

  // 4a5. L2 aud and nonce
  const l2Aud = l2.payload.aud;
  const l2Nonce = l2.payload.nonce;
  if (opts.expectedL2Aud !== undefined && opts.expectedL2Aud !== null) {
    if (l2Aud !== opts.expectedL2Aud) {
      result.errors.push(`L2 aud mismatch: expected '${opts.expectedL2Aud}', got '${String(l2Aud)}'`);
      return result;
    }
    result.checksPerformed.push('l2_aud');
  } else if (typeof l2Aud === 'string' && l2Aud) {
    result.checksSkipped.push('l2_aud (no expected value provided)');
  }
  if (opts.expectedL2Nonce !== undefined && opts.expectedL2Nonce !== null) {
    if (l2Nonce !== opts.expectedL2Nonce) {
      result.errors.push(`L2 nonce mismatch: expected '${opts.expectedL2Nonce}', got '${String(l2Nonce)}'`);
      return result;
    }
    result.checksPerformed.push('l2_nonce');
  } else if (typeof l2Nonce === 'string' && l2Nonce) {
    result.checksSkipped.push('l2_nonce (no expected value provided)');
  }

  result.l2Claims = await resolveDisclosures(l2);

  // 4a-mode. Infer execution mode from L2 mandate VCTs.
  const resolvedDelegatesForMode = result.l2Claims.delegate_payload;
  let hasOpenMandate = false;
  let hasFinalMandate = false;
  for (const item of asArray(resolvedDelegatesForMode)) {
    if (isJsonObject(item)) {
      const vct = item.vct ?? '';
      if (vct === L2_CHECKOUT_VCT_OPEN || vct === L2_PAYMENT_VCT_OPEN) hasOpenMandate = true;
      else if (vct === L2_CHECKOUT_VCT_FINAL || vct === L2_PAYMENT_VCT_FINAL) hasFinalMandate = true;
    }
  }
  if (hasOpenMandate && hasFinalMandate) {
    result.errors.push(
      'L2 contains both open (autonomous) and final (immediate) mandate VCTs — open mandates are not allowed in immediate mode',
    );
    return result;
  }
  const isAutonomous = hasOpenMandate;

  // 4a0. Validate L2 header typ now that we know the mode
  const expectedL2Typ = isAutonomous ? 'kb-sd-jwt+kb' : 'kb-sd-jwt';
  const l2HeaderErr = validateHeader(l2.header, 'L2', expectedL2Typ);
  if (l2HeaderErr) {
    result.errors.push(l2HeaderErr);
    return result;
  }

  // 4a-cross. Immediate L2 + L3 args is a caller error
  if (!isAutonomous && hasL3Args) {
    result.errors.push('L3 credentials provided but L2 contains only immediate-mode (final) mandates');
    return result;
  }

  // 4b. Extract and pair mandate disclosures
  const discStrByHash = new Map<string, string>();
  for (const ds of l2.disclosures) discStrByHash.set(await hashDisclosure(ds), ds);

  const rawDelegates = l2.payload.delegate_payload;
  if (!Array.isArray(rawDelegates)) {
    result.errors.push(`L2 delegate_payload must be a list, got ${rawDelegates === null ? 'null' : typeof rawDelegates}`);
    return result;
  }
  const resolvedDelegates = asArray(result.l2Claims.delegate_payload);

  for (const resolvedItem of resolvedDelegates) {
    if (isJsonObject(resolvedItem)) {
      const itemVct = resolvedItem.vct;
      if (typeof itemVct === 'string' && itemVct && !ALL_KNOWN_VCTS.has(itemVct)) {
        result.checksSkipped.push(`unrecognized_vct_in_delegate_payload: ${itemVct}`);
      }
    }
  }

  const { pairs: mandatePairs, errors: pairErrors } = extractMandatePairs(
    rawDelegates,
    resolvedDelegates,
    discStrByHash,
    isAutonomous,
  );
  if (pairErrors.length) {
    result.errors.push(...pairErrors);
    return result;
  }

  result.mandatePairCount = mandatePairs.length;
  const anyCheckout = mandatePairs.some((p) => p[0] !== null);
  const anyPayment = mandatePairs.some((p) => p[1] !== null);
  result.l2CheckoutDisclosed = anyCheckout;
  result.l2PaymentDisclosed = anyPayment;

  if (mandatePairs.length === 0) {
    result.errors.push('L2 delegate_payload resolved zero mandate disclosures');
    return result;
  }

  // 4b-bis. Surface network-enforced constraints (additive, informational).
  // The stateless verifier parses but never evaluates budget/recurrence — the
  // spec assigns them to the payment network — so expose them here to tell the
  // caller what it still must enforce. Collected from each pair's payment
  // mandate; does not affect any verdict, error, or other result field.
  for (const [pairIdx, pair] of mandatePairs.entries()) {
    const paymentInfo = pair[1];
    if (!paymentInfo) continue;
    for (const c of asArray(paymentInfo.resolved.constraints)) {
      if (isJsonObject(c) && NETWORK_ENFORCED_TYPES.has(c.type as KnownConstraintType)) {
        result.networkEnforced.push({ pairIndex: pairIdx, type: c.type as KnownConstraintType, constraint: c });
      }
    }
  }

  // 4c. Per-pair mandate validation
  for (const [pairIdx, pair] of mandatePairs.entries()) {
    const [checkoutInfo, paymentInfo] = pair;
    const checkoutMandate = checkoutInfo ? checkoutInfo.resolved : null;
    const paymentMandate = paymentInfo ? paymentInfo.resolved : null;
    const checkoutDiscB64 = checkoutInfo ? checkoutInfo.discB64 : null;
    let pairingKey = '';
    if (checkoutInfo && checkoutInfo.refHash) pairingKey = checkoutInfo.refHash;
    else if (paymentInfo && paymentInfo.refHash) pairingKey = paymentInfo.refHash;

    const pairResult = new MandatePairResult();
    pairResult.pairIndex = pairIdx;
    pairResult.pairingKey = pairingKey;
    pairResult.checkoutMandate = checkoutMandate ?? {};
    pairResult.paymentMandate = paymentMandate ?? {};

    const {
      errors: mpErrors,
      checksPerformed: mpChecks,
      checksSkipped: mpSkipped,
    } = await verifyMandatePair(checkoutMandate, paymentMandate, checkoutDiscB64, isAutonomous);
    pairResult.checksPerformed.push(...mpChecks);
    pairResult.checksSkipped.push(...mpSkipped);
    result.checksPerformed.push(...mpChecks);
    result.checksSkipped.push(...mpSkipped);

    if (mpErrors.length) {
      pairResult.errors.push(...mpErrors);
      result.errors.push(...mpErrors);
      result.pairResults.push(pairResult);
      return result;
    }
    result.pairResults.push(pairResult);
  }

  // 4c-bis. Optional card_id cross-check
  const l1CardId = l1.payload.card_id;
  if (l1CardId) {
    for (const pairResult of result.pairResults) {
      const pm = pairResult.paymentMandate;
      const pi = isJsonObject(pm) ? pm.payment_instrument : {};
      const piId = isJsonObject(pi) ? pi.id : null;
      if (piId && piId !== l1CardId) {
        result.checksPerformed.push('l1_card_id_cross_check');
        pairResult.checksPerformed.push('l1_card_id_cross_check');
        result.errors.push(`L1 card_id (${String(l1CardId)}) does not match payment_instrument.id (${String(piId)})`);
        return result;
      } else if (piId) {
        result.checksPerformed.push('l1_card_id_cross_check');
        pairResult.checksPerformed.push('l1_card_id_cross_check');
      } else {
        result.checksPerformed.push('l1_card_id_cross_check');
        pairResult.checksPerformed.push('l1_card_id_cross_check');
        result.errors.push(
          `L1 card_id (${String(l1CardId)}) present but payment_instrument.id is missing — cannot verify binding`,
        );
        return result;
      }
    }
  } else {
    result.checksSkipped.push('l1_card_id_cross_check');
  }

  // 4d. Autonomous mode: extract agent key and verify L3s
  if (isAutonomous) {
    if (!anyCheckout && !anyPayment) {
      result.errors.push(
        'Autonomous mode requires at least one L2 mandate disclosure to extract the agent delegation key (cnf.jwk)',
      );
      return result;
    }

    const { jwk: agentJwk, kid: agentKid, error: cnfError } = extractAgentKeyFromAllPairs(mandatePairs);
    if (cnfError) {
      result.errors.push(cnfError);
      return result;
    }
    if (!agentJwk) {
      result.errors.push('L2 mandates missing cnf.jwk for agent delegation');
      return result;
    }
    const agentJwkErr = validateEcPublicJwk(agentJwk);
    if (agentJwkErr) {
      result.errors.push(`L2 mandate cnf.jwk is malformed: ${agentJwkErr}`);
      return result;
    }

    let effectiveSplitL3s: SplitL3[];
    if (splitL3s !== null) {
      effectiveSplitL3s = splitL3s;
    } else if (l3Payment !== null || l3Checkout !== null) {
      effectiveSplitL3s = [
        {
          l3Payment,
          l3Checkout,
          l2PaymentSerialized: opts.l2PaymentSerialized ?? null,
          l2CheckoutSerialized: opts.l2CheckoutSerialized ?? null,
        },
      ];
    } else {
      effectiveSplitL3s = [];
    }

    if (effectiveSplitL3s.length && effectiveSplitL3s.length !== mandatePairs.length) {
      result.errors.push(
        `Split L3 count (${effectiveSplitL3s.length}) does not match mandate pair count (${mandatePairs.length})`,
      );
      return result;
    }

    for (const [pairIdx, l3p] of effectiveSplitL3s.entries()) {
      const pairResult = result.pairResults[pairIdx];
      const mandatePair = mandatePairs[pairIdx];
      // Indices are kept 1:1 (split-L3 count == pair count == pairResults count);
      // if that invariant is ever violated, fail closed rather than skip L3 checks.
      if (!pairResult || !mandatePair) {
        result.errors.push('Internal: split-L3 / mandate-pair index mismatch');
        return result;
      }
      const [checkoutInfo, paymentInfo] = mandatePair;
      const l2Pm = paymentInfo ? paymentInfo.resolved : null;

      const l3Specs = [
        {
          l3: l3p.l3Payment ?? null,
          label: 'L3a (payment)',
          serOverride: (l3p.l2PaymentSerialized ?? null) || (opts.l2PaymentSerialized ?? null),
          isPayment: true,
          requiredVct: L3_PAYMENT_VCT,
          expectedPairDisc: paymentInfo ? paymentInfo.discB64 : null,
        },
        {
          l3: l3p.l3Checkout ?? null,
          label: 'L3b (checkout)',
          serOverride: (l3p.l2CheckoutSerialized ?? null) || (opts.l2CheckoutSerialized ?? null),
          isPayment: false,
          requiredVct: L3_CHECKOUT_VCT,
          expectedPairDisc: checkoutInfo ? checkoutInfo.discB64 : null,
        },
      ];

      for (const spec of l3Specs) {
        const l3 = spec.l3;
        if (l3 === null) continue;
        const label = spec.label;

        if (!isJsonObject(l3.payload)) {
          result.errors.push(`${label} payload must be a JSON object, got ${typeof l3.payload}`);
          return result;
        }
        if ('cnf' in l3.payload) {
          result.errors.push(`${label} payload MUST NOT contain cnf claim`);
          return result;
        }
        if (!(await tryVerify(l3, agentJwk as Es256Jwk))) {
          result.errors.push(`${label} signature verification failed (agent key mismatch)`);
          return result;
        }
        const l3HeaderErr = validateHeader(l3.header, label, 'kb-sd-jwt');
        if (l3HeaderErr) {
          result.errors.push(l3HeaderErr);
          return result;
        }

        const l3L2Ser = spec.serOverride || opts.l2Serialized || l2.serialize();
        const actualSdHash = l3.payload.sd_hash ?? '';
        if (!actualSdHash) {
          result.errors.push(`${label} missing required sd_hash binding to L2`);
          return result;
        }
        if (actualSdHash !== (await hashAscii(l3L2Ser))) {
          result.errors.push(`${label} sd_hash does not match L2 serialized form`);
          return result;
        }

        // 5a-bind. L3 presentation must include the correct mandate pair's disclosure.
        if (spec.expectedPairDisc) {
          const segments = l3L2Ser.split('~');
          if (!segments.includes(spec.expectedPairDisc)) {
            result.errors.push(
              `${label} L2 presentation does not include mandate pair ${pairIdx} disclosure (L3-to-mandate-pair identity mismatch)`,
            );
            return result;
          }
          pairResult.checksPerformed.push(`pair_${pairIdx}_identity_binding`);
          result.checksPerformed.push(`pair_${pairIdx}_identity_binding`);
        }

        const l3SdAlg = l3.payload._sd_alg;
        if (l3SdAlg !== undefined && l3SdAlg !== null && l3SdAlg !== 'sha-256') {
          result.errors.push(`${label} _sd_alg must be 'sha-256', got '${String(l3SdAlg)}'`);
          return result;
        }

        const l3SdDup = duplicateSdDigest(l3.payload);
        if (l3SdDup !== null) {
          result.errors.push(`${label} _sd contains a duplicate disclosure digest (RFC 9901 section 7.1): ${l3SdDup}`);
          return result;
        }

        const l3Iat = l3.payload.iat;
        if (isFutureDated(l3Iat, now, skew)) {
          result.errors.push(`${label} iat is in the future: ${String(l3Iat)}`);
          return result;
        }
        const l3Exp = l3.payload.exp;
        if (isExpired(l3Exp, now, skew)) {
          result.errors.push(`${label} expired at ${String(l3Exp)}`);
          return result;
        }
        if (isFiniteNumber(l3Iat) && isFiniteNumber(l3Exp) && l3Exp - l3Iat > 3600) {
          result.errors.push(`${label} exp MUST NOT exceed 1 hour from iat`);
          return result;
        }

        const l3Aud = l3.payload.aud;
        const l3Nonce = l3.payload.nonce;
        const expAud = spec.isPayment ? opts.expectedL3PaymentAud : opts.expectedL3CheckoutAud;
        const expNonce = spec.isPayment ? opts.expectedL3PaymentNonce : opts.expectedL3CheckoutNonce;
        const l3Tag = label.toLowerCase().replace(/ /g, '_');
        if (expAud !== undefined && expAud !== null) {
          if (l3Aud !== expAud) {
            result.errors.push(`${label} aud mismatch: expected '${expAud}', got '${String(l3Aud)}'`);
            return result;
          }
          result.checksPerformed.push(`${l3Tag}_aud`);
        } else if (typeof l3Aud === 'string' && l3Aud) {
          result.checksSkipped.push(`${l3Tag}_aud (no expected value provided)`);
        }
        if (expNonce !== undefined && expNonce !== null) {
          if (l3Nonce !== expNonce) {
            result.errors.push(`${label} nonce mismatch: expected '${expNonce}', got '${String(l3Nonce)}'`);
            return result;
          }
          result.checksPerformed.push(`${l3Tag}_nonce`);
        } else if (typeof l3Nonce === 'string' && l3Nonce) {
          result.checksSkipped.push(`${l3Tag}_nonce (no expected value provided)`);
        }

        const l3HeaderKid = l3.header.kid;
        if (typeof l3HeaderKid !== 'string' || !l3HeaderKid) {
          result.errors.push(`${label} header missing required kid parameter`);
          return result;
        }
        if (agentKid !== null && l3HeaderKid !== agentKid) {
          result.errors.push(`${label} header kid '${l3HeaderKid}' does not match L2 cnf.jwk.kid '${agentKid}'`);
          return result;
        }

        const l3Claims = await resolveDisclosures(l3);
        if (spec.isPayment) pairResult.l3PaymentClaims = l3Claims;
        else pairResult.l3CheckoutClaims = l3Claims;

        const l3Err = validateL3MandateFields(l3Claims, label, spec.requiredVct, l2Pm);
        if (l3Err) {
          result.errors.push(l3Err);
          return result;
        }

        pairResult.checksPerformed.push(`${l3Tag}_structural_chain`);
        result.checksPerformed.push(`${l3Tag}_structural_chain`);
      }

      // 5b. Cross-reference check per pair
      if ((l3p.l3Payment ?? null) !== null && (l3p.l3Checkout ?? null) !== null) {
        const { valid: xrefValid, error: xrefError } = verifyL3CrossReference(
          pairResult.l3PaymentClaims,
          pairResult.l3CheckoutClaims,
        );
        if (!xrefValid) {
          result.errors.push(`L3 cross-reference check failed: ${xrefError}`);
          return result;
        }
        pairResult.checksPerformed.push('l3_cross_reference');
        result.checksPerformed.push('l3_cross_reference');
      } else if ((l3p.l3Payment ?? null) !== null || (l3p.l3Checkout ?? null) !== null) {
        pairResult.checksSkipped.push('l3_cross_reference (requires both L3a and L3b)');
        result.checksSkipped.push('l3_cross_reference (requires both L3a and L3b)');
      }
    }
  }

  // 6. Backward-compat: populate legacy fields from first pair
  const firstPair = result.pairResults[0];
  if (firstPair) {
    result.l3PaymentClaims = firstPair.l3PaymentClaims;
    result.l3CheckoutClaims = firstPair.l3CheckoutClaims;
  }

  result.valid = true;
  return result;
}

function isNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.trim() !== '';
}

function validatePaymentMandateRequiredFields(mandate: JsonObject, context: string): string | null {
  if (!isNonEmptyString(mandate.transaction_id)) return `${context} missing required field: transaction_id`;

  const payee = mandate.payee;
  if (payee === undefined || payee === null) return `${context} missing required field: payee`;
  if (!isJsonObject(payee)) return `${context} payee must be an object`;
  if (!isNonEmptyString(payee.name)) return `${context} payee missing required field: name`;
  if (!isNonEmptyString(payee.website)) return `${context} payee missing required field: website`;

  const paymentAmount = mandate.payment_amount;
  if (!isJsonObject(paymentAmount) || Object.keys(paymentAmount).length === 0) {
    return `${context} missing required field: payment_amount`;
  }
  if (!isNonEmptyString(paymentAmount.currency)) return `${context} payment_amount missing required field: currency`;
  const amount = paymentAmount.amount;
  if (amount === undefined || amount === null) return `${context} payment_amount missing required field: amount`;
  if (typeof amount === 'boolean' || !Number.isInteger(amount)) {
    return `${context} payment_amount field 'amount' must be an integer`;
  }

  const paymentInstrument = mandate.payment_instrument;
  if (paymentInstrument === undefined || paymentInstrument === null) {
    return `${context} missing required field: payment_instrument`;
  }
  if (!isJsonObject(paymentInstrument) || !isNonEmptyString(paymentInstrument.id) || !isNonEmptyString(paymentInstrument.type)) {
    return `${context} payment_instrument missing required field: id and type are required`;
  }
  return null;
}

function validateL3PaymentInstrument(l3Delegate: JsonObject, l2PaymentMandate: JsonObject | null, l3Label: string): string | null {
  if (!isJsonObject(l2PaymentMandate)) return null;
  const l2Pi = l2PaymentMandate.payment_instrument;
  if (!isJsonObject(l2Pi)) return null;
  const l3Pi = l3Delegate.payment_instrument;
  if (!isJsonObject(l3Pi)) return null;
  if (l3Pi.id !== l2Pi.id || l3Pi.type !== l2Pi.type) {
    return (
      `${l3Label} payment_instrument does not match L2 authorized value: ` +
      `L3 id=${String(l3Pi.id)}, type=${String(l3Pi.type)} vs L2 id=${String(l2Pi.id)}, type=${String(l2Pi.type)}`
    );
  }
  return null;
}

function validateL3MandateFields(
  l3Claims: JsonObject,
  l3Label: string,
  requiredVct: string,
  l2PaymentMandate: JsonObject | null,
): string | null {
  const delegates = asArray(l3Claims.delegate_payload);
  let foundRequiredVct = false;
  for (const delegate of delegates) {
    if (!isJsonObject(delegate)) continue;
    const vct = delegate.vct;
    if (vct === requiredVct) foundRequiredVct = true;
    if (vct === L3_PAYMENT_VCT) {
      const paymentFieldError = validatePaymentMandateRequiredFields(delegate, `${l3Label} payment mandate`);
      if (paymentFieldError) return paymentFieldError;
      const piErr = validateL3PaymentInstrument(delegate, l2PaymentMandate, l3Label);
      if (piErr) return piErr;
    } else if (vct === L3_CHECKOUT_VCT) {
      for (const reqField of ['checkout_jwt', 'checkout_hash']) {
        if (!delegate[reqField]) return `${l3Label} checkout mandate missing required field: ${reqField}`;
      }
    }
  }
  if (!foundRequiredVct) {
    if (requiredVct === L3_PAYMENT_VCT) return `${l3Label} missing required Layer 3 payment mandate disclosure: ${requiredVct}`;
    if (requiredVct === L3_CHECKOUT_VCT) return `${l3Label} missing required Layer 3 checkout mandate disclosure: ${requiredVct}`;
    return `${l3Label} missing required mandate disclosure: ${requiredVct}`;
  }
  return null;
}

function extractMandatePairs(
  rawDelegates: unknown[],
  resolvedDelegates: unknown[],
  discStrByHash: Map<string, string>,
  isAutonomous: boolean,
): MandatePairsResult {
  const checkouts: MandateInfo[] = [];
  const payments: MandateInfo[] = [];

  const seenRefs = new Set<string>();
  const n = Math.min(rawDelegates.length, resolvedDelegates.length);
  for (let i = 0; i < n; i++) {
    const rawItem = rawDelegates[i];
    const resolvedItem = resolvedDelegates[i];
    if (!isJsonObject(resolvedItem)) continue;
    const vct = (resolvedItem.vct as string) ?? '';
    const refHash = isJsonObject(rawItem) ? ((rawItem['...'] as string) ?? null) : null;

    if (refHash) {
      if (seenRefs.has(refHash)) {
        return { pairs: [], errors: ['L2 delegate_payload contains duplicate disclosure reference (mandate smuggling)'] };
      }
      seenRefs.add(refHash);
    }

    const discB64 = refHash ? (discStrByHash.get(refHash) ?? null) : null;
    const entry: MandateInfo = { resolved: resolvedItem, refHash, discB64 };

    if (CHECKOUT_VCTS.has(vct)) checkouts.push(entry);
    else if (PAYMENT_VCTS.has(vct)) payments.push(entry);
  }

  if (checkouts.length === 0 && payments.length === 0) {
    return { pairs: [], errors: ['L2 delegate_payload resolved zero mandate disclosures'] };
  }

  if (checkouts.length && payments.length) {
    return isAutonomous ? pairAutonomous(checkouts, payments) : pairImmediate(checkouts, payments);
  }

  if (!isAutonomous) {
    return { pairs: [], errors: ['Immediate mode requires both checkout and payment mandate disclosures'] };
  }

  const pairs: MandatePair[] = [];
  for (const c of checkouts) pairs.push([c, null]);
  for (const p of payments) pairs.push([null, p]);
  return { pairs, errors: [] };
}

function pairImmediate(checkouts: MandateInfo[], payments: MandateInfo[]): MandatePairsResult {
  const checkoutByHash = new Map<string, MandateInfo>();
  for (const c of checkouts) {
    if (c.resolved.vct === L2_CHECKOUT_VCT_OPEN) {
      return { pairs: [], errors: ['Immediate mode does not allow open checkout mandates (requires final values)'] };
    }
    const ch = (c.resolved.checkout_hash as string) ?? '';
    if (!ch) return { pairs: [], errors: ['Closed checkout mandate missing checkout_hash for pairing'] };
    if (checkoutByHash.has(ch)) {
      return { pairs: [], errors: ['L2 contains duplicate checkout mandates with same pairing key (checkout_hash collision)'] };
    }
    checkoutByHash.set(ch, c);
  }

  const paymentByTid = new Map<string, MandateInfo>();
  for (const p of payments) {
    if (p.resolved.vct === L2_PAYMENT_VCT_OPEN) {
      return { pairs: [], errors: ['Immediate mode does not allow open payment mandates (requires final values)'] };
    }
    const tid = (p.resolved.transaction_id as string) ?? '';
    if (!tid) return { pairs: [], errors: ['Closed payment mandate missing transaction_id for pairing'] };
    if (paymentByTid.has(tid)) {
      return { pairs: [], errors: ['L2 contains duplicate payment mandates with same pairing key (transaction_id collision)'] };
    }
    paymentByTid.set(tid, p);
  }

  const pairs: MandatePair[] = [];
  const matchedPayments = new Set<string>();
  for (const [ch, checkout] of checkoutByHash) {
    const payment = paymentByTid.get(ch);
    if (payment) {
      pairs.push([checkout, payment]);
      matchedPayments.add(ch);
    } else {
      return { pairs: [], errors: ['Orphaned checkout mandate: no payment mandate with matching transaction_id'] };
    }
  }
  for (const tid of paymentByTid.keys()) {
    if (!matchedPayments.has(tid)) {
      return { pairs: [], errors: ['Orphaned payment mandate: no checkout mandate with matching checkout_hash'] };
    }
  }
  return { pairs, errors: [] };
}

function pairAutonomous(checkouts: MandateInfo[], payments: MandateInfo[]): MandatePairsResult {
  const checkoutByRef = new Map<string, MandateInfo>();
  for (const c of checkouts) {
    if (!c.refHash) return { pairs: [], errors: ['Checkout mandate missing disclosure reference hash for pairing'] };
    if (checkoutByRef.has(c.refHash)) {
      return { pairs: [], errors: ['L2 contains duplicate checkout mandate disclosure references (pairing key collision)'] };
    }
    checkoutByRef.set(c.refHash, c);
  }

  const pairs: MandatePair[] = [];
  const matchedCheckouts = new Set<string>();
  for (const p of payments) {
    let refConstraint: JsonObject | null = null;
    for (const c of asArray(p.resolved.constraints)) {
      if (isJsonObject(c) && c.type === 'mandate.payment.reference') {
        refConstraint = c;
        break;
      }
    }
    if (refConstraint === null) {
      return { pairs: [], errors: ['Open payment mandate missing mandate.payment.reference constraint for pairing'] };
    }
    const condTid = (refConstraint.conditional_transaction_id as string) ?? '';
    if (!condTid) {
      return { pairs: [], errors: ['mandate.payment.reference constraint missing conditional_transaction_id for pairing'] };
    }
    if (matchedCheckouts.has(condTid)) {
      return { pairs: [], errors: ['L2 contains duplicate payment mandates referencing same checkout (pairing key collision)'] };
    }
    const checkout = checkoutByRef.get(condTid);
    if (checkout) {
      pairs.push([checkout, p]);
      matchedCheckouts.add(condTid);
    } else {
      return { pairs: [], errors: ['Orphaned payment mandate: conditional_transaction_id does not match any checkout disclosure'] };
    }
  }
  for (const refHash of checkoutByRef.keys()) {
    if (!matchedCheckouts.has(refHash)) {
      return { pairs: [], errors: ['Orphaned checkout mandate: no payment mandate references this checkout'] };
    }
  }
  return { pairs, errors: [] };
}

async function verifyMandatePair(
  checkoutMandate: JsonObject | null,
  paymentMandate: JsonObject | null,
  checkoutDiscB64: string | null,
  isAutonomous: boolean,
): Promise<MandatePairCheck> {
  const checksPerformed: string[] = [];
  const checksSkipped: string[] = [];
  const fail = (error: string): MandatePairCheck => ({ errors: [error], checksPerformed: [], checksSkipped: [] });

  if (checkoutMandate && checkoutMandate.vct === L2_CHECKOUT_VCT_OPEN) {
    const constraints = asArray(checkoutMandate.constraints);
    const hasLineItems = constraints.some((c) => isJsonObject(c) && c.type === 'mandate.checkout.line_items');
    if (!hasLineItems) return fail('Open checkout mandate must contain a mandate.checkout.line_items constraint');
    checksPerformed.push('open_checkout_contains_line_items');
  }

  if (paymentMandate && paymentMandate.vct === L2_PAYMENT_VCT_OPEN) {
    const constraints = asArray(paymentMandate.constraints);
    const hasReference = constraints.some((c) => isJsonObject(c) && c.type === 'mandate.payment.reference');
    if (!hasReference) return fail('Open payment mandate must contain a mandate.payment.reference constraint');
    const pi = paymentMandate.payment_instrument;
    if (!isJsonObject(pi) || !pi.id || !pi.type) {
      return fail('Open payment mandate missing required field: payment_instrument (must have id and type)');
    }
    checksPerformed.push('open_payment_has_payment_instrument');
    checksPerformed.push('open_payment_contains_reference');
  }

  if (!isAutonomous) {
    if (!checkoutMandate || !paymentMandate) {
      return fail('Immediate mode requires both checkout and payment mandate disclosures');
    }
    if (checkoutMandate.vct === L2_CHECKOUT_VCT_OPEN) {
      return fail('Immediate mode does not allow open checkout mandates (requires final values)');
    }
    if (paymentMandate.vct === L2_PAYMENT_VCT_OPEN) {
      return fail('Immediate mode does not allow open payment mandates (requires final values)');
    }
    for (const [mandate, label] of [
      [checkoutMandate, 'checkout'],
      [paymentMandate, 'payment'],
    ] as const) {
      if ('cnf' in mandate) {
        return fail(`Immediate mode ${label} mandate must not contain cnf claim (cnf is for autonomous delegation only)`);
      }
    }
    if (checkoutMandate.vct === L2_CHECKOUT_VCT_FINAL) {
      for (const reqField of ['checkout_jwt', 'checkout_hash']) {
        if (!checkoutMandate[reqField]) return fail(`Closed checkout mandate missing required field: ${reqField}`);
      }
      checksPerformed.push('closed_checkout_required_fields');
    }
    if (paymentMandate.vct === L2_PAYMENT_VCT_FINAL) {
      const paymentFieldError = validatePaymentMandateRequiredFields(paymentMandate, 'Closed payment mandate');
      if (paymentFieldError) return fail(paymentFieldError);
      checksPerformed.push('closed_payment_required_fields');
    }
    const { valid: bindingValid, error: bindingError } = await verifyCheckoutHashBinding(checkoutMandate, paymentMandate);
    if (!bindingValid) return fail(`L2 checkout-payment binding failed: ${bindingError}`);
    checksPerformed.push('l2_checkout_payment_binding');
  }

  if (isAutonomous) {
    if (checkoutMandate && paymentMandate) {
      if (!checkoutDiscB64) {
        return fail('L2 checkout mandate disclosure string is missing (required for reference binding verification)');
      }
      const { valid: bindingValid, error: bindingError } = await verifyL2ReferenceBinding(
        checkoutMandate,
        paymentMandate,
        checkoutDiscB64,
      );
      if (!bindingValid) return fail(`L2 reference binding failed: ${bindingError}`);
      checksPerformed.push('l2_reference_binding');
    } else {
      checksSkipped.push('l2_reference_binding (requires both checkout and payment mandates)');
    }
  }

  return { errors: [], checksPerformed, checksSkipped };
}

function extractAgentKeyFromAllPairs(mandatePairs: MandatePair[]): AgentKeyResult {
  const agentKeys: JsonObject[] = [];
  const agentKids: (string | null)[] = [];

  for (const [checkoutInfo, paymentInfo] of mandatePairs) {
    for (const [label, info, expectedVct] of [
      ['checkout', checkoutInfo, L2_CHECKOUT_VCT_OPEN],
      ['payment', paymentInfo, L2_PAYMENT_VCT_OPEN],
    ] as const) {
      if (info === null) continue;
      if (info.resolved.vct !== expectedVct) continue;
      const cnf = info.resolved.cnf;
      const jwk = isJsonObject(cnf) ? cnf.jwk : null;
      if (!isJsonObject(jwk) || Object.keys(jwk).length === 0) {
        return { jwk: null, kid: null, error: `L2 ${label} open mandate missing cnf.jwk for agent delegation` };
      }
      agentKeys.push(jwk);
      agentKids.push(typeof jwk.kid === 'string' ? jwk.kid : null);
    }
  }

  if (agentKeys.length === 0) return { jwk: null, kid: null, error: null };

  const [first, ...restKeys] = agentKeys;
  if (!first) return { jwk: null, kid: null, error: null };
  for (const other of restKeys) {
    if (other.x !== first.x || other.y !== first.y) {
      return { jwk: null, kid: null, error: 'L2 mandate cnf.jwk values must be identical across all pairs but differ' };
    }
  }

  const [firstKid, ...restKids] = agentKids.filter((k): k is string => k !== null);
  if (firstKid !== undefined) {
    for (const otherKid of restKids) {
      if (otherKid !== firstKid) {
        return { jwk: null, kid: null, error: 'L2 mandate cnf.jwk.kid values must be identical across all pairs but differ' };
      }
    }
    return { jwk: first, kid: firstKid, error: null };
  }
  return { jwk: first, kid: null, error: null };
}
