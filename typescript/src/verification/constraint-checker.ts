/** Constraint validation: verify Layer 3 fulfillment values satisfy Layer 2 constraints. */

import {
  AgentRecurrenceConstraint,
  AllowedMerchantConstraint,
  AllowedPayeeConstraint,
  CheckoutLineItemsConstraint,
  PaymentAmountConstraint,
  PaymentBudgetConstraint,
  PaymentRecurrenceConstraint,
  parseConstraint,
  ReferenceConstraint,
} from '../models/constraints.js';
import type { JsonObject } from '../models/constraints.js';
import { isJsonObject } from '../internal/guards.js';

export const StrictnessMode = {
  PERMISSIVE: 'permissive', // skip unknown constraint types
  STRICT: 'strict', // fail on unknown constraint types
} as const;
export type StrictnessMode = (typeof StrictnessMode)[keyof typeof StrictnessMode];

export class ConstraintCheckResult {
  satisfied = true;
  violations: string[] = [];
  checked: string[] = [];
  skipped: string[] = [];
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);
const nonEmpty = (v: unknown): boolean => isJsonObject(v) && Object.keys(v).length > 0;
const truthy = (v: unknown): boolean => Boolean(v);

export interface CheckConstraintsOptions {
  mode?: StrictnessMode;
  isOpenMandate?: boolean;
  constraintPolicy?: Record<string, StrictnessMode>;
}

/** Check whether the fulfillment values satisfy all constraints. */
export function checkConstraints(
  constraints: unknown,
  fulfillment: unknown,
  opts: CheckConstraintsOptions = {},
): ConstraintCheckResult {
  const mode = opts.mode ?? StrictnessMode.PERMISSIVE;
  const isOpenMandate = opts.isOpenMandate ?? false;
  const constraintPolicy = opts.constraintPolicy;

  const result = new ConstraintCheckResult();

  if (!isJsonObject(fulfillment)) {
    result.satisfied = false;
    result.violations.push(`Fulfillment must be an object, got ${fulfillment === null ? 'null' : typeof fulfillment}`);
    return result;
  }
  if (!Array.isArray(constraints)) {
    result.satisfied = false;
    result.violations.push(`Constraints must be a list, got ${constraints === null ? 'null' : typeof constraints}`);
    return result;
  }

  for (const cData of constraints) {
    if (!isJsonObject(cData)) {
      result.satisfied = false;
      result.violations.push(`Constraint entry must be an object, got ${cData === null ? 'null' : typeof cData}`);
      continue;
    }
    const constraint = parseConstraint(cData);
    const ctype = constraint.type;

    if (constraint instanceof PaymentAmountConstraint) {
      checkPaymentAmount(constraint, fulfillment, result);
    } else if (constraint instanceof AllowedPayeeConstraint) {
      checkAllowedPayee(constraint, fulfillment, result);
    } else if (constraint instanceof AllowedMerchantConstraint) {
      checkAllowedMerchant(constraint, fulfillment, result);
    } else if (constraint instanceof CheckoutLineItemsConstraint) {
      checkLineItems(constraint, fulfillment, result);
    } else if (constraint instanceof ReferenceConstraint) {
      result.checked.push(ctype); // verified by the integrity module
    } else if (
      constraint instanceof PaymentBudgetConstraint ||
      constraint instanceof PaymentRecurrenceConstraint ||
      constraint instanceof AgentRecurrenceConstraint
    ) {
      result.checked.push(ctype); // network-enforced constraints
    } else {
      // Determine effective strictness: a per-type policy overrides the global mode.
      let effectiveMode = mode;
      const policyMode = constraintPolicy?.[ctype];
      if (policyMode !== undefined) {
        effectiveMode = policyMode;
      }
      // Fail closed on an unknown (hence unenforceable) constraint under STRICT, and
      // ALWAYS for an open mandate: an open mandate leaves the agent's authority
      // unbounded, so a constraint we cannot check must never be silently skipped.
      if (isOpenMandate || effectiveMode === StrictnessMode.STRICT) {
        result.satisfied = false;
        result.violations.push(`Unknown constraint type: ${ctype}`);
      } else {
        result.skipped.push(ctype);
      }
    }
  }

  return result;
}

/**
 * Match merchants: by id if both have it, else by name+website.
 *
 * Python uses `==` / `bool()`; this port uses `===` / `Boolean()`. For the
 * JSON-scalar identity fields (id, name, website) the two agree. Where they can
 * diverge — a non-primitive field (Python `==` compares objects by value, `===`
 * by reference) or JS treating `[]` / `{}` as truthy where `bool()` is falsy —
 * `===` can only FAIL a match that Python would make, never invent one (two
 * distinct parsed objects are never `===`, and that inequality short-circuits
 * before the truthiness guard matters). A non-match means "not in the allowlist",
 * so the caller fails closed: the translation stays equal-or-stricter than
 * Python here, never more permissive.
 */
function merchantMatches(candidate: unknown, target: unknown): boolean {
  if (!isJsonObject(candidate) || !isJsonObject(target)) return false;
  const cId = candidate.id;
  const tId = target.id;
  if (cId && tId) return cId === tId;
  return (
    candidate.name === target.name &&
    truthy(candidate.name) &&
    candidate.website === target.website &&
    truthy(candidate.website)
  );
}

/**
 * Check the payment amount is within min/max bounds (integer minor units).
 *
 * Per AP2 schema, L3a nests amount/currency under a payment_amount object.
 */
function checkPaymentAmount(c: PaymentAmountConstraint, fulfillment: JsonObject, result: ConstraintCheckResult): void {
  result.checked.push('mandate.payment.amount_range');
  const paymentAmount = fulfillment.payment_amount;
  if (!nonEmpty(paymentAmount)) {
    result.satisfied = false;
    result.violations.push('Missing or invalid payment_amount in fulfillment');
    return;
  }
  const amountRaw = (paymentAmount as JsonObject).amount;
  if (amountRaw === undefined || amountRaw === null) {
    result.satisfied = false;
    result.violations.push('Missing amount in fulfillment payment_amount');
    return;
  }
  if (typeof amountRaw === 'boolean' || !isInt(amountRaw)) {
    result.satisfied = false;
    result.violations.push(`Invalid amount: must be an integer, got ${typeof amountRaw}: ${JSON.stringify(amountRaw)}`);
    return;
  }
  const actual = amountRaw;

  if (c.min !== null) {
    if (typeof c.min === 'boolean' || !isInt(c.min)) {
      result.satisfied = false;
      result.violations.push(`Constraint min must be an integer, got ${typeof c.min}: ${JSON.stringify(c.min)}`);
      return;
    }
    if (actual < c.min) {
      result.satisfied = false;
      result.violations.push(`Amount below minimum: ${actual} < ${c.min} ${c.currency}`);
    }
  }

  if (c.max !== null) {
    if (typeof c.max === 'boolean' || !isInt(c.max)) {
      result.satisfied = false;
      result.violations.push(`Constraint max must be an integer, got ${typeof c.max}: ${JSON.stringify(c.max)}`);
      return;
    }
    if (actual > c.max) {
      result.satisfied = false;
      result.violations.push(`Amount exceeds maximum: ${actual} > ${c.max} ${c.currency}`);
    }
  }

  // Mirror Python's .get("currency", c.currency): substitute the constraint
  // currency only when the key is ABSENT. A present-but-null currency must be
  // compared (and fail), not defaulted.
  const pa = paymentAmount as JsonObject;
  const fulfillmentCurrency = 'currency' in pa ? pa.currency : c.currency;
  if (fulfillmentCurrency !== c.currency) {
    result.satisfied = false;
    result.violations.push(`Currency mismatch: expected ${c.currency}, got ${String(fulfillmentCurrency)}`);
  }
}

/**
 * Reduce a constraint `allowed` list to usable inline merchant objects: drop
 * SD-ref placeholders (entries carrying a "..." key) and any entry lacking both
 * an id and a name. Used only when the fulfillment did not supply resolved
 * allowed_merchants, i.e. the allowlist is inline rather than SD-referenced.
 */
function resolveAllowed(constraintAllowed: unknown[]): unknown[] {
  return constraintAllowed.filter((m) => isJsonObject(m) && !('...' in m) && (m.id || m.name));
}

// checkAllowedPayee and checkAllowedMerchant are near-duplicates, but they mirror
// two separate Python functions (_check_allowed_payee / _check_allowed_merchant)
// with distinct constraint types and error strings. They are kept separate — not
// factored into one helper — to preserve line-for-line parity with Python.
function checkAllowedPayee(c: AllowedPayeeConstraint, fulfillment: JsonObject, result: ConstraintCheckResult): void {
  result.checked.push('mandate.payment.allowed_payees');
  const payee = fulfillment.payee ?? {};
  if (!nonEmpty(payee)) {
    result.satisfied = false;
    result.violations.push('Missing or invalid payee in fulfillment');
    return;
  }
  if (!Array.isArray(c.allowed)) {
    result.satisfied = false;
    result.violations.push(`mandate.payment.allowed_payees 'allowed' must be a list, got ${typeof c.allowed}`);
    return;
  }
  if (c.allowed.length === 0) {
    result.satisfied = false;
    result.violations.push("mandate.payment.allowed_payees constraint missing required 'allowed' field");
    return;
  }

  // Check whether the payee matches any allowed merchant. In L2 `allowed` holds
  // SD disclosure refs; the resolved merchants should arrive via
  // fulfillment.allowed_merchants (matches Python dict.get("allowed_merchants", [])).
  let allowedMerchants: unknown[] = Array.isArray(fulfillment.allowed_merchants) ? fulfillment.allowed_merchants : [];
  let constraintAllowed: unknown[] = [];
  if (allowedMerchants.length === 0) {
    // Support inline allowlists when constraints are not represented as SD refs.
    constraintAllowed = Array.isArray(c.allowed) ? c.allowed : [];
    allowedMerchants = resolveAllowed(constraintAllowed);
  }
  if (allowedMerchants.length === 0) {
    // Distinguish: all SD refs → skip (unresolved, not a violation); inline
    // merchants that failed validation → fail closed.
    const source = constraintAllowed.length ? constraintAllowed : c.allowed;
    const allSdRefs = source.every((m) => isJsonObject(m) && '...' in m);
    if (allSdRefs) {
      result.checked.push('mandate.payment.allowed_payees (skipped: no resolved payees)');
      return;
    }
    result.satisfied = false;
    result.violations.push('allowed_payees constraint present but no payees resolved');
    return;
  }

  const found = allowedMerchants.some((m) => merchantMatches(m, payee));
  if (!found) {
    const p = payee as JsonObject;
    result.satisfied = false;
    result.violations.push(`Payee ${String(p.name ?? '')} (id=${String(p.id ?? '')}) not in allowed merchants`);
  }
}

function checkAllowedMerchant(c: AllowedMerchantConstraint, fulfillment: JsonObject, result: ConstraintCheckResult): void {
  result.checked.push('mandate.checkout.allowed_merchants');
  const merchant = fulfillment.merchant ?? {};
  if (!nonEmpty(merchant)) {
    result.satisfied = false;
    result.violations.push('Missing or invalid merchant in fulfillment');
    return;
  }
  if (!Array.isArray(c.allowed)) {
    result.satisfied = false;
    result.violations.push(`mandate.checkout.allowed_merchants 'allowed' must be a list, got ${typeof c.allowed}`);
    return;
  }
  if (c.allowed.length === 0) {
    result.satisfied = false;
    result.violations.push("mandate.checkout.allowed_merchants constraint missing required 'allowed' field");
    return;
  }

  let allowedMerchants: unknown[] = Array.isArray(fulfillment.allowed_merchants) ? fulfillment.allowed_merchants : [];
  let constraintMerchants: unknown[] = [];
  if (allowedMerchants.length === 0) {
    // Support inline allowlists when constraints are not represented as SD refs.
    constraintMerchants = Array.isArray(c.allowed) ? c.allowed : [];
    allowedMerchants = resolveAllowed(constraintMerchants);
  }
  if (allowedMerchants.length === 0) {
    // Distinguish: all SD refs → skip (unresolved, not a violation); inline
    // merchants that failed validation → fail closed.
    const source = constraintMerchants.length ? constraintMerchants : c.allowed;
    const allSdRefs = source.every((m) => isJsonObject(m) && '...' in m);
    if (allSdRefs) {
      result.checked.push('mandate.checkout.allowed_merchants (skipped: no resolved merchants)');
      return;
    }
    result.satisfied = false;
    result.violations.push('allowed_merchants constraint present but no merchants resolved');
    return;
  }

  const found = allowedMerchants.some((m) => merchantMatches(m, merchant));
  if (!found) {
    const m = merchant as JsonObject;
    result.satisfied = false;
    result.violations.push(`Merchant ${String(m.name ?? '')} (id=${String(m.id ?? '')}) not in allowed list`);
  }
}

/**
 * Check selected items match the line items constraint.
 *
 * items: list of {id, acceptable_items, quantity} — each defines an allowed
 * line item with its own product ID allowlist and quantity limit.
 */
function checkLineItems(c: CheckoutLineItemsConstraint, fulfillment: JsonObject, result: ConstraintCheckResult): void {
  result.checked.push('mandate.checkout.line_items');

  if (!c.items || c.items.length === 0) {
    // AP2 schema enforces minItems: 1 on line_items.items — an empty items list
    // is always a malformed constraint regardless of cart state.
    result.satisfied = false;
    result.violations.push('line_items constraint must have at least one item entry');
    return;
  }

  // L2-side schema validation: acceptable_items entries must have a title. This
  // runs regardless of whether line_items are present (constraint validity is
  // independent of fulfillment).
  const allowedIds = new Set<string>();
  const idQuantityLimits = new Map<string, number>(); // item id -> summed quantity cap across matching requirements
  let hasNonemptyAcceptable = false;
  let hasWildcardAcceptable = false;
  let totalQuantityLimit = 0;
  let hasQuantityLimit = false;

  for (const itemEntry of c.items) {
    if (!isJsonObject(itemEntry)) {
      result.satisfied = false;
      result.violations.push(`line_items item entry must be an object, got ${itemEntry === null ? 'null' : typeof itemEntry}`);
      continue;
    }

    const acceptableItems = itemEntry.acceptable_items;
    if (Array.isArray(acceptableItems) && acceptableItems.length > 0) hasNonemptyAcceptable = true;
    if (Array.isArray(acceptableItems) && acceptableItems.length === 0) hasWildcardAcceptable = true;

    const itemId = itemEntry.id;
    if (typeof itemId !== 'string' || !itemId) {
      result.satisfied = false;
      result.violations.push("line_items item entry missing required 'id' field");
      continue;
    }
    if (!('acceptable_items' in itemEntry)) {
      result.satisfied = false;
      result.violations.push(`line_items item '${itemId}' missing required 'acceptable_items' field`);
      continue;
    }

    const quantityRaw = itemEntry.quantity;
    if (typeof quantityRaw === 'boolean' || !isInt(quantityRaw)) {
      result.satisfied = false;
      result.violations.push(`line_items item quantity must be an integer, got ${JSON.stringify(quantityRaw)}`);
      continue;
    }
    const quantityLimit = quantityRaw;
    if (quantityLimit <= 0) {
      result.satisfied = false;
      result.violations.push('line_items item quantity must be positive');
      continue;
    }

    hasQuantityLimit = true;
    totalQuantityLimit += quantityLimit;

    if (!Array.isArray(acceptableItems)) {
      result.satisfied = false;
      result.violations.push('line_items acceptable_items must be an array');
      continue;
    }

    const itemIds = new Set<string>();
    for (const ai of acceptableItems) {
      if (isJsonObject(ai) && !('...' in ai)) {
        if (!ai.title) {
          result.satisfied = false;
          result.violations.push(`Item ${String(ai.id ?? '?')} in acceptable_items missing required 'title'`);
        }
        const itemIdVal = ai.id || ai.sku;
        if (itemIdVal && typeof itemIdVal === 'string') {
          itemIds.add(itemIdVal);
          allowedIds.add(itemIdVal);
        } else if (itemIdVal !== undefined && itemIdVal !== null && typeof itemIdVal !== 'string') {
          result.satisfied = false;
          result.violations.push(`acceptable_items entry has non-string id: ${typeof itemIdVal}`);
        }
      }
    }

    for (const itemIdVal of itemIds) {
      idQuantityLimits.set(itemIdVal, (idQuantityLimits.get(itemIdVal) ?? 0) + quantityLimit);
    }
  }

  // Fail-closed: constraint has non-empty acceptable_items, but none resolved to usable IDs.
  // Empty acceptable_items entries are wildcards and allow any item for that line-item requirement.
  if (hasNonemptyAcceptable && allowedIds.size === 0 && !hasWildcardAcceptable) {
    result.satisfied = false;
    result.violations.push('line_items constraint present but no item IDs resolved');
    return;
  }

  const lineItems = fulfillment.line_items;
  if (!Array.isArray(lineItems)) {
    result.satisfied = false;
    result.violations.push(`line_items must be a list, got ${lineItems === null ? 'null' : typeof lineItems}`);
    return;
  }
  if (lineItems.length === 0) {
    if (c.items.length > 0) {
      result.satisfied = false;
      result.violations.push('Empty line_items does not satisfy line_items constraint with required items');
    }
    return;
  }

  let totalQuantity = 0;
  const quantityById = new Map<string, number>();
  for (const lineItem of lineItems) {
    if (!isJsonObject(lineItem)) {
      result.satisfied = false;
      result.violations.push(`Line item must be an object, got ${lineItem === null ? 'null' : typeof lineItem}`);
      continue;
    }
    const itemIdVal = lineItem.id || lineItem.sku;
    if (!itemIdVal) {
      result.satisfied = false;
      result.violations.push("Line item missing 'id' field");
      continue;
    }
    if (typeof itemIdVal !== 'string') {
      result.satisfied = false;
      result.violations.push(`Line item 'id' must be a non-empty string, got ${typeof itemIdVal}: ${JSON.stringify(itemIdVal)}`);
      continue;
    }

    // Match Python's line_item.get("quantity", 0): default only when the key is
    // ABSENT. A present-but-null quantity must be rejected as a non-integer.
    const quantityRaw = 'quantity' in lineItem ? lineItem.quantity : 0;
    if (typeof quantityRaw === 'boolean' || !isInt(quantityRaw)) {
      result.satisfied = false;
      result.violations.push(`Invalid quantity for item ${itemIdVal}: ${JSON.stringify(quantityRaw)}`);
      continue;
    }
    const quantity = quantityRaw;
    if (quantity < 0) {
      result.satisfied = false;
      result.violations.push(`Negative quantity for item ${itemIdVal}: ${quantity}`);
      continue;
    }

    if (allowedIds.size > 0 && itemIdVal && !allowedIds.has(itemIdVal) && !hasWildcardAcceptable) {
      result.satisfied = false;
      result.violations.push(`Item ${itemIdVal} not in acceptable items: ${JSON.stringify([...allowedIds].sort())}`);
    }

    totalQuantity += quantity;
    if (itemIdVal) quantityById.set(itemIdVal, (quantityById.get(itemIdVal) ?? 0) + quantity);
  }

  // Aggregate quantity cap across all line-item requirements.
  if (hasQuantityLimit && totalQuantity > totalQuantityLimit) {
    result.satisfied = false;
    result.violations.push(`Total quantity ${totalQuantity} exceeds limit ${totalQuantityLimit}`);
  }

  // Per-item quantity caps derived from the line-item requirement -> acceptable ID mapping.
  for (const [itemIdVal, itemQty] of quantityById) {
    const idCap = idQuantityLimits.get(itemIdVal);
    if (idCap !== undefined && itemQty > idCap) {
      result.satisfied = false;
      result.violations.push(`Quantity for item ${itemIdVal} exceeds per-item limit ${idCap}`);
    }
  }

  // match_mode controls whether fulfillment may be a subset of the allowed
  // line-item requirements or must cover each requirement at least once.
  const matchMode = c.matchMode;
  if (typeof matchMode !== 'string' || (matchMode !== 'minimum' && matchMode !== 'exact')) {
    result.satisfied = false;
    result.violations.push(`line_items match_mode must be 'minimum' or 'exact', got ${JSON.stringify(matchMode)}`);
    return;
  }

  if (matchMode === 'exact') {
    const missingEntries: string[] = [];
    for (const itemEntry of c.items) {
      if (!isJsonObject(itemEntry)) continue;
      const acceptableItems = itemEntry.acceptable_items;
      if (!Array.isArray(acceptableItems) || acceptableItems.length === 0) continue;

      const entryId = itemEntry.id ?? '?';
      const resolvedIds = new Set<string>();
      for (const ai of acceptableItems) {
        if (isJsonObject(ai) && !('...' in ai)) {
          const id = ai.id || ai.sku;
          if (typeof id === 'string' && id) resolvedIds.add(id);
        }
      }
      if (resolvedIds.size > 0 && ![...resolvedIds].some((id) => (quantityById.get(id) ?? 0) > 0)) {
        missingEntries.push(`${String(entryId)}: ${JSON.stringify([...resolvedIds].sort())}`);
      }
    }
    if (missingEntries.length > 0) {
      result.satisfied = false;
      result.violations.push('match_mode=exact: fulfillment missing required line item(s): ' + missingEntries.join(', '));
    }
  }
}
