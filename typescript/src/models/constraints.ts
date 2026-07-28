/** Constraint type definitions for autonomous-mode mandates.
 *
 * `toJSON()` preserves the exact key insertion order of the Python reference —
 * this is load-bearing for `sd_hash` and disclosure hashing.
 *
 * Parsing mirrors the Python reference exactly: `parseConstraint` stores each
 * known field's RAW value (no type coercion), just as Python's dataclass keeps
 * whatever `parse_constraint` puts in its kwargs. A present-but-wrongly-typed
 * field (e.g. a string `min`, a numeric `match_mode`) is preserved verbatim so
 * the runtime guards in the constraint checker reject it — rather than being
 * silently coerced to a default, which would fail open. The declared field
 * types describe the *intended* shape; at runtime a field may hold a raw value,
 * which the checker validates with `isInt`/`typeof` guards (the same way Python
 * dataclass annotations are not enforced at runtime).
 */

export type JsonObject = Record<string, unknown>;

/**
 * Compatibility alias for {@link JsonObject}. Downstream consumers (the AP2
 * TypeScript samples) import `Dict`; keep this exported until they migrate.
 */
export type Dict = JsonObject;

/**
 * RFC 7800 §3.1 confirmation object. Deliberately OPEN (index signature):
 * not-understood confirmation members MUST be ignored, so a closed/exact type
 * would reject inputs the RFC requires accepting. Layer rules (e.g. L1/L2
 * MUST contain `cnf.jwk`) are enforced at runtime by the verifier, not here.
 */
export interface CnfClaim {
  jwk?: JsonObject;
  kid?: string;
  jku?: string;
  jwe?: string;
  [member: string]: unknown;
}

// Apply a default only when the field is genuinely absent (`undefined`). A
// present `null` (or any other raw value) is preserved, matching Python's
// `kwargs[k] = v` for present keys vs. the dataclass default for absent keys.
const orDefault = <T>(v: unknown, dflt: T): T => (v !== undefined ? (v as T) : dflt);

/** Base constraint type. Unknown constraint types are preserved as-is. */
export class Constraint {
  type: string;
  extraFields: JsonObject;

  constructor(type = '', extraFields: JsonObject = {}) {
    this.type = type;
    this.extraFields = extraFields;
  }

  toJSON(): JsonObject {
    return { type: this.type, ...this.extraFields };
  }
}

export class AllowedMerchantConstraint extends Constraint {
  allowed: unknown[];

  constructor(opts: { allowed?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.checkout.allowed_merchants', opts.extraFields ?? {});
    this.allowed = orDefault(opts.allowed, [] as unknown[]);
  }

  override toJSON(): JsonObject {
    return { type: this.type, allowed: this.allowed, ...this.extraFields };
  }
}

export class CheckoutLineItemsConstraint extends Constraint {
  items: unknown[];
  matchMode: string;

  constructor(opts: { items?: unknown; matchMode?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.checkout.line_items', opts.extraFields ?? {});
    this.items = orDefault(opts.items, [] as unknown[]);
    this.matchMode = orDefault(opts.matchMode, 'minimum');
  }

  override toJSON(): JsonObject {
    return { type: this.type, items: this.items, match_mode: this.matchMode, ...this.extraFields };
  }
}

export class AllowedPayeeConstraint extends Constraint {
  allowed: unknown[];

  constructor(opts: { allowed?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.payment.allowed_payees', opts.extraFields ?? {});
    this.allowed = orDefault(opts.allowed, [] as unknown[]);
  }

  override toJSON(): JsonObject {
    return { type: this.type, allowed: this.allowed, ...this.extraFields };
  }
}

export class PaymentAmountConstraint extends Constraint {
  currency: string;
  min: number | null;
  max: number | null;

  constructor(opts: { currency?: unknown; min?: unknown; max?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.payment.amount_range', opts.extraFields ?? {});
    this.currency = orDefault(opts.currency, 'USD');
    this.min = orDefault(opts.min, null);
    this.max = orDefault(opts.max, null);
  }

  override toJSON(): JsonObject {
    const d: JsonObject = { type: this.type, currency: this.currency };
    if (this.min !== null) d.min = this.min;
    if (this.max !== null) d.max = this.max;
    return { ...d, ...this.extraFields };
  }
}

export class ReferenceConstraint extends Constraint {
  conditionalTransactionId: string;

  constructor(opts: { conditionalTransactionId?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.payment.reference', opts.extraFields ?? {});
    this.conditionalTransactionId = orDefault(opts.conditionalTransactionId, '');
  }

  override toJSON(): JsonObject {
    return { type: this.type, conditional_transaction_id: this.conditionalTransactionId, ...this.extraFields };
  }
}

export class PaymentBudgetConstraint extends Constraint {
  currency: string;
  max: number;
  min: number | null;

  constructor(opts: { currency?: unknown; max?: unknown; min?: unknown; extraFields?: JsonObject } = {}) {
    super('mandate.payment.budget', opts.extraFields ?? {});
    this.currency = orDefault(opts.currency, 'USD');
    this.max = orDefault(opts.max, 0);
    this.min = orDefault(opts.min, null);
    // Python raises in __post_init__ when max is not a positive integer; a
    // non-numeric raw max would raise a TypeError on comparison there, so we
    // reject it here too (parity: malformed budget is rejected, not coerced).
    if (typeof this.max !== 'number' || this.max <= 0) {
      throw new Error('PaymentBudgetConstraint.max must be a positive integer');
    }
    if (this.min !== null && (typeof this.min !== 'number' || this.min <= 0)) {
      throw new Error('PaymentBudgetConstraint.min must be a positive integer');
    }
  }

  override toJSON(): JsonObject {
    const d: JsonObject = { type: this.type, currency: this.currency, max: this.max };
    if (this.min !== null) d.min = this.min;
    return { ...d, ...this.extraFields };
  }
}

export class PaymentRecurrenceConstraint extends Constraint {
  frequency: string;
  startDate: string;
  endDate: string | null;
  number: number | null;

  constructor(
    opts: { frequency?: unknown; startDate?: unknown; endDate?: unknown; number?: unknown; extraFields?: JsonObject } = {},
  ) {
    super('mandate.payment.recurrence', opts.extraFields ?? {});
    this.frequency = orDefault(opts.frequency, '');
    this.startDate = orDefault(opts.startDate, '');
    this.endDate = orDefault(opts.endDate, null);
    this.number = orDefault(opts.number, null);
  }

  override toJSON(): JsonObject {
    const d: JsonObject = { type: this.type, frequency: this.frequency, start_date: this.startDate };
    if (this.endDate !== null) d.end_date = this.endDate;
    if (this.number !== null) d.number = this.number;
    return { ...d, ...this.extraFields };
  }
}

export class AgentRecurrenceConstraint extends Constraint {
  frequency: string;
  startDate: string;
  endDate: string;
  maxOccurrences: number | null;

  constructor(
    opts: { frequency?: unknown; startDate?: unknown; endDate?: unknown; maxOccurrences?: unknown; extraFields?: JsonObject } = {},
  ) {
    super('mandate.payment.agent_recurrence', opts.extraFields ?? {});
    this.frequency = orDefault(opts.frequency, '');
    this.startDate = orDefault(opts.startDate, '');
    this.endDate = orDefault(opts.endDate, '');
    this.maxOccurrences = orDefault(opts.maxOccurrences, null);
  }

  override toJSON(): JsonObject {
    const d: JsonObject = { type: this.type, frequency: this.frequency, start_date: this.startDate, end_date: this.endDate };
    if (this.maxOccurrences !== null) d.max_occurrences = this.maxOccurrences;
    return { ...d, ...this.extraFields };
  }
}

/**
 * The 8 constraint types registered in spec §6.2 (v0.1-draft). The registry
 * may grow (an IETF draft signals an `environment.*` family); unknown types
 * still parse to the base `Constraint` and are rejected by the checker's
 * fail-closed path, so this union constrains the REGISTRY keys — not inputs.
 */
export type KnownConstraintType =
  | 'mandate.checkout.allowed_merchants'
  | 'mandate.checkout.line_items'
  | 'mandate.payment.allowed_payees'
  | 'mandate.payment.amount_range'
  | 'mandate.payment.reference'
  | 'mandate.payment.budget'
  | 'mandate.payment.recurrence'
  | 'mandate.payment.agent_recurrence';

/** Union of the concrete constraint classes for the registered types. */
export type KnownConstraint =
  | AllowedMerchantConstraint
  | CheckoutLineItemsConstraint
  | AllowedPayeeConstraint
  | PaymentAmountConstraint
  | ReferenceConstraint
  | PaymentBudgetConstraint
  | PaymentRecurrenceConstraint
  | AgentRecurrenceConstraint;

function extraFieldsOf(obj: JsonObject, known: string[]): JsonObject {
  const extra: JsonObject = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === 'type' || known.includes(k)) continue;
    extra[k] = v;
  }
  return extra;
}

// Each factory passes the RAW field value straight through (no coercion). An
// absent key reads as `undefined`, which the constructor maps to the field's
// default; a present-but-wrong-type value is preserved so the checker rejects
// it — exactly matching Python's `parse_constraint`.
const REGISTRY: Record<KnownConstraintType, (o: JsonObject) => KnownConstraint> = {
  'mandate.checkout.allowed_merchants': (o) =>
    new AllowedMerchantConstraint({ allowed: o.allowed, extraFields: extraFieldsOf(o, ['allowed']) }),
  'mandate.checkout.line_items': (o) =>
    new CheckoutLineItemsConstraint({
      items: o.items,
      matchMode: o.match_mode,
      extraFields: extraFieldsOf(o, ['items', 'match_mode']),
    }),
  'mandate.payment.allowed_payees': (o) =>
    new AllowedPayeeConstraint({ allowed: o.allowed, extraFields: extraFieldsOf(o, ['allowed']) }),
  'mandate.payment.amount_range': (o) =>
    new PaymentAmountConstraint({
      currency: o.currency,
      min: o.min,
      max: o.max,
      extraFields: extraFieldsOf(o, ['currency', 'min', 'max']),
    }),
  'mandate.payment.reference': (o) =>
    new ReferenceConstraint({
      conditionalTransactionId: o.conditional_transaction_id,
      extraFields: extraFieldsOf(o, ['conditional_transaction_id']),
    }),
  'mandate.payment.budget': (o) =>
    new PaymentBudgetConstraint({
      currency: o.currency,
      max: o.max,
      min: o.min,
      extraFields: extraFieldsOf(o, ['currency', 'max', 'min']),
    }),
  'mandate.payment.recurrence': (o) =>
    new PaymentRecurrenceConstraint({
      frequency: o.frequency,
      startDate: o.start_date,
      endDate: o.end_date,
      number: o.number,
      extraFields: extraFieldsOf(o, ['frequency', 'start_date', 'end_date', 'number']),
    }),
  'mandate.payment.agent_recurrence': (o) =>
    new AgentRecurrenceConstraint({
      frequency: o.frequency,
      startDate: o.start_date,
      endDate: o.end_date,
      maxOccurrences: o.max_occurrences,
      extraFields: extraFieldsOf(o, ['frequency', 'start_date', 'end_date', 'max_occurrences']),
    }),
};

/** Parse a constraint object into the appropriate typed constraint. */
export function parseConstraint(data: unknown): Constraint {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    return new Constraint('unknown');
  }
  const obj = data as JsonObject;
  const ctype = typeof obj.type === 'string' ? obj.type : '';
  // Widen for the lookup: `ctype` is attacker-controlled and may be any string.
  const factory = (REGISTRY as Partial<Record<string, (o: JsonObject) => KnownConstraint>>)[ctype];
  if (!factory) {
    return new Constraint(ctype, extraFieldsOf(obj, []));
  }
  return factory(obj);
}
