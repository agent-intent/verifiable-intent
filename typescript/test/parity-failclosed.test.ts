/**
 * Regression tests for TS↔Python fail-closed parity.
 *
 * Each case is a malformed/edge input where the TypeScript verifier previously
 * "failed open" (accepted) while the Python reference "fails closed" (rejects).
 * These lock in that TS now rejects exactly what Python rejects. None of these
 * inputs is spec-conformant; a well-formed signed mandate is unaffected.
 */

import { describe, expect, it } from 'vitest';

import { checkConstraints, compactJson, parseConstraint } from '../src/index.js';

describe('parity: constraint checker fails closed on malformed input', () => {
  it('amount_range with string min does NOT bypass the bound (#1)', () => {
    const constraints = [{ type: 'mandate.payment.amount_range', currency: 'USD', min: '100', max: 1000 }];
    const fulfillment = { payment_amount: { amount: 50, currency: 'USD' } };
    const res = checkConstraints(constraints, fulfillment);
    expect(res.satisfied).toBe(false);
    expect(res.violations.some((v) => /min must be an integer/i.test(v))).toBe(true);
  });

  it('amount_range with string max does NOT bypass the bound (#1)', () => {
    const constraints = [{ type: 'mandate.payment.amount_range', currency: 'USD', max: '1000' }];
    const fulfillment = { payment_amount: { amount: 999999, currency: 'USD' } };
    const res = checkConstraints(constraints, fulfillment);
    expect(res.satisfied).toBe(false);
    expect(res.violations.some((v) => /max must be an integer/i.test(v))).toBe(true);
  });

  it('line_items with non-string match_mode is rejected, not coerced to minimum (#4)', () => {
    const constraints = [
      { type: 'mandate.checkout.line_items', match_mode: 123, items: [{ id: 'x', acceptable_items: [], quantity: 1 }] },
    ];
    const fulfillment = { line_items: [{ id: 'x', quantity: 1 }] };
    const res = checkConstraints(constraints, fulfillment);
    expect(res.satisfied).toBe(false);
    expect(res.violations.some((v) => /match_mode/i.test(v))).toBe(true);
  });

  it("present-but-null fulfillment currency fails the currency check (#3)", () => {
    const constraints = [{ type: 'mandate.payment.amount_range', currency: 'USD', min: 0, max: 100000 }];
    const fulfillment = { payment_amount: { amount: 500, currency: null } };
    const res = checkConstraints(constraints, fulfillment);
    expect(res.satisfied).toBe(false);
    expect(res.violations.some((v) => /Currency mismatch/i.test(v))).toBe(true);
  });

  it('present-but-null line item quantity is rejected as non-integer (#9)', () => {
    const constraints = [
      { type: 'mandate.checkout.line_items', match_mode: 'minimum', items: [{ id: 'x', acceptable_items: [], quantity: 5 }] },
    ];
    const fulfillment = { line_items: [{ id: 'x', quantity: null }] };
    const res = checkConstraints(constraints, fulfillment);
    expect(res.satisfied).toBe(false);
    expect(res.violations.some((v) => /quantity/i.test(v))).toBe(true);
  });
});

describe('parity: parseConstraint preserves raw values like Python (#6)', () => {
  it('keeps a wrongly-typed string min instead of dropping it', () => {
    const c = parseConstraint({ type: 'mandate.payment.amount_range', currency: 'USD', min: '100', max: 40000 });
    // Python preserves min: "100" verbatim in to_dict(); TS must not drop it.
    expect(c.toJSON()).toMatchObject({ min: '100', max: 40000 });
  });

  it('keeps a wrongly-typed numeric match_mode instead of reverting to "minimum"', () => {
    const c = parseConstraint({ type: 'mandate.checkout.line_items', items: [], match_mode: 5 });
    expect(c.toJSON()).toMatchObject({ match_mode: 5 });
  });
});

describe('parity: compactJson matches Python json.dumps number formatting (#2)', () => {
  it('serializes integers and ordinary decimals byte-identically to Python', () => {
    expect(compactJson({ amount: 27999, exp: 1700000000 })).toBe('{"amount":27999,"exp":1700000000}');
    // 279.99 and 1.5 render identically in JS and Python — must be preserved, not rejected.
    expect(compactJson({ price: 279.99 })).toBe('{"price":279.99}');
    expect(compactJson({ x: 1.5 })).toBe('{"x":1.5}');
  });

  it('throws only on numbers that would serialize differently from Python', () => {
    expect(() => compactJson({ n: 1e-7 })).toThrow(); // JS "1e-7" vs Python "1e-07"
    expect(() => compactJson({ n: 1e20 })).toThrow(); // JS "100000000000000000000" vs Python "1e+20"
    expect(() => compactJson({ n: Number.MAX_SAFE_INTEGER + 1 })).toThrow(); // precision loss
    expect(() => compactJson({ n: Infinity })).toThrow(); // not representable in JSON
  });
});
