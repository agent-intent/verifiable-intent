# [RFC] Add `payment.cumulative` Constraint For Autonomous Mode

**Proposal Name**: `cumulative_spend`

## Summary

This RFC proposes a new payment constraint type, `payment.cumulative`, that limits
total spend over a defined period (for example, "at most $500 per month").

This document is a proposal only. It introduces no SDK or protocol implementation
changes in this PR.

## Primary Goal

The main goal is to improve payment safety by enabling:

- better payment auditing over time (not just per transaction),
- learning from payment patterns across periods,
- earlier risk reduction through cumulative-limit enforcement before overspend happens.

## Problem

Current constraints are strong for per-transaction control (`payment.amount`) and
some recurring patterns, but they do not provide a clear, standardized way to cap
aggregate spend over a period in common delegated-shopping scenarios.

Real-world examples:

- Parent delegates shopping to an agent but wants a monthly cap.
- User allows an assistant to buy sports equipment but limits monthly spend.
- Finance teams allow autonomous procurement with periodic spend ceilings.

Without an explicit cumulative cap, users risk a sequence of individually valid
transactions that exceed their intended budget.

## Proposed Solution

Define a new registered constraint type:

- **Type**: `payment.cumulative`
- **Purpose**: enforce a maximum cumulative spend in a configured period
- **Enforcement**: payment-network/stateful verifier

### Proposed JSON Schema

```json
{
  "type": "payment.cumulative",
  "max_total": 50000,
  "currency": "USD",
  "period": "MONTHLY"
}
```

Field semantics:

- `type` (string, required): MUST equal `payment.cumulative`
- `max_total` (integer, required): cumulative ceiling in minor units (e.g., cents)
- `currency` (string, required): ISO 4217 code
- `period` (string, required): one of `DAILY`, `WEEKLY`, `MONTHLY`, `YEARLY`

### Validation Semantics

Given the current transaction amount and relevant history in the selected period:

1. Ensure transaction amount is a valid non-negative integer.
2. Ensure transaction currency matches `currency`.
3. Fetch historical approved amounts for the same constraint scope and period.
4. Compute `new_total = sum(history) + current_amount`.
5. Reject when `new_total > max_total`; otherwise allow.

### Scope

The initial proposal targets a practical default scope:

- per delegated mandate context,
- optionally refined by payment instrument and/or merchant in implementation policy.

Future revisions may make scope explicit in schema if needed for interoperability.

## Security Considerations

- **Replay/rapid-fire attempts**: enforcement must be atomic to avoid race-condition bypass.
- **Fail-open risk**: unknown constraint handling should be strict in security-sensitive networks.
- **Currency mismatch**: mismatched currencies MUST fail rather than implicitly convert.
- **History integrity**: verifiers must trust and protect transaction history state.
- **Clock/period boundaries**: period bucketing and timezone policy must be deterministic.

## Implementation Plan (for a follow-up implementation PR)

Planned files/components:

1. `src/verifiable_intent/models/constraints.py`
   - add `CumulativeSpendConstraint`
   - add period enum
   - wire serialization (`to_dict`/`from_dict`)
   - register in constraint factory/registry
2. `src/verifiable_intent/verification/constraint_checker.py`
   - integrate `payment.cumulative` in `check_constraints`
   - evaluate with history callback or history list
3. `spec/constraints.md`
   - add normative section for `payment.cumulative`
   - include schema, algorithm, examples
4. Tests:
   - unit tests for constructor validation, parsing, and runtime validation
   - edge cases: empty history, missing amount, invalid period, currency mismatch
   - integration tests via `check_constraints`
5. Example:
   - add a flow demonstrating first transaction approval and second transaction rejection
     when total exceeds monthly cap

Dependencies:

- no new external dependency required; state lookup provided by host/payment network.

## Alternatives Considered

1. **Use only `payment.amount`**
   - insufficient for cumulative control over multiple transactions.
2. **Overload `payment.budget`**
   - can cap total spend, but does not clearly encode period semantics.
3. **Protocol-specific custom constraints only**
   - harms interoperability and cross-implementation consistency.

## Open Questions

1. Should scope be explicitly modeled in schema (GLOBAL vs MERCHANT vs PAYMENT_INSTRUMENT)?
2. How should multi-currency mandates be handled (reject vs convert with trusted FX)?
3. Should period reset semantics support both calendar and rolling windows?
4. Should timezone be explicit in this schema?
5. Should this supersede, complement, or remain distinct from `payment.budget`?

## Rollout Recommendation

- Land as RFC/proposal first.
- Gather feedback from verifier/payment-network implementers.
- Finalize schema and semantics.
- Implement in a separate feature PR with tests and examples.

## How This Upgrades Existing Code

This proposal improves the current constraint model by adding a missing control:
period-based cumulative spend limits. Today, per-transaction constraints can all
pass while aggregate spend still exceeds user intent. `payment.cumulative` closes
that gap with explicit stateful validation semantics.

Expected upgrade impact:

- Stronger delegated spending controls without changing the core 3-layer model.
- Better real-world policy coverage (parental controls, monthly shopping caps,
  assistant procurement limits).
- Cleaner interoperability than ad-hoc protocol-specific custom constraints.
- Clear verifier responsibility for history-backed, atomic cumulative checks.

## Implementation Snapshot (Reference Only)

The following reflects implementation work already prototyped in the local
workspace and can be used as input for a future implementation PR:

1. Model + parsing
   - Added `CumulativePeriod` and `CumulativeSpendConstraint` in
     `src/verifiable_intent/models/constraints.py`
   - Added serialization helpers and registry mapping for `payment.cumulative`
2. Verification pipeline
   - Added cumulative enforcement path in
     `src/verifiable_intent/verification/constraint_checker.py`
   - Added history-aware validation support (callback/list style)
3. Tests
   - Added focused tests in `tests/test_constraints.py`
   - Added integration coverage updates in `tests/test_new_constraints.py`
4. Spec + examples
   - Added normative constraint section in `spec/constraints.md`
   - Added runnable demo `examples/autonomous_flow2.py` showing second purchase
     rejection when monthly total exceeds limit

Important for this RFC PR: keep the PR proposal-only by including only this
document and excluding SDK/spec/test/example code changes.
