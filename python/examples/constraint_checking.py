"""Constraint checking: all v2 registered types + validation modes.

Demonstrates how the Network validates that an agent's fulfillment
(Layer 3) satisfies the user's constraints (Layer 2).

V2 constraint types (8 registered):
  - mandate.payment.amount_range (min/max integer cents)
  - mandate.payment.allowed_payees
  - mandate.checkout.allowed_merchants
  - mandate.checkout.line_items
  - mandate.payment.reference (conditional_transaction_id)
  - mandate.payment.budget (cumulative spend cap)
  - mandate.payment.recurrence (merchant-managed subscriptions)
  - mandate.payment.agent_recurrence (agent-managed recurring purchases)

Run: python examples/constraint_checking.py
"""

from __future__ import annotations

# Import helpers first — bootstraps sys.path for SDK imports.
from helpers import MERCHANTS, banner, error, step, success, visible
from verifiable_intent.verification.constraint_checker import (
    StrictnessMode,
    check_constraints,
)


def _show_result(label: str, result):
    if result.satisfied:
        visible(label, "SATISFIED")
    else:
        error(f"  {label}: VIOLATED")
        for v in result.violations:
            print(f"      - {v}")
    if result.skipped:
        print(f"      Skipped: {result.skipped}")


def main():
    banner("Constraint Checking — V2 Types")

    # ------------------------------------------------------------------
    # 1. mandate.payment.amount_range — min/max integer cents
    # ------------------------------------------------------------------
    step(1, "mandate.payment.amount_range — Per-transaction budget bounds (integer cents)")

    constraints = [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}]

    result_pass = check_constraints(
        constraints,
        {"payment_amount": {"amount": 27999, "currency": "USD"}},
    )
    _show_result("27999 cents within 10000-40000 budget", result_pass)
    assert result_pass.satisfied

    result_fail = check_constraints(
        constraints,
        {"payment_amount": {"amount": 45000, "currency": "USD"}},
    )
    _show_result("45000 cents exceeds 40000 max", result_fail)
    assert not result_fail.satisfied

    result_currency = check_constraints(
        constraints,
        {"payment_amount": {"amount": 27999, "currency": "EUR"}},
    )
    _show_result("27999 EUR vs USD budget (currency mismatch)", result_currency)
    assert not result_currency.satisfied

    result_below_min = check_constraints(
        constraints,
        {"payment_amount": {"amount": 5000, "currency": "USD"}},
    )
    _show_result("5000 cents below 10000 min", result_below_min)
    assert not result_below_min.satisfied

    # ------------------------------------------------------------------
    # 2. mandate.payment.allowed_payees
    # ------------------------------------------------------------------
    step(2, "mandate.payment.allowed_payees — Allowed payees")

    constraints = [
        {
            "type": "mandate.payment.allowed_payees",
            "allowed": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        }
    ]

    result_with = check_constraints(
        constraints,
        {
            "payee": {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            "allowed_merchants": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        },
    )
    _show_result("Payee matches allowed merchant", result_with)
    assert result_with.satisfied

    result_wrong = check_constraints(
        constraints,
        {
            "payee": {"id": "rogue-id", "name": "Rogue Shop", "website": "https://rogue.com"},
            "allowed_merchants": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        },
    )
    _show_result("Payee not in allowed list", result_wrong)
    assert not result_wrong.satisfied

    # ------------------------------------------------------------------
    # 3. mandate.checkout.allowed_merchants
    # ------------------------------------------------------------------
    step(3, "mandate.checkout.allowed_merchants — Merchant allowlist")

    constraints = [
        {
            "type": "mandate.checkout.allowed_merchantss",
            "allowed": MERCHANTS,
        }
    ]

    result_ok = check_constraints(constraints, {})
    _show_result("mandate.checkout.allowed_merchants (structural validation)", result_ok)

    # ------------------------------------------------------------------
    # 4. mandate.checkout.line_items
    # ------------------------------------------------------------------
    step(4, "mandate.checkout.line_items — Allowed products and quantities")

    line_item = {
        "id": "line-item-1",
        "acceptable_items": [{"id": "BAB86345", "title": "Babolat Pure Aero"}],
        "quantity": 1,
    }
    constraints = [{"type": "mandate.checkout.line_items", "items": [line_item]}]

    result_ok = check_constraints(constraints, {})
    _show_result("mandate.checkout.line_items (structural validation)", result_ok)

    # ------------------------------------------------------------------
    # 5. mandate.payment.reference — Cross-reference via checkout disclosure hash
    # ------------------------------------------------------------------
    step(5, "mandate.payment.reference — Cross-reference via conditional_transaction_id")

    constraints = [{"type": "mandate.payment.reference", "conditional_transaction_id": "abc123"}]
    result_ok = check_constraints(constraints, {})
    _show_result("mandate.payment.reference (binding checked via integrity layer)", result_ok)

    # ------------------------------------------------------------------
    # Strictness modes
    # ------------------------------------------------------------------
    step(6, "Strictness modes: PERMISSIVE vs STRICT")

    custom_constraints = [
        {"type": "mandate.payment.amount_range", "currency": "USD", "min": 0, "max": 50000},
        {"type": "urn:example:custom-loyalty-check", "loyaltyTier": "gold"},
    ]
    fulfillment = {"payment_amount": {"amount": 10000, "currency": "USD"}}

    result_permissive = check_constraints(
        custom_constraints,
        fulfillment,
        mode=StrictnessMode.PERMISSIVE,
    )
    _show_result("PERMISSIVE mode (unknown types skipped)", result_permissive)
    print(f"      Skipped types: {result_permissive.skipped}")

    result_strict = check_constraints(
        custom_constraints,
        fulfillment,
        mode=StrictnessMode.STRICT,
    )
    _show_result("STRICT mode (unknown types fail)", result_strict)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("""
  +----------------------------------------------------------------+
  |  V2 registered constraint types (8):                           |
  |  -----------------------------------                           |
  |  1. mandate.payment.amount_range               — Min/max cents              |
  |  2. mandate.payment.allowed_payees        — Payee allowlist            |
  |  3. mandate.checkout.allowed_merchants — Merchant list         |
  |  4. mandate.checkout.line_items  — Product constraints        |
  |  5. mandate.payment.reference            — Checkout cross-ref         |
  |  6. mandate.payment.budget       — Cumulative spend cap       |
  |  7. mandate.payment.recurrence   — Subscription setup         |
  |  8. mandate.payment.agent_recurrence — Agent recurring purchases |
  |                                                                |
  |  Extensible: Unknown types handled per strictness mode        |
  |  PERMISSIVE: skip + log   STRICT: reject                      |
  +----------------------------------------------------------------+
""")

    assert result_permissive.satisfied, "Permissive mode should skip unknown types"
    assert not result_strict.satisfied, "Strict mode should fail on unknown types"

    success("Constraint checking demo complete")

    return True


if __name__ == "__main__":
    main()
