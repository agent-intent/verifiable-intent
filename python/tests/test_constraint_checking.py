"""Tests for constraint checking: payment.amount, allowed_payee, strictness modes (v2)."""

from __future__ import annotations

from verifiable_intent.verification.constraint_checker import StrictnessMode, check_constraints


def test_constraint_checker_payment_amount_pass():
    """Amount within min/max range passes."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
        {"payment_amount": {"amount": 27999, "currency": "USD"}},
    )
    assert result.satisfied
    assert not result.violations


def test_constraint_checker_payment_amount_fail_over():
    """Amount exceeding max fails."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 20000}],
        {"payment_amount": {"amount": 27999, "currency": "USD"}},
    )
    assert not result.satisfied
    assert any("exceeds" in v.lower() or "maximum" in v.lower() for v in result.violations)


def test_constraint_checker_payment_amount_fail_under():
    """Amount below min fails."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 30000, "max": 40000}],
        {"payment_amount": {"amount": 27999, "currency": "USD"}},
    )
    assert not result.satisfied
    assert any("below" in v.lower() or "minimum" in v.lower() for v in result.violations)


def test_constraint_checker_unknown_type_permissive():
    """Unknown constraint type is skipped in permissive mode."""
    result = check_constraints(
        [{"type": "urn:example:custom-constraint", "value": "test"}],
        {},
        mode=StrictnessMode.PERMISSIVE,
    )
    assert result.satisfied
    assert "urn:example:custom-constraint" in result.skipped


def test_constraint_checker_unknown_type_strict():
    """Unknown constraint type fails in strict mode."""
    result = check_constraints(
        [{"type": "urn:example:custom-constraint", "value": "test"}],
        {},
        mode=StrictnessMode.STRICT,
    )
    assert not result.satisfied
    assert any("unknown" in v.lower() for v in result.violations)


def test_unknown_constraint_rejected_for_open_mandate_permissive():
    """Unknown constraint in open mandate is rejected even in PERMISSIVE mode (Finding 1)."""
    result = check_constraints(
        [{"type": "urn:example:custom-constraint", "value": "test"}],
        {},
        mode=StrictnessMode.PERMISSIVE,
        is_open_mandate=True,
    )
    assert not result.satisfied
    assert any("unknown" in v.lower() for v in result.violations)
    assert "urn:example:custom-constraint" not in result.skipped


def test_unknown_constraint_rejected_for_open_mandate_strict():
    """Unknown constraint in open mandate is rejected in STRICT mode (Finding 1)."""
    result = check_constraints(
        [{"type": "urn:example:custom-constraint", "value": "test"}],
        {},
        mode=StrictnessMode.STRICT,
        is_open_mandate=True,
    )
    assert not result.satisfied
    assert any("unknown" in v.lower() for v in result.violations)


def test_unknown_constraint_skipped_for_closed_mandate_permissive():
    """Unknown constraint in closed mandate is still skipped in PERMISSIVE (backward compat)."""
    result = check_constraints(
        [{"type": "urn:example:custom-constraint", "value": "test"}],
        {},
        mode=StrictnessMode.PERMISSIVE,
        is_open_mandate=False,
    )
    assert result.satisfied
    assert "urn:example:custom-constraint" in result.skipped


def test_constraint_checker_payment_amount_missing_fulfillment():
    """Payment amount constraint fails when fulfillment omits amount."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
        {},
    )
    assert not result.satisfied
    assert any("missing" in v.lower() for v in result.violations)


def test_constraint_checker_currency_mismatch():
    """Payment amount constraint fails when currency doesn't match."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
        {"payment_amount": {"amount": 27999, "currency": "EUR"}},
    )
    assert not result.satisfied
    assert any("currency" in v.lower() for v in result.violations)


def test_constraint_checker_payment_amount_invalid_format():
    """Malformed amount value should produce violation, not exception."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
        {"payment_amount": {"amount": "not-a-number", "currency": "USD"}},
    )
    assert not result.satisfied
    assert any("invalid amount" in v.lower() for v in result.violations)


# ---------------------------------------------------------------------------
# mandate.checkout.line_items constraint tests (Findings 2, 3)
# ---------------------------------------------------------------------------


def _line_items_constraint(acceptable_items, quantity):
    """Build a mandate.checkout.line_items constraint dict."""
    return {
        "type": "mandate.checkout.line_items",
        "items": [{"id": "line-item-1", "acceptable_items": acceptable_items, "quantity": quantity}],
    }


def test_line_items_valid_id():
    """Line item with allowed ID passes."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 2)],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert result.satisfied, f"Should pass: {result.violations}"


def test_line_items_invalid_id():
    """Line item with disallowed ID fails."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 2)],
        {"line_items": [{"id": "UNKNOWN-SKU", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("UNKNOWN-SKU" in v for v in result.violations)


def test_line_items_quantity_total():
    """Total quantity across items exceeds limit fails."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 1)],
        {"line_items": [{"id": "BAB86345", "quantity": 2}]},
    )
    assert not result.satisfied
    assert any("total quantity" in v.lower() for v in result.violations)


def test_line_items_quantity_per_item_ok_total_exceeds():
    """Each line under limit individually but total over fails."""
    result = check_constraints(
        [
            _line_items_constraint(
                [
                    {"id": "BAB86345", "title": "Babolat Pure Aero"},
                    {"id": "HEA23102", "title": "Head Graphene 360 Speed"},
                ],
                2,
            )
        ],
        {
            "line_items": [
                {"id": "BAB86345", "quantity": 1},
                {"id": "HEA23102", "quantity": 2},
            ]
        },
    )
    assert not result.satisfied
    assert any("total quantity" in v.lower() for v in result.violations)


def test_line_items_empty_acceptable_items():
    """No acceptable_items means any ID allowed (spec §4.2 step 2)."""
    result = check_constraints(
        [_line_items_constraint([], 5)],
        {"line_items": [{"id": "ANY-ID", "quantity": 1}]},
    )
    assert result.satisfied, f"Should pass with empty acceptable_items: {result.violations}"


def test_line_items_empty_items_list_fails():
    """Constraint with empty items list must fail structural validation."""
    result = check_constraints(
        [{"type": "mandate.checkout.line_items", "items": []}],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("at least one item entry" in v.lower() for v in result.violations)


def test_line_items_quantity_must_be_positive():
    """Each line-item requirement quantity must be a positive integer."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 0)],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("must be positive" in v.lower() for v in result.violations)


def test_line_items_per_sku_quantity_limit_enforced():
    """Per-SKU cap must fail even when aggregate total quantity is within limits."""
    result = check_constraints(
        [
            {
                "type": "mandate.checkout.line_items",
                "items": [
                    {"id": "line-a", "acceptable_items": [{"id": "A", "title": "Item A"}], "quantity": 1},
                    {"id": "line-b", "acceptable_items": [{"id": "B", "title": "Item B"}], "quantity": 5},
                ],
            }
        ],
        {"line_items": [{"id": "A", "quantity": 2}, {"id": "B", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("per-item limit" in v.lower() and "item a" in v.lower() for v in result.violations)


def test_line_items_overlapping_sku_quantity_limits():
    """Overlapping requirement mappings for the same SKU should accumulate caps."""
    constraints = [
        {
            "type": "mandate.checkout.line_items",
            "items": [
                {"id": "line-1", "acceptable_items": [{"id": "A", "title": "Item A"}], "quantity": 1},
                {"id": "line-2", "acceptable_items": [{"id": "A", "title": "Item A"}], "quantity": 2},
            ],
        }
    ]
    ok = check_constraints(constraints, {"line_items": [{"id": "A", "quantity": 3}]})
    assert ok.satisfied, f"Overlapping ID caps should accumulate: {ok.violations}"

    too_many = check_constraints(constraints, {"line_items": [{"id": "A", "quantity": 4}]})
    assert not too_many.satisfied
    assert any("per-item limit" in v.lower() for v in too_many.violations)


def test_line_items_no_line_items():
    """Empty line_items must fail when constraint has required items."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 1)],
        {"line_items": []},
    )
    assert not result.satisfied
    assert any("empty" in v.lower() for v in result.violations)


def test_line_items_invalid_quantity_type():
    """Non-numeric quantity should produce violation, not exception."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 2)],
        {"line_items": [{"id": "BAB86345", "quantity": "oops"}]},
    )
    assert not result.satisfied
    assert any("invalid quantity" in v.lower() for v in result.violations)


# ---------------------------------------------------------------------------
# Quality Review Round 2: WS3 hardening tests
# ---------------------------------------------------------------------------


def test_payment_amount_float_rejected():
    """Float amount must be rejected, not silently truncated (P1-C7)."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
        {"payment_amount": {"amount": 10000.9, "currency": "USD"}},
    )
    assert not result.satisfied
    assert any("invalid amount" in v.lower() for v in result.violations)


def test_payment_amount_bool_rejected():
    """Boolean amount must be rejected (P1-C7)."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 0, "max": 40000}],
        {"payment_amount": {"amount": True, "currency": "USD"}},
    )
    assert not result.satisfied
    assert any("invalid amount" in v.lower() for v in result.violations)


def test_payment_amount_zero_valid():
    """Amount=0 must pass required-field presence/type checks (regression)."""
    result = check_constraints(
        [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 0, "max": 40000}],
        {"payment_amount": {"amount": 0, "currency": "USD"}},
    )
    assert result.satisfied, f"amount=0 should be valid: {result.violations}"


def test_line_items_constraint_quantity_float_rejected():
    """Float quantity in constraint must be rejected (P1-C7)."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 1.5)],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("integer" in v.lower() for v in result.violations)


def test_line_items_cart_quantity_bool_rejected():
    """Boolean line_items quantity must be rejected (P1-C7)."""
    result = check_constraints(
        [_line_items_constraint([{"id": "BAB86345", "title": "Babolat Pure Aero"}], 2)],
        {"line_items": [{"id": "BAB86345", "quantity": True}]},
    )
    assert not result.satisfied
    assert any("invalid quantity" in v.lower() for v in result.violations)


def test_allowed_payee_none_allowed_fails_closed():
    """AllowedPayeeConstraint with allowed_payees=None fails cleanly (P1-C6)."""
    # Pass dict without allowed_payees key to simulate malformed constraint
    result = check_constraints(
        [{"type": "mandate.payment.allowed_payees"}],
        {"payee": {"id": "merchant-1", "name": "Test"}},
    )
    assert not result.satisfied
    assert any("allowed_payees" in v.lower() for v in result.violations)


def test_allowed_merchant_none_merchants_fails_closed():
    """AllowedMerchantConstraint with allowed_merchants=None fails cleanly (P1-C6)."""
    result = check_constraints(
        [{"type": "mandate.checkout.allowed_merchants", "allowed": []}],
        {"merchant": {"id": "merchant-1", "name": "Test"}},
    )
    # With empty allowed_merchants list, should fail with missing 'allowed_merchants' field error
    assert not result.satisfied
    assert any("allowed_merchants" in v.lower() for v in result.violations)


def test_line_items_missing_id_rejected():
    """Item entry without 'id' field must be rejected (P1-C5)."""
    result = check_constraints(
        [
            {
                "type": "mandate.checkout.line_items",
                "items": [{"acceptable_items": [{"id": "BAB86345", "title": "Test"}], "quantity": 1}],
            }
        ],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("missing required 'id'" in v.lower() for v in result.violations)


def test_line_items_missing_acceptable_items_rejected():
    """Item entry without 'acceptable_items' field must be rejected (P1-C5)."""
    result = check_constraints(
        [{"type": "mandate.checkout.line_items", "items": [{"id": "line-1", "quantity": 1}]}],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("missing required 'acceptable_items'" in v.lower() for v in result.violations)


def test_check_constraints_none_constraints():
    """None constraints returns clean error (P2-4)."""
    result = check_constraints(None, {"payment_amount": {"amount": 27999, "currency": "USD"}})
    assert not result.satisfied
    assert any("constraints must be a list" in v.lower() for v in result.violations)


def test_es256_signature_length_validation():
    """ES256 rejects non-canonical signature lengths (P1-C4)."""
    from verifiable_intent.crypto.signing import es256_sign, es256_verify, generate_es256_key

    key = generate_es256_key()
    payload = b"test payload"
    valid_sig = es256_sign(payload, key)

    # Valid 64-byte signature
    assert es256_verify(payload, valid_sig, key.public_key())

    # 63-byte signature (truncated)
    assert not es256_verify(payload, valid_sig[:63], key.public_key())

    # 65-byte signature (extended)
    assert not es256_verify(payload, valid_sig + b"\x00", key.public_key())


# ---------------------------------------------------------------------------
# constraint_policy (§2F): per-constraint-type strictness overrides
# ---------------------------------------------------------------------------


def test_constraint_policy_permissive_override_skips_unknown():
    """Permissive global + permissive override for this type → unknown is skipped."""
    result = check_constraints(
        [{"type": "urn:example:custom", "value": "x"}],
        {},
        mode=StrictnessMode.PERMISSIVE,
        constraint_policy={"urn:example:custom": StrictnessMode.PERMISSIVE},
    )
    assert result.satisfied
    assert "urn:example:custom" in result.skipped


def test_constraint_policy_strict_override_rejects_unknown():
    """Permissive global + strict override for this type → unknown is rejected."""
    result = check_constraints(
        [{"type": "urn:example:custom", "value": "x"}],
        {},
        mode=StrictnessMode.PERMISSIVE,
        constraint_policy={"urn:example:custom": StrictnessMode.STRICT},
    )
    assert not result.satisfied
    assert any("unknown" in v.lower() for v in result.violations)


def test_constraint_policy_permissive_override_relaxes_strict_global():
    """Strict global + permissive override for this type → unknown is skipped."""
    result = check_constraints(
        [{"type": "urn:example:custom", "value": "x"}],
        {},
        mode=StrictnessMode.STRICT,
        constraint_policy={"urn:example:custom": StrictnessMode.PERMISSIVE},
    )
    assert result.satisfied
    assert "urn:example:custom" in result.skipped


def test_constraint_policy_strict_global_rejects_without_override():
    """Strict global + no override → unknown constraint rejected (existing behavior)."""
    result = check_constraints(
        [{"type": "urn:example:custom", "value": "x"}],
        {},
        mode=StrictnessMode.STRICT,
    )
    assert not result.satisfied
    assert any("unknown" in v.lower() for v in result.violations)


def test_constraint_policy_mixed_per_type():
    """Two unknown types with different per-type policies behave independently."""
    result = check_constraints(
        [
            {"type": "urn:example:one", "value": 1},
            {"type": "urn:example:two", "value": 2},
        ],
        {},
        mode=StrictnessMode.PERMISSIVE,
        constraint_policy={
            "urn:example:one": StrictnessMode.PERMISSIVE,
            "urn:example:two": StrictnessMode.STRICT,
        },
    )
    assert not result.satisfied
    # One is skipped, two is rejected
    assert "urn:example:one" in result.skipped
    assert any("urn:example:two" in v for v in result.violations)


# ---------------------------------------------------------------------------
# match_mode (§2G): exact vs minimum matching for line_items
# ---------------------------------------------------------------------------


def _line_items_constraint_v2(items, match_mode="minimum"):
    return {
        "type": "mandate.checkout.line_items",
        "items": items,
        "match_mode": match_mode,
    }


def _item(item_id, quantity=1, acceptable=None):
    """Build a line-item requirement with an acceptable_items allowlist."""
    if acceptable is None:
        acceptable = [{"id": item_id, "title": f"{item_id} product"}]
    return {"id": f"line-{item_id}", "acceptable_items": acceptable, "quantity": quantity}


def test_match_mode_minimum_subset_passes():
    """Default (minimum) mode: fulfillment with a subset of allowed items passes."""
    constraint = _line_items_constraint_v2([_item("ALPHA", quantity=2), _item("BETA", quantity=1)])
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert result.satisfied, result.violations


def test_match_mode_exact_fulfillment_matches_passes():
    """Exact mode: fulfillment containing every allowed item passes."""
    constraint = _line_items_constraint_v2(
        [_item("ALPHA", quantity=1), _item("BETA", quantity=1)],
        match_mode="exact",
    )
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}, {"id": "BETA", "quantity": 1}]},
    )
    assert result.satisfied, result.violations


def test_match_mode_exact_missing_item_fails():
    """Exact mode: fulfillment missing a required item fails."""
    constraint = _line_items_constraint_v2(
        [_item("ALPHA", quantity=1), _item("BETA", quantity=1)],
        match_mode="exact",
    )
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("match_mode=exact" in v for v in result.violations)


def test_match_mode_exact_satisfies_entry_with_one_of_multiple_acceptable_items():
    """Exact mode is satisfied when each line-item entry is fulfilled by any acceptable item."""
    constraint = _line_items_constraint_v2(
        [
            _item(
                "ALPHA",
                quantity=1,
                acceptable=[
                    {"id": "ALPHA", "title": "Alpha product"},
                    {"id": "BETA", "title": "Beta product"},
                ],
            )
        ],
        match_mode="exact",
    )
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert result.satisfied, result.violations


def test_match_mode_exact_extra_item_fails():
    """Exact mode: fulfillment containing items outside the allowlist fails
    (this is already handled by the subset check)."""
    constraint = _line_items_constraint_v2(
        [_item("ALPHA", quantity=1)],
        match_mode="exact",
    )
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}, {"id": "GAMMA", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("not in acceptable items" in v for v in result.violations)


def test_match_mode_invalid_value_fails_closed():
    """Unknown match_mode values must be violations, not silent minimum-mode fallback."""
    constraint = _line_items_constraint_v2([_item("ALPHA", quantity=1)], match_mode="strict")
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("match_mode must be" in v for v in result.violations)


def test_match_mode_empty_string_fails_closed():
    """Empty-string match_mode is invalid."""
    constraint = _line_items_constraint_v2([_item("ALPHA", quantity=1)], match_mode="")
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("match_mode must be" in v for v in result.violations)


def test_match_mode_non_string_fails_closed():
    """Non-string match_mode values are invalid."""
    constraint = {"type": "mandate.checkout.line_items", "items": [_item("ALPHA", quantity=1)], "match_mode": 7}
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert not result.satisfied
    assert any("match_mode must be" in v for v in result.violations)


def test_match_mode_minimum_missing_item_passes():
    """Minimum mode: fulfillment missing an allowed item still passes (unlike exact)."""
    constraint = _line_items_constraint_v2(
        [_item("ALPHA", quantity=1), _item("BETA", quantity=1)],
        match_mode="minimum",
    )
    result = check_constraints(
        [constraint],
        {"line_items": [{"id": "ALPHA", "quantity": 1}]},
    )
    assert result.satisfied, result.violations
