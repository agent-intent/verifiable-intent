"""Tests for Round 4 review fixes."""

from __future__ import annotations

import time

from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    get_agent_keys,
    get_issuer_keys,
    get_user_keys,
)
from verifiable_intent import (
    AllowedMerchantConstraint,
    CheckoutLineItemsConstraint,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt, resolve_disclosures
from verifiable_intent.verification.constraint_checker import check_constraints

# ---------- Shared helpers ----------


def _make_l1(now=None):
    issuer = get_issuer_keys()
    user = get_user_keys()
    now = now or int(time.time())
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 365 * 24 * 3600,
        email="user@example.com",
        pan_last_four="8842",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_autonomous_l2(l1_ser, payment_mandate, now=None):
    """Build a valid autonomous L2 with the supplied payment_mandate."""
    user = get_user_keys()
    agent = get_agent_keys()
    now = now or int(time.time())
    from verifiable_intent import CheckoutMandate

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
            CheckoutLineItemsConstraint(
                items=[{"id": "line-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
            ),
        ],
    )
    user_mandate = UserMandate(
        nonce="test-nonce",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    return create_layer2_autonomous(user_mandate, user.private_key)


# ========== Fix 1: open payment mandate requires payment_instrument ==========


class TestOpenPaymentMandateRequiresPaymentInstrument:
    def test_open_payment_mandate_missing_payment_instrument(self):
        """verify_chain must reject open payment mandate with no payment_instrument."""
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        agent = get_agent_keys()
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            # payment_instrument intentionally omitted
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        l2 = _make_autonomous_l2(l1_ser, payment_mandate, now)
        result = verify_chain(l1, l2, l3_payment=None, l1_serialized=l1_ser, skip_issuer_verification=True)
        # We need an L3 to enter autonomous branch — use a stub L3
        l3_stub = SdJwt(
            header={"alg": "ES256", "typ": "kb-sd-jwt", "kid": "agent-key-1"},
            payload={"sd_hash": "x", "iat": now},
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        result = verify_chain(l1, l2, l3_payment=l3_stub, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("payment_instrument" in e for e in result.errors)


# ========== Fix 2: non-dict elements in allowed_merchants ==========


class TestAllowedMerchantsNonDictElements:
    def test_allowed_payee_non_dict_elements_no_crash(self):
        """check_constraints must not crash when allowed_merchants contains non-dicts."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "Shop"}]}],
            {
                "payee": {"id": "m1", "name": "Shop"},
                "allowed_merchants": [None, "bad", 42, {"id": "m1", "name": "Shop"}],
            },
        )
        assert result.satisfied
        assert not result.violations

    def test_allowed_payee_all_non_dict_no_crash(self):
        """check_constraints must not crash when every element of allowed_merchants is non-dict."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "Shop"}]}],
            {
                "payee": {"id": "m1", "name": "Shop"},
                "allowed_merchants": [None, "bad", 42],
            },
        )
        # No matching merchant → violation, but no crash
        assert not result.satisfied

    def test_allowed_merchant_non_dict_elements_no_crash(self):
        """check_constraints must not crash when allowed_merchants has non-dicts (merchant variant)."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": [{"id": "m1", "name": "Shop"}]}],
            {
                "merchant": {"id": "m1", "name": "Shop"},
                "allowed_merchants": [None, "bad", 1, {"id": "m1", "name": "Shop"}],
            },
        )
        assert result.satisfied
        assert not result.violations


# ========== Fix 3: non-list delegate_payload ==========


class TestDelegatePayloadNonList:
    def test_delegate_payload_non_list_no_crash(self):
        """verify_chain must return an error (not TypeError) when delegate_payload is not a list."""
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        user = get_user_keys()
        agent = get_agent_keys()

        # Build a valid autonomous L2, then mutate delegate_payload to non-list
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        l2 = _make_autonomous_l2(l1_ser, payment_mandate, now)

        # Mutate the payload — re-sign to keep signature valid
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        mutated_payload = dict(l2.payload)
        mutated_payload["delegate_payload"] = 42  # non-list
        l2_bad = create_sd_jwt(l2.header, mutated_payload, l2.disclosures, user.private_key)

        l3_stub = SdJwt(
            header={"alg": "ES256", "typ": "kb-sd-jwt", "kid": "agent-key-1"},
            payload={"sd_hash": "x", "iat": now},
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        result = verify_chain(l1, l2_bad, l3_payment=l3_stub, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        # The key invariant is no crash (no TypeError). Mode inference now skips the non-list
        # delegate_payload during VCT scanning; the typ check or list guard catches it instead.
        assert result.errors, "Expected at least one error for non-list delegate_payload, got none"


# ========== Fix 4: resolve_disclosures malformed _sd ==========


class TestResolveDisclosuresMalformedSd:
    def test_resolve_disclosures_malformed_sd_int(self):
        """resolve_disclosures must not crash when _sd is an integer."""
        sd_jwt = SdJwt(
            header={"alg": "ES256", "typ": "sd+jwt"},
            payload={"vct": "test", "_sd": 123, "other": "value"},
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        result = resolve_disclosures(sd_jwt)
        assert result["other"] == "value"

    def test_resolve_disclosures_malformed_sd_unhashable(self):
        """resolve_disclosures must not crash when _sd contains unhashable elements."""
        sd_jwt = SdJwt(
            header={"alg": "ES256", "typ": "sd+jwt"},
            payload={"vct": "test", "_sd": [{"x": 1}, "valid-hash-string"], "other": "value"},
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        result = resolve_disclosures(sd_jwt)
        assert result["other"] == "value"


# ========== Fix 5: payment.amount with missing max/min ==========


class TestPaymentAmountMissingBounds:
    def test_payment_amount_missing_max_passes(self):
        """payment.amount with min-only is valid (max is optional — no upper bound)."""
        result = check_constraints(
            [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000}],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
        )
        assert result.satisfied

    def test_payment_amount_missing_min(self):
        """payment.amount with max-only is valid per AP2 schema (min is optional — no lower bound)."""
        result = check_constraints(
            [{"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000}],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
        )
        assert result.satisfied
        assert not result.violations

    def test_payment_amount_missing_both_passes(self):
        """payment.amount with neither min nor max is valid (no bounds enforced)."""
        result = check_constraints(
            [{"type": "mandate.payment.amount_range", "currency": "USD"}],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
        )
        assert result.satisfied

    def test_payment_amount_both_present_passes(self):
        """payment.amount with both min and max present still passes as before."""
        result = check_constraints(
            [{"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
        )
        assert result.satisfied
        assert not result.violations


# ========== Fix 6: allowed_payee / allowed_merchant empty allowlists ==========


class TestEmptyAllowlists:
    def test_allowed_payee_missing_allowed_field(self):
        """payment.allowed_payee with no 'allowed_payees' field must be a violation."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees"}],
            {"payee": {"id": "m1", "name": "Shop"}},
        )
        assert not result.satisfied
        assert any("allowed_payees" in v for v in result.violations)

    def test_allowed_payee_empty_allowed_field(self):
        """payment.allowed_payee with empty 'allowed_payees' list must be a violation."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": []}],
            {"payee": {"id": "m1", "name": "Shop"}},
        )
        assert not result.satisfied

    def test_allowed_merchant_missing_merchants_field(self):
        """allowed_merchant with no 'allowed_merchants' field must be a violation."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants"}],
            {"merchant": {"id": "m1", "name": "Shop"}},
        )
        assert not result.satisfied
        assert any("allowed_merchants" in v for v in result.violations)

    def test_allowed_merchant_empty_merchants_field(self):
        """allowed_merchant with empty 'allowed_merchants' list must be a violation."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": []}],
            {"merchant": {"id": "m1", "name": "Shop"}},
        )
        assert not result.satisfied


# ========== Round 5 fixes ==========


class TestPaymentAmountMinOptional:
    def test_max_only_exceeds_max_fails(self):
        """max-only constraint fails when amount > max."""
        result = check_constraints(
            [{"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000}],
            {"payment_amount": {"amount": 40001, "currency": "USD"}},
        )
        assert not result.satisfied
        assert any("maximum" in v for v in result.violations)

    def test_to_dict_omits_none_min(self):
        """PaymentAmountConstraint.to_dict() must not emit 'min: null' when min is absent."""
        from verifiable_intent.models.constraints import PaymentAmountConstraint

        c = PaymentAmountConstraint(currency="USD", max=40000)
        d = c.to_dict()
        assert "min" not in d
        assert d["max"] == 40000

    def test_to_dict_includes_min_when_set(self):
        """PaymentAmountConstraint.to_dict() emits 'min' when it is set."""
        from verifiable_intent.models.constraints import PaymentAmountConstraint

        c = PaymentAmountConstraint(currency="USD", min=10000, max=40000)
        d = c.to_dict()
        assert d["min"] == 10000


class TestAllowedListTypeValidation:
    def test_allowed_payee_non_list_allowed_fails(self):
        """payment.allowed_payee with non-list 'allowed_payees' is always a violation (not bypassed by fulfillment)."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": "oops"}],
            {"payee": {"id": "m1", "name": "Shop"}, "allowed_merchants": [{"id": "m1", "name": "Shop"}]},
        )
        assert not result.satisfied
        assert any("list" in v for v in result.violations)

    def test_allowed_merchant_non_list_merchants_fails(self):
        """mandate.checkout.allowed_merchant with non-list 'allowed_merchants' is always a violation."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": "oops"}],
            {"merchant": {"id": "m1", "name": "Shop"}, "allowed_merchants": [{"id": "m1", "name": "Shop"}]},
        )
        assert not result.satisfied
        assert any("list" in v for v in result.violations)


class TestLineItemsSkuTypeValidation:
    def test_cart_item_sku_as_list_fails(self):
        """Cart item with list-typed sku must fail with violation, not crash."""
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [
                        {"id": "req1", "acceptable_items": [], "quantity": 5},
                    ],
                }
            ],
            {"line_items": [{"id": ["A"], "quantity": 1}]},
        )
        assert not result.satisfied
        assert any("string" in v.lower() for v in result.violations)

    def test_cart_item_id_as_dict_fails(self):
        """Cart item with dict-typed id must fail with violation, not crash."""
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [
                        {"id": "req1", "acceptable_items": [], "quantity": 5},
                    ],
                }
            ],
            {"line_items": [{"id": {"x": "A"}, "quantity": 1}]},
        )
        assert not result.satisfied
        assert any("string" in v.lower() for v in result.violations)

    def test_acceptable_items_sku_as_list_fails(self):
        """acceptable_items entry with list-typed sku must fail with violation, not crash."""
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [
                        {"id": "req1", "acceptable_items": [{"id": ["A"], "title": "Widget"}], "quantity": 1},
                    ],
                }
            ],
            {"line_items": [{"id": "A", "quantity": 1}]},
        )
        assert not result.satisfied
        assert any("string" in v.lower() or "non-string" in v.lower() for v in result.violations)
