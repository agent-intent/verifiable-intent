"""Tests for PR review fixes: type-safety crashes, logic bugs, and hardening."""

from __future__ import annotations

import time

from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    get_agent_keys,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
)
from verifiable_intent import (
    AllowedMerchantConstraint,
    CheckoutL3Mandate,
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    FinalCheckoutMandate,
    FinalPaymentMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentL3Mandate,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer2_immediate,
    create_layer3_checkout,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt
from verifiable_intent.verification.constraint_checker import check_constraints


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


# ---------- Shared fixtures ----------


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
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_immediate_l2(l1_ser, now=None):
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = now or int(time.time())
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        currency="USD",
        amount=27999,
        payee=MERCHANTS[0],
        payment_instrument=PAYMENT_INSTRUMENT,
        transaction_id=c_hash,
    )
    user_mandate = UserMandate(
        nonce="test-nonce",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    return create_layer2_immediate(user_mandate, user.private_key)


# ========== Fix #2: Non-object JWT payloads ==========


class TestNonObjectPayloads:
    """verify_chain must return errors (not crash) on non-dict payloads."""

    def test_l1_list_payload(self):
        """L1 with list payload should fail with error, not AttributeError."""
        l1 = SdJwt(
            header={"alg": "ES256", "typ": "sd+jwt"},
            payload=["not", "an", "object"],
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        l2 = SdJwt(
            header={"alg": "ES256", "typ": "kb-sd-jwt"},
            payload={"sd_hash": "x"},
            signature=b"\x00" * 64,
            disclosures=[],
            disclosure_values=[],
        )
        result = verify_chain(l1, l2, skip_issuer_verification=True)
        assert not result.valid
        assert any("L1 payload" in e for e in result.errors)


# ========== Fix #3: L3 header kid binding ==========


class TestL3HeaderKidBinding:
    """L3 header kid must be a string matching L2 cnf.jwk.kid."""

    def test_l3_header_kid_non_string_rejected(self):
        """Non-string kid in L3 header should fail with error, not crash.

        The signature verifier re-encodes from current header/payload, so
        mutating header.kid to a non-string changes the signing input and fails
        signature first. We verify the chain rejects (doesn't crash) regardless.
        """
        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())

        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)
        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == MERCHANTS[0]["name"])

        final_payment = FinalPaymentMandate(
            transaction_id=checkout_hash_from_jwt("fake-jwt"),
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="n-l3a",
            aud="https://www.mastercard.com",
            iat=now,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        # Tamper with header kid — replace with invalid value
        l3a.header["kid"] = 12345  # not a string

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        # Signature verification re-encodes from current header, so the mutated kid
        # changes the signing input — chain fails at signature check (before kid guard).
        # Key test: verify_chain returns error, doesn't crash with TypeError.
        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=get_issuer_keys().public_key,
            l1_serialized=l1_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert not result.valid
        assert result.errors  # Should have at least one error (signature or kid)


# ========== Fix #4: Non-dict constraint entries ==========


class TestNonDictConstraintEntries:
    """check_constraints must handle non-dict entries without crashing."""

    def test_string_constraint_entry(self):
        result = check_constraints(["not-a-dict"], {"payment_amount": {"amount": 100, "currency": "USD"}})
        assert not result.satisfied
        assert any("must be an object" in v for v in result.violations)

    def test_int_constraint_entry(self):
        result = check_constraints([123], {})
        assert not result.satisfied
        assert any("must be an object" in v for v in result.violations)

    def test_mixed_valid_and_invalid_entries(self):
        result = check_constraints(
            [42, {"type": "mandate.payment.amount_range", "currency": "USD", "min": 100, "max": 500}],
            {"payment_amount": {"amount": 200, "currency": "USD"}},
        )
        assert not result.satisfied  # The int entry causes failure
        assert any("must be an object" in v for v in result.violations)

    def test_none_constraint_entry(self):
        result = check_constraints([None], {})
        assert not result.satisfied


# ========== Fix #5: Non-dict line_items entries ==========


class TestNonDictLineItems:
    """check_constraints must handle non-dict line_items without crashing."""

    def test_string_line_item(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [{"id": "li-1", "acceptable_items": [{"sku": "X", "title": "Item"}], "quantity": 5}],
                }
            ],
            {"line_items": ["not-a-dict"]},
        )
        assert not result.satisfied
        assert any("must be an object" in v for v in result.violations)

    def test_int_line_item(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [{"id": "li-1", "acceptable_items": [{"sku": "X", "title": "Item"}], "quantity": 5}],
                }
            ],
            {"line_items": [123]},
        )
        assert not result.satisfied
        assert any("must be an object" in v for v in result.violations)


# ========== Fix #6: Immediate mode requires both mandates ==========


class TestImmediateMandatePairConformance:
    """Immediate mode must require both checkout and payment mandates."""

    def test_immediate_checkout_only_rejected(self):
        """Immediate L2 with only checkout mandate should fail."""
        user = get_user_keys()
        merchant = get_merchant_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.1",
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        )
        # Only checkout mandate, no payment mandate
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
        )
        result = create_layer2_immediate(user_mandate, user.private_key)
        l2 = result.sd_jwt

        chain_result = verify_chain(l1, l2, issuer_public_key=get_issuer_keys().public_key, l1_serialized=l1_ser)
        assert not chain_result.valid
        assert any("both" in e.lower() or "requires" in e.lower() for e in chain_result.errors)


# ========== Fix #7: Open mandates rejected in immediate mode ==========


class TestImmediateRejectsOpenMandates:
    """Immediate mode must reject open (autonomous-style) mandates."""

    def test_open_checkout_in_immediate_rejected(self):
        """Open checkout mandate in immediate mode should fail verification."""
        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        # Create an open checkout mandate (autonomous style) but in immediate mode L2
        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.1",
            currency="USD",
            amount=27999,
            payee=MERCHANTS[0],
            payment_instrument=PAYMENT_INSTRUMENT,
            transaction_id="test-tid",
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
        )
        result = create_layer2_immediate(user_mandate, user.private_key)
        l2 = result.sd_jwt

        chain_result = verify_chain(l1, l2, issuer_public_key=get_issuer_keys().public_key, l1_serialized=l1_ser)
        assert not chain_result.valid
        assert any("open" in e.lower() and "immediate" in e.lower() for e in chain_result.errors)


# ========== Fix #8: Line items missing ID ==========


class TestLineItemsMissingId:
    """Line items missing 'id' field should be rejected."""

    def test_empty_cart_item_rejected(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [{"id": "li-1", "acceptable_items": [{"sku": "SKU-1", "title": "Item"}], "quantity": 5}],
                }
            ],
            {"line_items": [{}]},
        )
        assert not result.satisfied
        assert any("missing" in v.lower() and "id" in v.lower() for v in result.violations)

    def test_cart_item_with_only_quantity_rejected(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [{"id": "li-1", "acceptable_items": [{"sku": "SKU-1", "title": "Item"}], "quantity": 5}],
                }
            ],
            {"line_items": [{"quantity": 1}]},
        )
        assert not result.satisfied
        assert any("missing" in v.lower() and "id" in v.lower() for v in result.violations)


# ========== Fix #9: Malformed fulfillment shapes ==========


class TestMalformedFulfillmentShapes:
    """Payee/merchant as non-dict should fail closed."""

    def test_string_payee(self):
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "M"}]}],
            {"payee": "invalid-string", "allowed_merchants": [{"id": "m1", "name": "M"}]},
        )
        assert not result.satisfied
        assert any("payee" in v.lower() for v in result.violations)

    def test_int_payee(self):
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "M"}]}],
            {"payee": 123, "allowed_merchants": [{"id": "m1", "name": "M"}]},
        )
        assert not result.satisfied

    def test_list_merchant(self):
        """List merchant fails closed (not a valid dict)."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": [{"id": "m1", "name": "M"}]}],
            {"merchant": [{"id": "m1"}], "allowed_merchants": [{"id": "m1", "name": "M"}]},
        )
        assert not result.satisfied
        assert any("merchant" in v.lower() for v in result.violations)

    def test_int_merchant(self):
        """Integer merchant fails closed (not a valid dict)."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": [{"id": "m1", "name": "M"}]}],
            {"merchant": 123, "allowed_merchants": [{"id": "m1", "name": "M"}]},
        )
        assert not result.satisfied
        assert any("merchant" in v.lower() for v in result.violations)


# ========== Fix #10: cnf on immediate-mode mandates ==========


class TestImmediateRejectsCnf:
    """Immediate mode mandates with cnf should be rejected."""

    def test_immediate_payment_mandate_with_cnf_rejected(self):
        """Payment mandate with cnf in immediate mode should fail verification.

        Model __post_init__ prevents creating a PaymentMandate with both cnf_jwk and
        amount, so we create a normal immediate L2, then inject cnf into the resolved
        disclosure to simulate an externally-constructed credential.
        """
        user = get_user_keys()
        agent = get_agent_keys()
        merchant = get_merchant_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.1",
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.1",
            currency="USD",
            amount=27999,
            payee=MERCHANTS[0],
            payment_instrument=PAYMENT_INSTRUMENT,
            transaction_id=c_hash,
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
        )
        result = create_layer2_immediate(user_mandate, user.private_key)
        l2 = result.sd_jwt

        # Inject cnf into the payment mandate disclosure (simulate externally-constructed credential)
        # We need to find the payment mandate disclosure value and inject cnf into it
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if disc_val else None
            if isinstance(value, dict) and value.get("vct") == "mandate.payment.1":
                value["cnf"] = {"jwk": agent.public_jwk}
                break

        chain_result = verify_chain(l1, l2, issuer_public_key=get_issuer_keys().public_key, l1_serialized=l1_ser)
        assert not chain_result.valid
        assert any("cnf" in e.lower() for e in chain_result.errors)


# ========== Fix #1: L3 payment instrument substitution ==========


class TestL3PaymentInstrumentSubstitution:
    """L3 payment instrument must match L2 authorized value."""

    def test_l3_payment_instrument_mismatch_detected(self):
        """Agent swapping payment instrument in L3a should fail verification."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        merchant = get_merchant_keys()
        now = int(time.time())

        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)
        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == MERCHANTS[0]["name"])

        # L3a with UNAUTHORIZED payment instrument
        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument={"type": "card", "id": "UNAUTHORIZED-CARD-ID", "description": "Stolen Card"},
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="n-l3a",
            aud="https://www.mastercard.com",
            iat=now,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        # L2 payment mandate specifies a payment_instrument — agent must use the same one
        chain_result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        # Instrument mismatch must be rejected regardless of open/closed VCT
        assert not chain_result.valid
        assert any("payment_instrument" in e.lower() and "does not match" in e.lower() for e in chain_result.errors)

    def test_l3_payment_instrument_match_passes(self):
        """L3 with matching payment instrument should pass."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        merchant = get_merchant_keys()
        now = int(time.time())

        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)
        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == MERCHANTS[0]["name"])
        checkout_disc = _find_disclosure(
            l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )
        item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == ACCEPTABLE_ITEMS[0]["id"])

        # L3a with correct payment instrument
        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="n-l3a",
            aud="https://www.mastercard.com",
            iat=now,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        # L3b
        final_checkout = FinalCheckoutMandate(
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        )
        l3b_mandate = CheckoutL3Mandate(
            nonce="n-l3b",
            aud="https://tennis-warehouse.com",
            iat=now,
            final_checkout=final_checkout,
        )
        l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
        l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            l3_checkout=l3b,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            l2_payment_serialized=l2_payment_ser,
            l2_checkout_serialized=l2_checkout_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"


# ========== Finding 1 (new): Autonomous instrument mismatch must fail ==========


class TestAutonomousInstrumentMismatch:
    """Unauthorized card ID in L3a must fail even with open L2 mandates."""

    def test_autonomous_instrument_mismatch_rejected(self):
        """Agent using unauthorized payment instrument in L3a must be rejected."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        merchant = get_merchant_keys()
        now = int(time.time())

        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)
        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == MERCHANTS[0]["name"])

        # L3a with UNAUTHORIZED payment instrument (different ID)
        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument={"type": "card", "id": "STOLEN-CARD-9999"},
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="n-l3a",
            aud="https://www.mastercard.com",
            iat=now,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        chain_result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert not chain_result.valid
        assert any("payment_instrument" in e.lower() and "does not match" in e.lower() for e in chain_result.errors)


# ========== Finding 2: Duplicate mandate smuggling ==========


class TestDuplicateMandateSmuggling:
    """Smuggled extra mandates in L2 must be detected and rejected."""

    def test_duplicate_checkout_mandates_rejected(self):
        """L2 with two checkout mandates should fail verification."""
        from verifiable_intent.crypto.disclosure import hash_disclosure
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)

        # Find the checkout mandate disclosure hash
        checkout_ref_hash = None
        for ds, dv in zip(l2.disclosures, l2.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and val.get("vct") == "mandate.checkout.open.1":
                checkout_ref_hash = hash_disclosure(ds)
                break
        assert checkout_ref_hash is not None

        # Inject duplicate checkout mandate reference and re-sign
        import copy

        new_payload = copy.deepcopy(l2.payload)
        new_payload["delegate_payload"].append({"...": checkout_ref_hash})
        l2_tampered = create_sd_jwt(l2.header, new_payload, l2.disclosures, user.private_key)

        # Pass dummy L3 to trigger autonomous mode (typ check passes before duplicate detection)
        dummy_l3 = SdJwt(header={}, payload={}, signature=b"\x00" * 64)
        chain_result = verify_chain(
            l1, l2_tampered, l3_payment=dummy_l3, l1_serialized=l1_ser, skip_issuer_verification=True
        )
        assert not chain_result.valid
        assert any("duplicate disclosure reference" in e.lower() for e in chain_result.errors)

    def test_duplicate_payment_mandates_rejected(self):
        """L2 with two payment mandates should fail verification."""
        from verifiable_intent.crypto.disclosure import hash_disclosure
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(user_mandate, user.private_key)

        # Find the payment mandate disclosure hash
        payment_ref_hash = None
        for ds, dv in zip(l2.disclosures, l2.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and val.get("vct") == "mandate.payment.open.1":
                payment_ref_hash = hash_disclosure(ds)
                break
        assert payment_ref_hash is not None

        # Inject duplicate payment mandate reference and re-sign to avoid signature failure
        import copy

        new_payload = copy.deepcopy(l2.payload)
        new_payload["delegate_payload"].append({"...": payment_ref_hash})
        l2_tampered = create_sd_jwt(l2.header, new_payload, l2.disclosures, user.private_key)

        # Pass dummy L3 to trigger autonomous mode (typ check passes before duplicate detection)
        dummy_l3 = SdJwt(header={}, payload={}, signature=b"\x00" * 64)
        chain_result = verify_chain(
            l1, l2_tampered, l3_payment=dummy_l3, l1_serialized=l1_ser, skip_issuer_verification=True
        )
        assert not chain_result.valid
        assert any("duplicate disclosure reference" in e.lower() for e in chain_result.errors)


# ========== Finding 4: Empty cnf bypass ==========


class TestEmptyCnfBypass:
    """cnf: {} must be caught by immediate-mode rejection."""

    def test_immediate_mandate_with_empty_cnf_rejected(self):
        """Mandate with cnf: {} in immediate mode should fail."""
        user = get_user_keys()
        merchant = get_merchant_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.1",
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.1",
            currency="USD",
            amount=27999,
            payee=MERCHANTS[0],
            payment_instrument=PAYMENT_INSTRUMENT,
            transaction_id=c_hash,
        )
        user_mandate = UserMandate(
            nonce="test-n",
            aud="https://www.agent.com",
            iat=now,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
        )
        result = create_layer2_immediate(user_mandate, user.private_key)
        l2 = result.sd_jwt

        # Inject empty cnf into payment mandate (simulate externally-constructed credential)
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if disc_val else None
            if isinstance(value, dict) and value.get("vct") == "mandate.payment.1":
                value["cnf"] = {}
                break

        chain_result = verify_chain(l1, l2, issuer_public_key=get_issuer_keys().public_key, l1_serialized=l1_ser)
        assert not chain_result.valid
        assert any("cnf" in e.lower() for e in chain_result.errors)


# ========== Finding 3: Non-list allowed_merchants ==========


class TestNonListAllowedMerchants:
    """Non-list allowed_merchants in fulfillment must not crash."""

    def test_allowed_payee_nonlist_allowed_merchants(self):
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "M"}]}],
            {"payee": {"id": "m1", "name": "M"}, "allowed_merchants": "not-a-list"},
        )
        # Should not crash — falls through to inline constraint check
        assert result.satisfied

    def test_allowed_merchant_nonlist_allowed_merchants(self):
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": [{"id": "m1", "name": "M"}]}],
            {"merchant": {"id": "m1", "name": "M"}, "allowed_merchants": 42},
        )
        # Should not crash — falls through to inline constraint check
        assert result.satisfied


# ========== Finding 5: Non-list delegate_payload ==========


class TestNonListDelegatePayload:
    """resolve_disclosures must handle non-list delegate_payload."""

    def test_resolve_disclosures_nonlist_delegate_payload(self):
        from verifiable_intent.crypto.sd_jwt import SdJwt, resolve_disclosures

        sd = SdJwt(
            header={"alg": "ES256", "typ": "sd+jwt"},
            payload={"delegate_payload": "not-a-list", "vct": "test"},
            signature=b"\x00" * 64,
        )
        result = resolve_disclosures(sd)
        # Should not crash; delegate_payload left as-is
        assert result["delegate_payload"] == "not-a-list"


# ========== Finding 12: Non-serializable in verify_sd_jwt_signature ==========


class TestVerifySdJwtSignatureNonSerializable:
    """Non-JSON-serializable payloads must return False, not crash."""

    def test_verify_sd_jwt_signature_nonserializable(self):
        from verifiable_intent.crypto.sd_jwt import SdJwt, verify_sd_jwt_signature
        from verifiable_intent.crypto.signing import generate_es256_key

        key = generate_es256_key()
        sd = SdJwt(
            header={"alg": "ES256", "typ": "sd+jwt"},
            payload={"data": object()},  # Not JSON-serializable
            signature=b"\x00" * 64,
        )
        # Should return False, not raise TypeError
        assert verify_sd_jwt_signature(sd, key.public_key()) is False


# ========== Finding 13: Malformed min/max on payment.amount ==========


class TestPaymentAmountMalformedMinMax:
    """String/None/bool min/max must produce violation, not crash."""

    def test_payment_amount_string_min_rejected(self):
        from verifiable_intent.models.constraints import PaymentAmountConstraint

        c = PaymentAmountConstraint(currency="USD", min=10000, max=40000)
        c.min = "not-a-number"  # Simulate malformed
        # Test the constraint object directly (dict-based path parses normally)
        from verifiable_intent.verification.constraint_checker import ConstraintCheckResult, _check_payment_amount

        r = ConstraintCheckResult()
        _check_payment_amount(c, {"payment_amount": {"amount": 27999, "currency": "USD"}}, r)
        assert not r.satisfied
        assert any("constraint min" in v.lower() for v in r.violations)

    def test_payment_amount_none_max_skips_upper_bound(self):
        """max=None means no upper bound — matches min=None behavior."""
        from verifiable_intent.models.constraints import PaymentAmountConstraint
        from verifiable_intent.verification.constraint_checker import ConstraintCheckResult, _check_payment_amount

        c = PaymentAmountConstraint(currency="USD", min=10000, max=40000)
        c.max = None  # No upper bound
        r = ConstraintCheckResult()
        _check_payment_amount(c, {"payment_amount": {"amount": 27999, "currency": "USD"}}, r)
        assert r.satisfied

    def test_payment_amount_bool_min_rejected(self):
        from verifiable_intent.models.constraints import PaymentAmountConstraint
        from verifiable_intent.verification.constraint_checker import ConstraintCheckResult, _check_payment_amount

        c = PaymentAmountConstraint(currency="USD", min=10000, max=40000)
        c.min = True  # bool is subclass of int
        r = ConstraintCheckResult()
        _check_payment_amount(c, {"payment_amount": {"amount": 27999, "currency": "USD"}}, r)
        assert not r.satisfied
        assert any("constraint min" in v.lower() for v in r.violations)


# ========== Finding 7: Non-dict items entries ==========


class TestNonDictItemsEntries:
    """Non-dict entries in c.items must produce violations, not be silently skipped."""

    def test_line_items_nondict_item_entry_violation(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [
                        "not-a-dict",
                        {"id": "li-1", "acceptable_items": [{"id": "X", "title": "Item"}], "quantity": 1},
                    ],
                }
            ],
            {"line_items": [{"id": "X", "quantity": 1}]},
        )
        assert not result.satisfied
        assert any("must be an object" in v.lower() for v in result.violations)
