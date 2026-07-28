"""Integration tests for the autonomous (3-layer) flow with v2 split L3."""

from __future__ import annotations

import time

import pytest

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
    create_layer3_checkout,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _build_full_chain():
    """Build a complete v2 3-layer chain. Returns all components."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    # L1: Issuer credential
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 365 * 24 * 3600,
        aud="https://wallet.example.com",
        email="user@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)
    l1_ser = l1.serialize()

    # L2: User mandate (autonomous)
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
            CheckoutLineItemsConstraint(
                items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
            ),
        ],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=[
            PaymentAmountConstraint(currency="USD", min=10000, max=40000),
        ],
    )
    user_mandate = UserMandate(
        nonce="test-nonce-l2",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
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

    # Find disclosures in L2
    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    # Create checkout JWT and compute hash
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    # L3a: Payment mandate for network
    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce="test-nonce-l3a",
        aud="https://www.mastercard.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # L3b: Checkout mandate for merchant
    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce="test-nonce-l3b",
        aud="https://tennis-warehouse.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    # Compute selective L2 presentations for sd_hash verification
    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

    return {
        "l1": l1,
        "l2": l2,
        "l3a": l3a,
        "l3b": l3b,
        "l1_ser": l1_ser,
        "l2_ser": l2_ser,
        "l2_payment_ser": l2_payment_ser,
        "l2_checkout_ser": l2_checkout_ser,
        "issuer": issuer,
        "user": user,
        "agent": agent,
    }


class TestAutonomousChainCreation:
    def test_l1_has_one_disclosure(self):
        chain = _build_full_chain()
        assert len(chain["l1"].disclosures) == 1  # email only

    def test_l3a_has_payment_disclosure(self):
        chain = _build_full_chain()
        l3a = chain["l3a"]
        assert len(l3a.disclosures) >= 1

    def test_l3b_has_checkout_disclosure(self):
        chain = _build_full_chain()
        l3b = chain["l3b"]
        assert len(l3b.disclosures) >= 1


class TestAutonomousChainVerification:
    def test_verify_with_payment_l3_only(self):
        chain = _build_full_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain.get("l2_payment_ser"),
            l2_checkout_serialized=chain.get("l2_checkout_ser"),
        )
        assert result.valid, f"Chain verification failed: {result.errors}"

    def test_verify_with_checkout_l3_only(self):
        chain = _build_full_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_checkout=chain["l3b"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain.get("l2_payment_ser"),
            l2_checkout_serialized=chain.get("l2_checkout_ser"),
        )
        assert result.valid, f"Chain verification failed: {result.errors}"

    def test_verify_with_both_l3s(self):
        chain = _build_full_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            l3_checkout=chain["l3b"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain.get("l2_payment_ser"),
            l2_checkout_serialized=chain.get("l2_checkout_ser"),
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert "l3_cross_reference" in result.checks_performed

    def test_l2_disclosures_detected(self):
        chain = _build_full_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain.get("l2_payment_ser"),
            l2_checkout_serialized=chain.get("l2_checkout_ser"),
        )
        assert result.valid
        assert result.l2_payment_disclosed

    def test_wrong_agent_key_fails(self):
        """L3 signed with wrong key should fail verification."""
        chain = _build_full_chain()
        from verifiable_intent.crypto.signing import generate_es256_key

        wrong_key = generate_es256_key()

        now = int(time.time())
        final_payment = FinalPaymentMandate(
            transaction_id="fake",
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        bad_mandate = PaymentL3Mandate(
            nonce="bad-nonce",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
        )
        l2_base = chain["l2_ser"].split("~")[0]
        payment_disc = _find_disclosure(
            chain["l2"], lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
        )
        merchant_disc = _find_disclosure(
            chain["l2"], lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse"
        )
        bad_l3 = create_layer3_payment(bad_mandate, wrong_key, l2_base, payment_disc, merchant_disc)

        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=bad_l3,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain.get("l2_payment_ser"),
            l2_checkout_serialized=chain.get("l2_checkout_ser"),
        )
        assert not result.valid
        assert any("signature" in e.lower() or "key" in e.lower() for e in result.errors)


class TestAutonomousModelConstruction:
    def test_checkout_mandate_rejects_dual_mode(self):
        with pytest.raises(ValueError, match="cannot have both"):
            CheckoutMandate(cnf_jwk={"x": "a"}, checkout_jwt="jwt")

    def test_payment_mandate_rejects_dual_mode(self):
        with pytest.raises(ValueError, match="cannot have both"):
            PaymentMandate(cnf_jwk={"x": "a"}, amount=100)

    def test_checkout_mandate_to_dict(self):
        m = CheckoutMandate(vct="mandate.checkout.open.1", cnf_jwk={"x": "a"})
        d = m.to_dict()
        assert d["vct"] == "mandate.checkout.open.1"
        assert d["cnf"]["jwk"]["x"] == "a"

    def test_final_payment_mandate_to_dict(self):
        m = FinalPaymentMandate(
            transaction_id="abc",
            payee={"id": "m1"},
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        d = m.to_dict()
        assert d["vct"] == "mandate.payment.1"
        assert d["transaction_id"] == "abc"
        assert d["payment_amount"]["amount"] == 27999

    def test_payment_mandate_rejects_removed_fields(self):
        """PaymentMandate no longer accepts recurrence or execution_date (issue #8)."""
        with pytest.raises(TypeError):
            PaymentMandate(vct="mandate.payment.open.1", cnf_jwk={"x": "a"}, recurrence="MNTH")
        with pytest.raises(TypeError):
            PaymentMandate(vct="mandate.payment.open.1", cnf_jwk={"x": "a"}, execution_date="2026-03-01")
