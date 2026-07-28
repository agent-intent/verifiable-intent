"""Tests for selective disclosure: each party sees only what they need (v2)."""

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
)
from verifiable_intent.crypto.disclosure import decode_disclosure, hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _make_full_chain():
    """Helper: create a complete v2 3-layer chain."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 365 * 24 * 3600,
        aud="https://wallet.example.com",
        email="test@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
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
        nonce="sd-nonce-1",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
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
        nonce="sd-nonce-l3a",
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
        nonce="sd-nonce-l3b",
        aud="https://tennis-warehouse.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    return l1, l2, l3a, l3b


def test_l1_selective_disclosure():
    """L1 has 1 selectively disclosable claim: email only (v2)."""
    l1, _, _, _ = _make_full_chain()

    # Without disclosures, email is a hash
    assert "email" not in l1.payload
    assert "_sd" in l1.payload
    assert len(l1.payload["_sd"]) == 1

    # With disclosures resolved
    resolved = resolve_disclosures(l1)
    assert resolved["email"] == "test@example.com"


def test_l3a_has_payment_disclosure():
    """L3a has payment and merchant as separate disclosures for network."""
    _, _, l3a, _ = _make_full_chain()

    assert len(l3a.disclosures) >= 1

    # Check at least one disclosure has a payment VCT
    vcttypes = set()
    for d in l3a.disclosures:
        decoded = decode_disclosure(d)
        val = decoded[-1]
        if isinstance(val, dict):
            vcttypes.add(val.get("vct", ""))

    assert "mandate.payment.1" in vcttypes


def test_l3b_has_checkout_disclosure():
    """L3b has checkout disclosure for merchant."""
    _, _, _, l3b = _make_full_chain()

    assert len(l3b.disclosures) >= 1

    vcttypes = set()
    for d in l3b.disclosures:
        decoded = decode_disclosure(d)
        val = decoded[-1]
        if isinstance(val, dict):
            vcttypes.add(val.get("vct", ""))

    assert "mandate.checkout.1" in vcttypes


def test_l2_autonomous_has_separate_mandate_disclosures():
    """L2 autonomous mandates are individually disclosable."""
    _, l2, _, _ = _make_full_chain()

    # L2 should have multiple disclosures: merchants + items + mandates
    assert len(l2.disclosures) >= 2

    # Resolve and check delegate_payload
    resolved = resolve_disclosures(l2)
    delegates = resolved.get("delegate_payload", [])

    vct_types = set()
    for d in delegates:
        if isinstance(d, dict) and "vct" in d:
            vct_types.add(d["vct"])

    # Both checkout and payment mandates must be present
    assert "mandate.checkout.open.1" in vct_types, "Missing mandate.checkout.open in L2 disclosures"
    assert "mandate.payment.open.1" in vct_types, "Missing mandate.payment.open in L2 disclosures"
