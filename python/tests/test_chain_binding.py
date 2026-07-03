"""Tests for mandatory chain-binding sd_hash checks (v2)."""

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
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    FinalPaymentMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentL3Mandate,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import hash_bytes


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def test_verify_chain_requires_l2_sd_hash_when_l1_serialized_provided():
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    now = int(time.time())

    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="userCredentialId",
            iat=now,
            exp=now + 3600,
            aud="https://wallet.example.com",
            pan_last_four="1234",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        ),
        issuer.private_key,
    )

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
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
    )
    l2 = create_layer2_autonomous(
        UserMandate(
            nonce="n-1",
            aud="https://www.agent.com",
            iat=now,
            iss="https://wallet.example.com",
            exp=now + 86400,
            mode=MandateMode.AUTONOMOUS,
            sd_hash="",  # Intentionally omitted
            checkout_mandate=checkout_mandate,
            payment_mandate=payment_mandate,
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        ),
        user.private_key,
    )

    result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
    )
    assert not result.valid
    # typ validation catches autonomous L2 (kb-sd-jwt+kb) presented without L3 first,
    # or sd_hash check catches the empty hash — either is a valid rejection
    assert any("sd_hash" in e.lower() or "typ" in e.lower() for e in result.errors)


def test_verify_chain_requires_l3_sd_hash_when_l2_serialized_provided():
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="userCredentialId",
            iat=now,
            exp=now + 3600,
            aud="https://wallet.example.com",
            pan_last_four="1234",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        ),
        issuer.private_key,
    )

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
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    l2 = create_layer2_autonomous(
        UserMandate(
            nonce="n-2",
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
        ),
        user.private_key,
    )
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    # Find disclosures
    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    # Create L3a with deliberately wrong sd_hash (create_layer3_payment
    # computes sd_hash automatically — we need to make the chain verify
    # fail on sd_hash mismatch instead).
    # The v2 create_layer3_payment auto-computes sd_hash, so we test via
    # providing a wrong l2_serialized to verify_chain.
    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce="n-3",
        aud="https://www.mastercard.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # Give verify_chain a WRONG l2_payment_serialized so sd_hash mismatch
    result = verify_chain(
        l1,
        l2,
        l3_payment=l3a,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_payment_serialized="wrong-serialization~",
    )
    assert not result.valid
    assert any("sd_hash" in e.lower() for e in result.errors)


# --- Tests for fail-closed issuer key requirement ---


def _make_minimal_l1_and_issuer():
    """Build a minimal valid L1 and return (l1, issuer) for issuer-key tests."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    now = int(time.time())

    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="userCredentialId",
            iat=now,
            exp=now + 3600,
            pan_last_four="8842",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        ),
        issuer.private_key,
    )
    return l1, issuer


def test_verify_chain_fails_without_issuer_key():
    """verify_chain must fail when issuer_public_key is absent and skip_issuer_verification is not set."""
    from verifiable_intent.crypto.sd_jwt import SdJwt

    l1, _issuer = _make_minimal_l1_and_issuer()
    # Pass a dummy L2 — we expect the error before any later check
    dummy_l2 = SdJwt(
        header={"alg": "ES256", "typ": "kb-sd-jwt"},
        payload={"sd_hash": "x", "iat": int(time.time())},
        signature=b"\x00" * 64,
        disclosures=[],
        disclosure_values=[],
    )

    result = verify_chain(l1, dummy_l2)
    assert not result.valid
    assert any("issuer_public_key is required" in e for e in result.errors), result.errors


def test_verify_chain_skip_issuer_verification_bypasses_key_requirement():
    """verify_chain with skip_issuer_verification=True must not fail due to missing issuer key."""
    from verifiable_intent.crypto.sd_jwt import SdJwt

    l1, _issuer = _make_minimal_l1_and_issuer()
    dummy_l2 = SdJwt(
        header={"alg": "ES256", "typ": "kb-sd-jwt"},
        payload={"sd_hash": "x", "iat": int(time.time())},
        signature=b"\x00" * 64,
        disclosures=[],
        disclosure_values=[],
    )

    result = verify_chain(l1, dummy_l2, skip_issuer_verification=True)
    # Chain will fail on a later check (L2 header, sd_hash mismatch, etc.)
    # but NOT on the missing issuer key
    assert not any("issuer_public_key is required" in e for e in result.errors), result.errors


def test_verify_chain_with_issuer_key_still_works():
    """verify_chain with a valid issuer_public_key verifies L1 sig and passes a correct chain."""
    from verifiable_intent import (
        CheckoutMandate,
        MandateMode,
        PaymentMandate,
        UserMandate,
        create_layer2_immediate,
    )
    from verifiable_intent.crypto.disclosure import hash_bytes

    l1, issuer = _make_minimal_l1_and_issuer()
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = int(time.time())
    l1_ser = l1.serialize()

    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    user_mandate = UserMandate(
        nonce="n-test",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.1",
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.1",
            currency="USD",
            amount=27999,
            payee=MERCHANTS[0],
            payment_instrument=PAYMENT_INSTRUMENT,
            transaction_id=c_hash,
        ),
    )
    result_l2 = create_layer2_immediate(user_mandate, user.private_key)
    l2 = result_l2.sd_jwt

    result = verify_chain(l1, l2, issuer_public_key=issuer.public_key, l1_serialized=l1_ser)
    assert result.valid, f"Expected valid chain but got errors: {result.errors}"
