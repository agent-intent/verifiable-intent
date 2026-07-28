"""Integration tests for the immediate (2-layer) flow with v2 structure."""

from __future__ import annotations

import time

from helpers import (
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
)
from verifiable_intent import (
    CheckoutMandate,
    IssuerCredential,
    MandateMode,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_immediate,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures


def test_immediate_two_layer_chain():
    """Test 2-layer chain: L1 + L2 with final values, no L3."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

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
    l1 = create_layer1(cred, issuer.private_key)
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
        nonce="imm-nonce-1",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    result = create_layer2_immediate(user_mandate, user.private_key)
    l2 = result.sd_jwt

    # Verify 2-layer chain (no L3)
    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert chain_result.valid, f"Chain verification failed: {chain_result.errors}"


def test_immediate_no_cnf_in_mandates():
    """Verify that immediate mode mandates do NOT contain cnf."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 365 * 24 * 3600,
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)
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
        nonce="imm-nonce-2",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    result = create_layer2_immediate(user_mandate, user.private_key)
    l2 = result.sd_jwt
    l2_claims = resolve_disclosures(l2)

    # No mandate disclosure should contain cnf
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict):
            assert "cnf" not in delegate, "Immediate mode mandate should not have cnf"


def test_immediate_expired_l1_fails():
    """Test that expired L1 credential fails verification."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now - 86400 * 2,
        exp=now - 86400,  # Expired yesterday
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)
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
        nonce="imm-nonce-3",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    result = create_layer2_immediate(user_mandate, user.private_key)
    l2 = result.sd_jwt

    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert not chain_result.valid
    assert any("expired" in e.lower() for e in chain_result.errors)
