"""Tests for configurable expected_l1_vct parameter in verify_chain() (Finding F7)."""

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

_CUSTOM_VCT = "https://example.com/card"
_MC_VCT = "https://credentials.mastercard.com/card"


def _build_l1_l2(vct: str = _MC_VCT):
    """Build a minimal immediate chain with the given L1 VCT URI."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    merchant = get_merchant_keys()
    now = int(time.time())

    cred = IssuerCredential(
        vct=vct,
        iss="https://www.example.com",
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
        nonce="test-nonce",
        aud="https://agent.example.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2 = create_layer2_immediate(user_mandate, user.private_key).sd_jwt

    return {"l1": l1, "l2": l2, "l1_ser": l1_ser, "issuer": issuer}


class TestConfigurableL1Vct:
    def test_custom_l1_vct_accepted(self):
        """An L1 with a custom VCT URI must pass when expected_l1_vct matches."""
        chain = _build_l1_l2(vct=_CUSTOM_VCT)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l1_vct=_CUSTOM_VCT,
        )
        # The chain should not fail on the VCT check — any VCT error would have
        # that exact URI in the message.
        vct_errors = [e for e in result.errors if "vct" in e.lower() and "l1" in e.lower()]
        assert not vct_errors, f"VCT check failed unexpectedly: {vct_errors}"

    def test_default_vct_still_works(self):
        """Omitting expected_l1_vct must accept the standard Mastercard VCT (no regression)."""
        chain = _build_l1_l2(vct=_MC_VCT)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            # expected_l1_vct not provided — must default to _MC_VCT
        )
        assert result.valid, f"Unexpected errors: {result.errors}"

    def test_custom_vct_mismatch_fails(self):
        """An L1 with the standard MC VCT must fail when expected_l1_vct differs."""
        chain = _build_l1_l2(vct=_MC_VCT)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l1_vct="https://other.example.com/card",
        )
        assert not result.valid
        assert any("l1 vct" in e.lower() for e in result.errors), f"Expected a VCT error, got: {result.errors}"
        # Error must mention the expected VCT so the caller knows what was checked
        assert any("https://other.example.com/card" in e for e in result.errors)
