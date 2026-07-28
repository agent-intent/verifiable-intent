"""Tests for VCT-based mode inference in verify_chain (Finding F6).

Mode (Immediate vs Autonomous) is now inferred from the L2 mandate VCTs,
not from whether L3 arguments were provided.  This decouples structural
validation from caller intent and catches two previously-undetected cases:

 1. Immediate L2 + L3 args supplied   → explicit error (caller mistake)
 2. Autonomous L2 + no L3 args         → valid (L3 verification skipped)
 3. Mixed-VCT L2 (open + final)       → explicit error (malformed L2)
"""

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
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer2_immediate,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt, create_sd_jwt

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_l1(issuer, user, now):
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        email="test@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_immediate_l2(user, l1, now):
    """Build a valid Immediate-mode L2."""
    merchant = get_merchant_keys()
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
        nonce="n-imm-inf",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    return create_layer2_immediate(user_mandate, user.private_key).sd_jwt


def _make_autonomous_l2(user, agent, l1, now):
    """Build a valid Autonomous-mode L2 (open VCTs, agent key bound)."""
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
            CheckoutLineItemsConstraint(
                items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}]
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
        nonce="n-auto-inf",
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
    return create_layer2_autonomous(user_mandate, user.private_key)


# ---------------------------------------------------------------------------
# Test 1: immediate L2 + L3 args → error
# ---------------------------------------------------------------------------


def test_immediate_l2_with_l3_args_rejected():
    """Passing L3 args alongside an Immediate-mode L2 must be rejected.

    The verifier infers mode from the L2 mandate VCTs (final VCTs = Immediate).
    Supplying L3 args is then a caller error, caught explicitly before any L3
    verification is attempted."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    now = int(time.time())

    l1 = _make_l1(issuer, user, now)
    l2 = _make_immediate_l2(user, l1, now)

    # Build a dummy L3 that will never actually be verified
    dummy_l3 = SdJwt(
        header={"alg": "ES256", "typ": "kb-sd-jwt"},
        payload={},
        signature=b"\x00" * 64,
        disclosures=[],
        disclosure_values=[],
    )

    result = verify_chain(
        l1,
        l2,
        l3_payment=dummy_l3,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
    )

    assert not result.valid, "Expected verification to fail when L3 is provided with an immediate L2"
    assert any("immediate" in e.lower() or "L3 credentials" in e for e in result.errors), (
        f"Expected an error about immediate-mode/L3 mismatch, got: {result.errors}"
    )


# ---------------------------------------------------------------------------
# Test 2: autonomous L2 + no L3 args → valid (L3 verification skipped)
# ---------------------------------------------------------------------------


def test_autonomous_l2_without_l3_is_valid():
    """Autonomous L2 (open VCTs) without L3 args must pass structural verification.

    Mode is inferred from the L2 VCTs (open VCTs = Autonomous).  The absence of
    L3 args is valid — it means the verifier skips L3 verification (e.g., the
    network only does L2 validation before L3 arrives).  This is NOT a protocol
    error; L3 verification is simply deferred."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    now = int(time.time())

    l1 = _make_l1(issuer, user, now)
    l2 = _make_autonomous_l2(user, agent, l1, now)

    result = verify_chain(
        l1,
        l2,
        # No l3_payment, no l3_checkout, no split_l3s
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
    )

    assert result.valid, (
        f"Expected autonomous L2 without L3 args to pass structural verification, but got errors: {result.errors}"
    )
    # Mode should be detected as autonomous (has open mandate VCTs)
    assert result.mandate_pair_count >= 1, "Expected at least one mandate pair to be resolved"


# ---------------------------------------------------------------------------
# Test 3: mixed-mode L2 (open + final VCTs) → error
# ---------------------------------------------------------------------------


def test_mixed_mode_vcts_rejected():
    """L2 with both open (autonomous) and final (immediate) mandate VCTs must be rejected.

    Such a credential cannot be assigned a coherent mode and likely indicates
    a corrupted or maliciously crafted L2."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    now = int(time.time())

    l1 = _make_l1(issuer, user, now)
    l1_ser = l1.serialize()

    # Build an L2 payload that contains both an open and a final mandate VCT.
    # We construct the SD-JWT directly to bypass the issuance-layer mode guards.
    from verifiable_intent.crypto.disclosure import create_disclosure

    # create_disclosure(claim_name, claim_value, salt=None)
    open_disc = create_disclosure(
        "delegate_payload",
        {
            "vct": "mandate.checkout.open.1",
            "constraints": [],
        },
        salt="salt-open-abc12345",
    )
    final_disc = create_disclosure(
        "delegate_payload",
        {
            "vct": "mandate.payment.1",
            "transaction_id": "tid-123",
            "currency": "USD",
            "amount": 27999,
            "payee": {"id": "m1", "name": "Acme"},
            "payment_instrument": PAYMENT_INSTRUMENT,
        },
        salt="salt-final-abc12345",
    )

    from verifiable_intent.crypto.disclosure import hash_disclosure

    l2_payload = {
        "nonce": "n-mixed",
        "aud": "https://www.agent.com",
        "iat": now,
        "sd_hash": hash_bytes(l1_ser.encode("ascii")),
        "delegate_payload": [
            {"...": hash_disclosure(open_disc)},
            {"...": hash_disclosure(final_disc)},
        ],
    }
    # Use kb-sd-jwt typ (immediate) — typ check happens after mode inference anyway
    l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
    l2 = create_sd_jwt(l2_header, l2_payload, [open_disc, final_disc], user.private_key)

    result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )

    assert not result.valid, "Expected mixed-mode VCT L2 to be rejected"
    assert any("mixed mode" in e.lower() or ("open" in e.lower() and "final" in e.lower()) for e in result.errors), (
        f"Expected an error about mixed open/final VCTs, got: {result.errors}"
    )
