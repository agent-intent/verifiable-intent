"""Tests for optional aud/nonce validation in verify_chain() (Finding F5)."""

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

# ---------------------------------------------------------------------------
# Chain builders
# ---------------------------------------------------------------------------

_L2_AUD = "https://www.agent.com"
_L2_NONCE = "n-auto"
_L3A_AUD = "https://www.mastercard.com"
_L3A_NONCE = "n-l3a"
_L3B_AUD = "https://tennis-warehouse.com"
_L3B_NONCE = "n-l3b"


def _find_disclosure(sd_jwt, predicate):
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _build_autonomous_chain():
    """Build a complete autonomous chain. Known aud/nonce baked into the mandates."""
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
        email="user@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)
    l1_ser = l1.serialize()

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
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    user_mandate = UserMandate(
        nonce=_L2_NONCE,
        aud=_L2_AUD,
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

    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce=_L3A_NONCE,
        aud=_L3A_AUD,
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce=_L3B_NONCE,
        aud=_L3B_AUD,
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

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


def _build_immediate_chain():
    """Build a minimal immediate (2-layer) chain."""
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
        nonce=_L2_NONCE,
        aud=_L2_AUD,
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2 = create_layer2_immediate(user_mandate, user.private_key).sd_jwt

    return {"l1": l1, "l2": l2, "l1_ser": l1_ser, "issuer": issuer, "user": user}


# ---------------------------------------------------------------------------
# L2 aud validation tests
# ---------------------------------------------------------------------------


class TestL2AudValidation:
    def test_l2_aud_mismatch_fails(self):
        """Providing a wrong expected_l2_aud must fail with a clear error."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_aud="https://example.com",  # wrong — actual is _L2_AUD
        )
        assert not result.valid
        assert any("l2 aud mismatch" in e.lower() for e in result.errors)

    def test_l2_aud_match_passes(self):
        """Providing the correct expected_l2_aud must pass and appear in checks_performed."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_aud=_L2_AUD,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert "l2_aud" in result.checks_performed

    def test_l2_aud_not_requested_present_skipped(self):
        """When expected_l2_aud is not provided but L2 has aud, it appears in checks_skipped."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            # expected_l2_aud not provided
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l2_aud" in s for s in result.checks_skipped)


# ---------------------------------------------------------------------------
# L2 nonce validation tests
# ---------------------------------------------------------------------------


class TestL2NonceValidation:
    def test_l2_nonce_mismatch_fails(self):
        """Providing a wrong expected_l2_nonce must fail with a clear error."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_nonce="wrong-nonce",
        )
        assert not result.valid
        assert any("l2 nonce mismatch" in e.lower() for e in result.errors)

    def test_l2_nonce_match_passes(self):
        """Providing the correct expected_l2_nonce must pass and appear in checks_performed."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_nonce=_L2_NONCE,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert "l2_nonce" in result.checks_performed


# ---------------------------------------------------------------------------
# L3 aud validation tests (autonomous chain)
# ---------------------------------------------------------------------------


class TestL3AudValidation:
    def test_l3_aud_mismatch_fails(self):
        """Providing a wrong expected_l3_aud must fail (checked against L3a)."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            expected_l3_payment_aud="https://wrong.example.com",
        )
        assert not result.valid
        assert any("aud mismatch" in e.lower() for e in result.errors)

    def test_l3_aud_match_passes(self):
        """Providing the correct expected_l3_payment_aud for L3a must pass and appear in checks_performed."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            expected_l3_payment_aud=_L3A_AUD,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l3a" in s and "aud" in s for s in result.checks_performed)

    def test_l3_aud_not_requested_present_skipped(self):
        """When expected_l3_aud is not provided but L3a has aud, it appears in checks_skipped."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l3a" in s and "aud" in s for s in result.checks_skipped)

    def test_l3_checkout_aud_mismatch_fails(self):
        """Wrong expected_l3_checkout_aud must fail when checked against L3b."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_checkout=chain["l3b"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            expected_l3_checkout_aud="https://wrong.example.com",
        )
        assert not result.valid
        assert any("aud mismatch" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# L3 nonce validation tests (autonomous chain)
# ---------------------------------------------------------------------------


class TestL3NonceValidation:
    def test_l3_nonce_mismatch_fails(self):
        """Providing a wrong expected_l3_nonce must fail (checked against L3a)."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            expected_l3_payment_nonce="wrong-nonce",
        )
        assert not result.valid
        assert any("nonce mismatch" in e.lower() for e in result.errors)

    def test_l3_nonce_match_passes(self):
        """Providing the correct expected_l3_nonce for L3a must pass and appear in checks_performed."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            expected_l3_payment_nonce=_L3A_NONCE,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l3a" in s and "nonce" in s for s in result.checks_performed)

    def test_l3_nonce_not_requested_present_skipped(self):
        """When expected_l3_nonce is not provided but L3a has nonce, it appears in checks_skipped."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l3a" in s and "nonce" in s for s in result.checks_skipped)


# ---------------------------------------------------------------------------
# Combined aud + nonce validation
# ---------------------------------------------------------------------------


class TestCombinedAudNonce:
    def test_both_l2_aud_and_nonce_match(self):
        """Both aud and nonce matching on L2 must pass, both in checks_performed."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_aud=_L2_AUD,
            expected_l2_nonce=_L2_NONCE,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert "l2_aud" in result.checks_performed
        assert "l2_nonce" in result.checks_performed

    def test_l2_aud_ok_nonce_wrong_fails(self):
        """Correct aud but wrong nonce on L2 must fail."""
        chain = _build_immediate_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            expected_l2_aud=_L2_AUD,
            expected_l2_nonce="bad-nonce",
        )
        assert not result.valid
        assert any("nonce mismatch" in e.lower() for e in result.errors)

    def test_split_l3_different_audiences_both_pass(self):
        """L3a and L3b have different aud/nonce; per-credential params validate correctly."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            l3_checkout=chain["l3b"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            expected_l3_payment_aud=_L3A_AUD,
            expected_l3_payment_nonce=_L3A_NONCE,
            expected_l3_checkout_aud=_L3B_AUD,
            expected_l3_checkout_nonce=_L3B_NONCE,
        )
        assert result.valid, f"Unexpected errors: {result.errors}"
        assert any("l3a" in s and "aud" in s for s in result.checks_performed)
        assert any("l3b" in s and "aud" in s for s in result.checks_performed)
        assert any("l3a" in s and "nonce" in s for s in result.checks_performed)
        assert any("l3b" in s and "nonce" in s for s in result.checks_performed)

    def test_split_l3_swapped_audiences_fails(self):
        """Swapping payment/checkout aud values must fail — validates per-credential routing."""
        chain = _build_autonomous_chain()
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            l3_checkout=chain["l3b"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            expected_l3_payment_aud=_L3B_AUD,  # swapped — L3a has _L3A_AUD
            expected_l3_checkout_aud=_L3A_AUD,  # swapped — L3b has _L3B_AUD
        )
        assert not result.valid
        assert any("aud mismatch" in e.lower() for e in result.errors)
