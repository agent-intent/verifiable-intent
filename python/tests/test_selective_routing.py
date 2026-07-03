"""Tests for selective disclosure routing (using helpers instead of agent.service) (v2)."""

from __future__ import annotations

import time

import pytest

from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    build_role_presentations,
    get_agent_keys,
    get_issuer_keys,
    get_user_keys,
)
from verifiable_intent import (
    AllowedMerchantConstraint,
    CheckoutMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt, decode_sd_jwt, resolve_disclosures


def test_build_role_presentations_splits_checkout_and_payment_views():
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
        constraints=[AllowedMerchantConstraint(allowed=MERCHANTS)],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    l2 = create_layer2_autonomous(
        UserMandate(
            nonce="n-1",
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

    l2_checkout_only_ser, l2_payment_only_ser = build_role_presentations(l2, l2.serialize())
    l2_checkout_only = decode_sd_jwt(l2_checkout_only_ser)
    l2_payment_only = decode_sd_jwt(l2_payment_only_ser)

    cart_claims = resolve_disclosures(l2_checkout_only)
    payment_claims = resolve_disclosures(l2_payment_only)

    cart_delegates = cart_claims.get("delegate_payload", [])
    payment_delegates = payment_claims.get("delegate_payload", [])

    assert any(d.get("vct") == "mandate.checkout.open.1" for d in cart_delegates if isinstance(d, dict))
    assert not any(d.get("vct") == "mandate.payment.open.1" for d in cart_delegates if isinstance(d, dict))

    assert any(d.get("vct") == "mandate.payment.open.1" for d in payment_delegates if isinstance(d, dict))
    assert not any(d.get("vct") == "mandate.checkout.open.1" for d in payment_delegates if isinstance(d, dict))

    # Network-side presentation must include merchant entries used by payment.payee checks.
    assert any(
        isinstance(dv[-1], dict) and dv[-1].get("name") == "Tennis Warehouse"
        for dv in l2_payment_only.disclosure_values
    )


def test_build_role_presentations_rejects_missing_checkout_disclosures():
    """Routing must fail closed when no checkout mandate is found, not leak full L2."""
    # Construct an SdJwt with only non-mandate disclosures (e.g. a plain string).
    l2_no_mandates = SdJwt(
        header={"alg": "ES256", "typ": "kb-sd-jwt+kb"},
        payload={"iss": "test", "delegate_payload": []},
        signature=b"fake",
        disclosures=["aaa"],
        disclosure_values=[["salt", "key", "just-a-string"]],
    )
    with pytest.raises(ValueError, match="No checkout mandate disclosures found"):
        build_role_presentations(l2_no_mandates, "fallback")


def test_build_role_presentations_rejects_missing_payment_disclosures():
    """Routing must fail closed when no payment mandate is found, not leak full L2."""
    # SdJwt with a checkout mandate but no payment mandate.
    l2_checkout_only = SdJwt(
        header={"alg": "ES256", "typ": "kb-sd-jwt+kb"},
        payload={"iss": "test", "delegate_payload": []},
        signature=b"fake",
        disclosures=["bbb"],
        disclosure_values=[["salt", "key", {"vct": "mandate.checkout.open.1"}]],
    )
    with pytest.raises(ValueError, match="No payment mandate disclosures found"):
        build_role_presentations(l2_checkout_only, "fallback")
