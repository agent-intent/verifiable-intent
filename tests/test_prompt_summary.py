"""Tests for `prompt_summary` on L2 (Autonomous mode).

spec/README.md lists `prompt_summary` in the Layer 2 claim table as
selectively disclosable in Autonomous mode, and names it among the claims a
merchant presentation may carry. These tests pin that behaviour: the claim is
hidden in the base JWT, recoverable from the disclosures, and absent entirely
when the mandate does not set it.
"""

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
from verifiable_intent.crypto.sd_jwt import resolve_disclosures

PROMPT = "Buy a cheap beginner racket, returnable"


def _make_l2(prompt_summary: str | None):
    now = int(time.time())
    issuer, user, agent = get_issuer_keys(), get_user_keys(), get_agent_keys()

    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user-001",
            iat=now,
            exp=now + 365 * 24 * 3600,
            aud="https://wallet.example.com",
            email="test@example.com",
            pan_last_four="1234",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        ),
        issuer.private_key,
    )

    user_mandate = UserMandate(
        nonce="prompt-summary-nonce-1",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary=prompt_summary,
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[AllowedMerchantConstraint(allowed=MERCHANTS)],
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    return create_layer2_autonomous(user_mandate, user.private_key)


def test_prompt_summary_is_selectively_disclosable():
    """Hidden in the base JWT, recoverable once disclosures are resolved."""
    l2 = _make_l2(PROMPT)

    assert "prompt_summary" not in l2.payload
    assert resolve_disclosures(l2)["prompt_summary"] == PROMPT


def test_prompt_summary_survives_serialization():
    """A verifier parsing the serialized L2 can recover the claim."""
    from verifiable_intent.crypto.sd_jwt import decode_sd_jwt

    l2 = _make_l2(PROMPT)
    parsed = decode_sd_jwt(l2.serialize())

    assert resolve_disclosures(parsed)["prompt_summary"] == PROMPT


def test_prompt_summary_absent_when_not_set():
    """The claim is optional: no disclosure is emitted when it is unset."""
    l2 = _make_l2(None)

    assert "prompt_summary" not in l2.payload
    assert "prompt_summary" not in resolve_disclosures(l2)
