"""Tests for L1 card_id: round-trip, backward compatibility, cross-check."""

import time

from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    get_agent_keys,
    get_issuer_keys,
    get_user_keys,
)
from verifiable_intent import create_layer1, verify_chain
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures
from verifiable_intent.issuance.user import create_layer2_autonomous
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import CheckoutMandate, MandateMode, PaymentMandate, UserMandate


class TestCardIdRoundTrip:
    def test_card_id_in_l1_payload(self):
        """card_id appears as always-visible claim in L1."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        cred = IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user123",
            iat=now,
            exp=now + 3600,
            pan_last_four="8842",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
            card_id="f199c3dd-7106-478b-9b5f-7af9ca725170",
        )
        l1 = create_layer1(cred, issuer.private_key)
        claims = resolve_disclosures(l1)

        assert claims["card_id"] == "f199c3dd-7106-478b-9b5f-7af9ca725170"
        assert claims["pan_last_four"] == "8842"

    def test_card_id_none_omitted_from_payload(self):
        """When card_id is None, it is not included in the L1 payload."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        cred = IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user123",
            iat=now,
            exp=now + 3600,
            pan_last_four="8842",
            scheme="Mastercard",
            cnf_jwk=user.public_jwk,
        )
        l1 = create_layer1(cred, issuer.private_key)
        claims = resolve_disclosures(l1)

        assert "card_id" not in claims


def _build_chain(card_id=None, payment_instrument=None):
    """Build an autonomous chain with optional card_id in L1."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    now = int(time.time())
    pi = payment_instrument if payment_instrument is not None else PAYMENT_INSTRUMENT

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="user123",
        iat=now,
        exp=now + 365 * 24 * 3600,
        pan_last_four="8842",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
        card_id=card_id,
    )
    l1 = create_layer1(cred, issuer.private_key)
    l1_ser = l1.serialize()

    mandate = UserMandate(
        nonce="n1",
        aud="https://agent.example.com",
        iat=now,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "li-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
                ),
            ],
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=pi,
            constraints=[
                PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                AllowedPayeeConstraint(allowed=MERCHANTS),
            ],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS[:1],
    )

    l2 = create_layer2_autonomous(mandate, user.private_key)
    return {"issuer": issuer, "l1": l1, "l1_ser": l1_ser, "l2": l2}


class TestCardIdBackwardCompat:
    def test_no_card_id_skips_check(self):
        """Chains without card_id still pass verification (skipped check)."""
        chain = _build_chain(card_id=None)
        result = verify_chain(
            chain["l1"], chain["l2"], issuer_public_key=chain["issuer"].public_key, l1_serialized=chain["l1_ser"]
        )
        assert result.valid
        assert "l1_card_id_cross_check" in result.checks_skipped


class TestCardIdCrossCheck:
    def test_matching_card_id_passes(self):
        """card_id matching payment_instrument.id passes cross-check."""
        chain = _build_chain(card_id=PAYMENT_INSTRUMENT["id"])
        result = verify_chain(
            chain["l1"], chain["l2"], issuer_public_key=chain["issuer"].public_key, l1_serialized=chain["l1_ser"]
        )
        assert result.valid
        assert "l1_card_id_cross_check" in result.checks_performed

    def test_mismatched_card_id_fails(self):
        """card_id not matching payment_instrument.id fails cross-check."""
        chain = _build_chain(card_id="wrong-card-id-12345")
        result = verify_chain(
            chain["l1"], chain["l2"], issuer_public_key=chain["issuer"].public_key, l1_serialized=chain["l1_ser"]
        )
        assert not result.valid
        assert any("card_id" in e for e in result.errors)

    def test_card_id_set_but_pi_id_absent_fails(self):
        """card_id set in L1 but payment_instrument has no id field — fails closed.

        The chain fails because required-field validation catches missing payment_instrument.id
        before the card_id cross-check runs. Either way, the chain is invalid.
        """
        pi_no_id = {"type": "mastercard.srcDigitalCard", "description": "Mastercard **** 1234"}
        chain = _build_chain(card_id="f199c3dd-7106-478b-9b5f-7af9ca725170", payment_instrument=pi_no_id)
        result = verify_chain(
            chain["l1"], chain["l2"], issuer_public_key=chain["issuer"].public_key, l1_serialized=chain["l1_ser"]
        )
        assert not result.valid
        assert any("payment_instrument" in e for e in result.errors)
