"""Tests for mode enforcement on L2 issuance functions (Finding F4)."""

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
    get_merchant_keys,
    get_user_keys,
)
from verifiable_intent import (
    AllowedMerchantConstraint,
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    MandateMode,
    PaymentAmountConstraint,
    PaymentMandate,
    UserMandate,
    create_layer2_autonomous,
    create_layer2_immediate,
)


def _make_immediate_mandate(now: int, user_keys, merchant_keys) -> UserMandate:
    """Build a minimal valid Immediate-mode UserMandate."""
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant_keys)
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
        payee={"id": "merchant-wimbledon-1", "name": "Wimbledon Sports"},
        payment_instrument=PAYMENT_INSTRUMENT,
        transaction_id=c_hash,
    )
    return UserMandate(
        nonce="test-nonce",
        aud="https://agent.example.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )


def _make_autonomous_mandate(now: int, user_keys, agent_keys) -> UserMandate:
    """Build a minimal valid Autonomous-mode UserMandate."""
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent_keys.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
            CheckoutLineItemsConstraint(
                items=[
                    {
                        "id": "item-racket-1",
                        "acceptable_items": ACCEPTABLE_ITEMS,
                        "quantity": 1,
                    }
                ]
            ),
        ],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent_keys.public_jwk,
        cnf_kid="agent-key-1",
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=[
            PaymentAmountConstraint(max=40000),
        ],
    )
    return UserMandate(
        nonce="test-nonce",
        aud="https://agent.example.com",
        iat=now,
        mode=MandateMode.AUTONOMOUS,
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )


# ---------------------------------------------------------------------------
# Mode mismatch tests
# ---------------------------------------------------------------------------


def test_immediate_function_rejects_autonomous_mandate():
    """create_layer2_immediate() must raise ValueError when mode=AUTONOMOUS."""
    now = int(time.time())
    user = get_user_keys()
    agent = get_agent_keys()
    mandate = _make_autonomous_mandate(now, user, agent)
    assert mandate.mode == MandateMode.AUTONOMOUS

    with pytest.raises(ValueError, match="create_layer2_immediate\\(\\) requires mode=IMMEDIATE"):
        create_layer2_immediate(mandate, user.private_key)


def test_autonomous_function_rejects_immediate_mandate():
    """create_layer2_autonomous() must raise ValueError when mode=IMMEDIATE."""
    now = int(time.time())
    user = get_user_keys()
    merchant = get_merchant_keys()
    mandate = _make_immediate_mandate(now, user, merchant)
    assert mandate.mode == MandateMode.IMMEDIATE

    with pytest.raises(ValueError, match="create_layer2_autonomous\\(\\) requires mode=AUTONOMOUS"):
        create_layer2_autonomous(mandate, user.private_key)


# ---------------------------------------------------------------------------
# Happy-path tests (correct mode passes without error)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Error message content tests
# ---------------------------------------------------------------------------


def test_immediate_error_includes_wrong_mode_value():
    """Error message from create_layer2_immediate() must include the actual mode value."""
    now = int(time.time())
    user = get_user_keys()
    agent = get_agent_keys()
    mandate = _make_autonomous_mandate(now, user, agent)

    with pytest.raises(ValueError, match="AUTONOMOUS"):
        create_layer2_immediate(mandate, user.private_key)


def test_autonomous_error_includes_wrong_mode_value():
    """Error message from create_layer2_autonomous() must include the actual mode value."""
    now = int(time.time())
    user = get_user_keys()
    merchant = get_merchant_keys()
    mandate = _make_immediate_mandate(now, user, merchant)

    with pytest.raises(ValueError, match="IMMEDIATE"):
        create_layer2_autonomous(mandate, user.private_key)


# ---------------------------------------------------------------------------
# Non-enum mode value tests (P3 fix: AttributeError → clean ValueError)
# ---------------------------------------------------------------------------


def test_immediate_with_string_mode_raises_clean_error():
    """String mode value (not MandateMode enum) must raise ValueError, not AttributeError."""
    now = int(time.time())
    user = get_user_keys()
    agent = get_agent_keys()
    mandate = _make_autonomous_mandate(now, user, agent)
    # Mutate to a non-enum string after construction
    mandate.mode = "AUTONOMOUS"

    with pytest.raises(ValueError, match="AUTONOMOUS"):
        create_layer2_immediate(mandate, user.private_key)


def test_autonomous_with_string_mode_raises_clean_error():
    """String mode value (not MandateMode enum) must raise ValueError, not AttributeError."""
    now = int(time.time())
    user = get_user_keys()
    merchant = get_merchant_keys()
    mandate = _make_immediate_mandate(now, user, merchant)
    # Mutate to a non-enum string after construction
    mandate.mode = "IMMEDIATE"

    with pytest.raises(ValueError, match="IMMEDIATE"):
        create_layer2_autonomous(mandate, user.private_key)
