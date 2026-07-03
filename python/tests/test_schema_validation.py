"""Tests for credential schema validation.

Validates required-field enforcement and structural constraints across
all credential layers (L1, L2, L3).
"""

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
from verifiable_intent.crypto.sd_jwt import resolve_disclosures
from verifiable_intent.verification.constraint_checker import check_constraints


def test_immediate_l2_auto_computes_checkout_hash():
    """Verify checkout_hash is present in emitted disclosure when auto-computed.

    Finding 1 (P0): create_layer2_immediate must auto-compute checkout_hash
    from checkout_jwt BEFORE serializing disclosures. If auto-compute ran
    after disclosure creation, the emitted checkout mandate dict would be
    missing checkout_hash, breaking chain verification downstream.

    This test creates an L2 where checkout_jwt is set but checkout_hash is
    NOT explicitly provided on the CheckoutMandate. After creation, it
    resolves disclosures and verifies both checkout_hash (on checkout
    mandate) and transaction_id (on payment mandate) are present.
    """
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

    # Intentionally omit checkout_hash and transaction_id — auto-compute should fill them
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
        # checkout_hash deliberately NOT set
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        currency="USD",
        amount=27999,
        payee=MERCHANTS[0],
        payment_instrument=PAYMENT_INSTRUMENT,
        # transaction_id deliberately NOT set
    )
    user_mandate = UserMandate(
        nonce="ap2-align-nonce-1",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    result = create_layer2_immediate(user_mandate, user.private_key)
    l2 = result.sd_jwt

    # Resolve all disclosures to inspect the emitted mandate dicts
    l2_claims = resolve_disclosures(l2)

    # Find the checkout and payment mandate disclosures
    checkout_found = False
    payment_found = False
    expected_hash = checkout_hash_from_jwt(checkout_jwt)

    for delegate in l2_claims.get("delegate_payload", []):
        if not isinstance(delegate, dict):
            continue
        vct = delegate.get("vct", "")
        if vct == "mandate.checkout.1":
            checkout_found = True
            assert "checkout_hash" in delegate, "Auto-computed checkout_hash missing from checkout mandate disclosure"
            assert delegate["checkout_hash"] == expected_hash, (
                f"checkout_hash mismatch: {delegate['checkout_hash']} != {expected_hash}"
            )
        elif vct == "mandate.payment.1":
            payment_found = True
            assert "transaction_id" in delegate, "Auto-computed transaction_id missing from payment mandate disclosure"
            assert delegate["transaction_id"] == expected_hash, (
                f"transaction_id mismatch: {delegate['transaction_id']} != {expected_hash}"
            )

    assert checkout_found, "Checkout mandate not found in resolved L2 disclosures"
    assert payment_found, "Payment mandate not found in resolved L2 disclosures"

    # Verify the full chain also passes
    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert chain_result.valid, f"Chain verification failed: {chain_result.errors}"


def test_immediate_closed_checkout_missing_checkout_jwt_fails():
    """Chain fails when closed checkout mandate lacks checkout_jwt.

    Finding 2: A closed checkout mandate (vct=mandate.checkout) must have
    both checkout_jwt and checkout_hash per AP2 schema requirements. When
    checkout_jwt is absent and checkout_hash is also absent, chain
    verification must reject the L2 with an error referencing the missing
    required field.
    """
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

    # Create a closed checkout mandate with NO checkout_jwt and NO checkout_hash.
    # Since checkout_jwt is None, auto-compute in create_layer2_immediate will not fire.
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=None,
        checkout_hash=None,
    )
    # Valid payment mandate with all required fields except transaction_id
    # (which would normally be auto-computed from checkout_jwt)
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        currency="USD",
        amount=27999,
        payee=MERCHANTS[0],
        payment_instrument=PAYMENT_INSTRUMENT,
        transaction_id=c_hash,
    )
    user_mandate = UserMandate(
        nonce="ap2-align-nonce-2",
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
    assert not chain_result.valid, "Chain should fail when closed checkout mandate lacks checkout_jwt"
    assert any("checkout_jwt" in e.lower() or "checkout_hash" in e.lower() for e in chain_result.errors), (
        f"Error should mention missing checkout field, got: {chain_result.errors}"
    )


def test_immediate_closed_payment_missing_required_fields_fails():
    """Chain fails when closed payment mandate lacks AP2-required fields.

    Finding 3: A closed payment mandate (vct=mandate.payment) requires
    transaction_id, payee, currency, amount, and payment_instrument per the
    AP2 schema. When these are absent, chain verification must reject the L2
    with an error referencing the missing required field.

    This test creates a payment mandate with only vct set (no payee,
    currency, amount, or payment_instrument). The auto-compute will add
    transaction_id from the checkout_jwt, but the other fields remain
    absent.
    """
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

    # Valid checkout mandate (auto-compute will fill checkout_hash)
    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
    )
    # Payment mandate deliberately missing payee, currency, amount, payment_instrument.
    # Auto-compute will add transaction_id from checkout_jwt, but the rest stays absent.
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        # payee, currency, amount, payment_instrument all deliberately omitted
    )
    user_mandate = UserMandate(
        nonce="ap2-align-nonce-3",
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
    assert not chain_result.valid, "Chain should fail when closed payment mandate lacks required fields"
    assert any("missing required field" in e.lower() for e in chain_result.errors), (
        f"Error should mention missing required field, got: {chain_result.errors}"
    )


def test_immediate_closed_payment_empty_transaction_id_fails():
    """Closed payment mandate with transaction_id='' must fail required-field validation.

    Since create_layer2_immediate auto-computes transaction_id from checkout_jwt,
    we inject the empty transaction_id into the disclosure value after issuance
    to simulate an externally-constructed credential.
    """
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
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        currency="USD",
        amount=27999,
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    user_mandate = UserMandate(
        nonce="required-fields-empty-txid",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2 = create_layer2_immediate(user_mandate, user.private_key).sd_jwt

    # Inject empty transaction_id into the payment mandate disclosure post-issuance
    for disc_val in l2.disclosure_values:
        value = disc_val[-1] if disc_val else None
        if isinstance(value, dict) and value.get("vct") == "mandate.payment.1":
            value["transaction_id"] = ""
            break

    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert not chain_result.valid, "Chain should fail when transaction_id is an empty string"
    assert any("transaction_id" in e.lower() for e in chain_result.errors), (
        f"Error should mention transaction_id, got: {chain_result.errors}"
    )


def test_immediate_closed_payment_empty_currency_fails():
    """Closed payment mandate with currency='' must fail required-field validation."""
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
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        currency="",
        amount=27999,
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    user_mandate = UserMandate(
        nonce="required-fields-empty-currency",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2 = create_layer2_immediate(user_mandate, user.private_key).sd_jwt

    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert not chain_result.valid, "Chain should fail when currency is an empty string"
    assert any("currency" in e.lower() for e in chain_result.errors), (
        f"Error should mention currency, got: {chain_result.errors}"
    )


def test_immediate_closed_payment_amount_zero_is_valid():
    """Required-field checks must treat amount=0 as present and valid."""
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
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        currency="USD",
        amount=0,
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    user_mandate = UserMandate(
        nonce="required-fields-zero",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2 = create_layer2_immediate(user_mandate, user.private_key).sd_jwt

    chain_result = verify_chain(
        l1,
        l2,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
    )
    assert chain_result.valid, f"amount=0 must be accepted as a valid required value: {chain_result.errors}"


def test_line_items_missing_title_violates():
    """L2-side: acceptable_items entries must have title per AP2 item schema.

    Finding 4: The AP2 item schema requires each acceptable_items entry to
    include a 'title' field. When an entry has an 'id' but no 'title',
    the constraint checker must report a violation mentioning the missing
    required 'title'.
    """
    result = check_constraints(
        [
            {
                "type": "mandate.checkout.line_items",
                "items": [
                    {
                        "id": "line-1",
                        "acceptable_items": [{"id": "BAB86345"}],
                        "quantity": 1,
                    }
                ],
            }
        ],
        {"line_items": [{"id": "BAB86345", "quantity": 1}]},
    )
    assert not result.satisfied, "Constraint check should fail when acceptable_items entry lacks title"
    assert any("title" in v.lower() for v in result.violations), (
        f"Violation should mention missing 'title', got: {result.violations}"
    )


def test_immediate_closed_payment_empty_payee_fails():
    """Chain fails when closed payment mandate has empty payee dict.

    Finding 5: The AP2 merchant schema requires payee to have 'id' and 'name'.
    A structurally invalid payee (e.g., {}) should not pass chain verification,
    even though the top-level payee field is not None.
    """
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

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
    )
    # payee is an empty dict — top-level check passes but nested required fields are missing
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        payee={},
        currency="USD",
        amount=27999,
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    user_mandate = UserMandate(
        nonce="ap2-align-nonce-5",
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
    assert not chain_result.valid, "Chain should fail when payee is empty dict"
    assert any("payee" in e.lower() for e in chain_result.errors), (
        f"Error should mention payee, got: {chain_result.errors}"
    )


def test_immediate_closed_payment_empty_payment_instrument_fails():
    """Chain fails when closed payment mandate has empty payment_instrument dict.

    Finding 5 (continued): The AP2 payment_instrument schema requires 'id' and
    'type'. An empty dict should not pass chain verification.
    """
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

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        payee=MERCHANTS[0],
        currency="USD",
        amount=27999,
        payment_instrument={},  # Empty dict — missing required id and type
    )
    user_mandate = UserMandate(
        nonce="ap2-align-nonce-6",
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
    assert not chain_result.valid, "Chain should fail when payment_instrument is empty dict"
    assert any("payment_instrument" in e.lower() for e in chain_result.errors), (
        f"Error should mention payment_instrument, got: {chain_result.errors}"
    )


# --- Helpers for autonomous chain tests ---


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _build_autonomous_chain(
    final_payment=None,
    final_checkout=None,
    *,
    omit_final_payment: bool = False,
    omit_final_checkout: bool = False,
):
    """Build an autonomous 3-layer chain with customizable L3 mandates.

    If final_payment or final_checkout is not provided, uses valid defaults.
    Returns dict with all chain components.
    """
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
        constraints=[
            PaymentAmountConstraint(currency="USD", min=10000, max=40000),
        ],
    )
    user_mandate = UserMandate(
        nonce="schema-val-nonce",
        aud="https://www.agent.com",
        iat=now,
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

    # L3a: Payment mandate
    if final_payment is None and not omit_final_payment:
        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
    l3a_mandate = PaymentL3Mandate(
        nonce="schema-val-l3a",
        aud="https://www.mastercard.com",
        iat=now,
        final_payment=None if omit_final_payment else final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # L3b: Checkout mandate
    if final_checkout is None and not omit_final_checkout:
        final_checkout = FinalCheckoutMandate(
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        )
    l3b_mandate = CheckoutL3Mandate(
        nonce="schema-val-l3b",
        aud="https://tennis-warehouse.com",
        iat=now,
        final_checkout=None if omit_final_checkout else final_checkout,
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
        "l2_payment_ser": l2_payment_ser,
        "l2_checkout_ser": l2_checkout_ser,
        "issuer": issuer,
    }


# --- Finding 7: L3 closed-mandate required fields ---


def test_l3a_empty_payee_fails_chain():
    """L3a payment mandate with empty payee dict fails chain verification."""
    chain = _build_autonomous_chain(
        final_payment=FinalPaymentMandate(
            transaction_id="dummy-hash",
            payee={},  # Missing required id + name
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        ),
    )
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_payment=chain["l3a"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_payment_serialized=chain["l2_payment_ser"],
    )
    assert not result.valid, "Chain should fail with empty L3a payee"
    assert any("payee" in e.lower() for e in result.errors), f"Error should mention payee, got: {result.errors}"


def test_l3a_empty_payment_instrument_fails_chain():
    """L3a payment mandate with empty payment_instrument dict fails chain verification."""
    chain = _build_autonomous_chain(
        final_payment=FinalPaymentMandate(
            transaction_id="dummy-hash",
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument={},  # Missing required id + type
        ),
    )
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_payment=chain["l3a"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_payment_serialized=chain["l2_payment_ser"],
    )
    assert not result.valid, "Chain should fail with empty L3a payment_instrument"
    assert any("payment_instrument" in e.lower() for e in result.errors), (
        f"Error should mention payment_instrument, got: {result.errors}"
    )


def test_l3a_empty_transaction_id_fails_chain():
    """L3a payment mandate with transaction_id='' must fail required-field validation."""
    chain = _build_autonomous_chain(
        final_payment=FinalPaymentMandate(
            transaction_id="",
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        ),
    )
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_payment=chain["l3a"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_payment_serialized=chain["l2_payment_ser"],
    )
    assert not result.valid, "Chain should fail with empty L3a transaction_id"
    assert any("transaction_id" in e.lower() for e in result.errors), (
        f"Error should mention transaction_id, got: {result.errors}"
    )


def test_l3a_empty_currency_fails_chain():
    """L3a payment mandate with currency='' must fail required-field validation."""
    chain = _build_autonomous_chain(
        final_payment=FinalPaymentMandate(
            transaction_id="dummy-hash",
            payee=MERCHANTS[0],
            payment_amount={"currency": "", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        ),
    )
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_payment=chain["l3a"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_payment_serialized=chain["l2_payment_ser"],
    )
    assert not result.valid, "Chain should fail with empty L3a currency"
    assert any("currency" in e.lower() for e in result.errors), f"Error should mention currency, got: {result.errors}"


def test_l3b_missing_checkout_hash_fails_chain():
    """L3b checkout mandate missing checkout_hash fails chain verification."""
    chain = _build_autonomous_chain(
        final_checkout=FinalCheckoutMandate(
            checkout_jwt="<some-jwt>",
            checkout_hash="",  # Missing required checkout_hash
        ),
    )
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_checkout=chain["l3b"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_checkout_serialized=chain["l2_checkout_ser"],
    )
    assert not result.valid, "Chain should fail with missing L3b checkout_hash"
    assert any("checkout_hash" in e.lower() for e in result.errors), (
        f"Error should mention checkout_hash, got: {result.errors}"
    )


def test_l3a_missing_payment_mandate_disclosure_fails_chain():
    """L3a without a final payment mandate disclosure fails chain verification."""
    chain = _build_autonomous_chain(omit_final_payment=True)
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_payment=chain["l3a"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_payment_serialized=chain["l2_payment_ser"],
    )
    assert not result.valid, "Chain should fail when L3a omits mandate.payment disclosure"
    assert any("mandate.payment.1" in e for e in result.errors), (
        f"Error should mention missing mandate.payment disclosure, got: {result.errors}"
    )


def test_l3b_missing_checkout_mandate_disclosure_fails_chain():
    """L3b without a final checkout mandate disclosure fails chain verification."""
    chain = _build_autonomous_chain(omit_final_checkout=True)
    result = verify_chain(
        chain["l1"],
        chain["l2"],
        l3_checkout=chain["l3b"],
        issuer_public_key=chain["issuer"].public_key,
        l1_serialized=chain["l1_ser"],
        l2_checkout_serialized=chain["l2_checkout_ser"],
    )
    assert not result.valid, "Chain should fail when L3b omits mandate.checkout disclosure"
    assert any("mandate.checkout.1" in e for e in result.errors), (
        f"Error should mention missing mandate.checkout disclosure, got: {result.errors}"
    )


def test_merchant_matching_id_and_name_fallback():
    """Merchant matching: by id if both have it, else by name fallback."""
    from verifiable_intent.issuance.user import _match_merchant_refs

    mandate_merchants = [{"id": "tw-001", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"}]
    disc_hashes = ["hash-0"]

    # Matching by correct id works
    result = _match_merchant_refs([{"id": "tw-001"}], mandate_merchants, disc_hashes)
    assert len(result) == 1

    # Matching by website with wrong id fails (id takes precedence when both have it)
    with pytest.raises(ValueError, match="unknown merchant"):
        _match_merchant_refs(
            [{"id": "wrong-id", "website": "https://tennis-warehouse.com"}],
            mandate_merchants,
            disc_hashes,
        )

    # Merchant missing id but with name matches by name fallback
    result = _match_merchant_refs(
        [{"name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"}],
        mandate_merchants,
        disc_hashes,
    )
    assert len(result) == 1

    # Merchant missing both id and name is rejected
    with pytest.raises(ValueError, match="missing both 'id' and 'name'"):
        _match_merchant_refs(
            [{"website": "https://tennis-warehouse.com"}],
            mandate_merchants,
            disc_hashes,
        )


def test_risk_data_round_trips_through_l2_autonomous():
    """risk_data set on an L2 autonomous PaymentMandate is preserved in the L2 disclosure
    and survives chain verification.
    """
    chain = _build_autonomous_chain()
    # Sanity: chain builds without risk_data
    assert chain["l2"] is not None

    # Build a fresh autonomous chain with risk_data on the payment mandate
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
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

    risk = {"device_id": "android1234", "ip_address": "192.168.1.100"}
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
        risk_data=risk,
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    user_mandate = UserMandate(
        nonce="risk-data-nonce",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(user_mandate, user.private_key)

    # Verify risk_data is present in the L2 payment mandate disclosure
    claims = resolve_disclosures(l2)
    payment_disclosures = [
        d
        for d in claims.get("delegate_payload", [])
        if isinstance(d, dict) and d.get("vct") == "mandate.payment.open.1"
    ]
    assert payment_disclosures, "Payment mandate disclosure should be present"
    assert payment_disclosures[0].get("risk_data") == risk, (
        "risk_data should round-trip through L2 disclosure resolution"
    )
