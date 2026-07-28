"""Tests for L2 reference binding: payment.reference constraint (v2).

V2 replaces conditionalCartHash + conditionalCartDisclosureHash with
conditional_transaction_id (hash of checkout disclosure).
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
    verify_l2_reference_binding,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt, resolve_disclosures


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _build_l1_l2():
    """Helper: build L1 and autonomous L2 with standard v2 constraints."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    now = int(time.time())

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 365 * 24 * 3600,
        aud="https://wallet.example.com",
        email="alice@example.com",
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
        nonce="ref-nonce-1",
        aud="https://www.agent.com",
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
    return l1, l2, now, issuer, user, agent


class TestReferenceConstraintIssuance:
    def test_l2_has_payment_reference_constraint(self):
        """create_layer2_autonomous() should inject a payment.reference constraint."""
        l1, l2, _, _, _, _ = _build_l1_l2()

        l2_claims = resolve_disclosures(l2)
        payment_mandate = None
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                payment_mandate = delegate
                break

        assert payment_mandate is not None, "No payment mandate in L2"
        constraints = payment_mandate.get("constraints", [])
        ref_constraints = [c for c in constraints if c.get("type") == "mandate.payment.reference"]
        assert len(ref_constraints) == 1, f"Expected 1 payment.reference, got {len(ref_constraints)}"
        ref = ref_constraints[0]
        assert "conditional_transaction_id" in ref
        assert ref["conditional_transaction_id"] != ""

    def test_conditional_transaction_id_is_checkout_disclosure_hash(self):
        """conditional_transaction_id should match hash of checkout disclosure."""
        from verifiable_intent.crypto.disclosure import hash_disclosure

        l1, l2, _, _, _, _ = _build_l1_l2()

        l2_claims = resolve_disclosures(l2)
        # Find the checkout disclosure string
        checkout_disc_b64 = _find_disclosure(
            l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )
        assert checkout_disc_b64 is not None

        # Find the reference constraint
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                constraints = delegate.get("constraints", [])
                for c in constraints:
                    if c.get("type") == "mandate.payment.reference":
                        expected = hash_disclosure(checkout_disc_b64)
                        assert c["conditional_transaction_id"] == expected
                        return
        pytest.fail("payment.reference constraint not found in L2")


class TestReferenceBindingVerification:
    def test_verify_passes_with_correct_hashes(self):
        """verify_l2_reference_binding() should pass with SDK-produced L2."""
        l1, l2, _, _, _, _ = _build_l1_l2()

        l2_claims = resolve_disclosures(l2)
        checkout_mandate = None
        payment_mandate = None
        checkout_disc_b64 = None
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict):
                if delegate.get("vct") == "mandate.checkout.open.1":
                    checkout_mandate = delegate
                elif delegate.get("vct") == "mandate.payment.open.1":
                    payment_mandate = delegate

        checkout_disc_b64 = _find_disclosure(
            l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )
        assert checkout_mandate is not None
        assert payment_mandate is not None
        assert checkout_disc_b64 is not None

        valid, error = verify_l2_reference_binding(checkout_mandate, payment_mandate, checkout_disc_b64)
        assert valid, f"Verification should pass but failed: {error}"

    def test_verify_fails_with_wrong_disclosure(self):
        """verify_l2_reference_binding() should fail if checkout disclosure doesn't match."""
        l1, l2, _, _, _, _ = _build_l1_l2()

        l2_claims = resolve_disclosures(l2)
        checkout_mandate = None
        payment_mandate = None
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict):
                if delegate.get("vct") == "mandate.checkout.open.1":
                    checkout_mandate = delegate
                elif delegate.get("vct") == "mandate.payment.open.1":
                    payment_mandate = delegate

        assert checkout_mandate is not None
        assert payment_mandate is not None

        # Provide a wrong checkout disclosure string
        valid, error = verify_l2_reference_binding(checkout_mandate, payment_mandate, "wrong-disclosure-string")
        assert not valid, "Verification should fail with wrong disclosure"
        assert "mismatch" in error.lower()

    def test_verify_fails_with_missing_transaction_id(self):
        """verify_l2_reference_binding() should fail if conditional_transaction_id is missing."""
        l1, l2, _, _, _, _ = _build_l1_l2()

        l2_claims = resolve_disclosures(l2)
        checkout_mandate = None
        payment_mandate = None
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict):
                if delegate.get("vct") == "mandate.checkout.open.1":
                    checkout_mandate = delegate
                elif delegate.get("vct") == "mandate.payment.open.1":
                    payment_mandate = delegate

        checkout_disc_b64 = _find_disclosure(
            l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )

        # Strip the conditional_transaction_id from the reference constraint
        stripped_payment = dict(payment_mandate)
        stripped_payment["constraints"] = []
        for c in payment_mandate["constraints"]:
            if c.get("type") == "mandate.payment.reference":
                stripped_c = dict(c)
                stripped_c["conditional_transaction_id"] = ""
                stripped_payment["constraints"].append(stripped_c)
            else:
                stripped_payment["constraints"].append(c)

        valid, error = verify_l2_reference_binding(checkout_mandate, stripped_payment, checkout_disc_b64)
        assert not valid, "Verification should fail when conditional_transaction_id is empty"
        assert "missing" in error.lower()


class TestChainWithReferenceBinding:
    def test_full_chain_validates_l2_binding(self):
        """verify_chain(, skip_issuer_verification=True) should validate L2 reference binding in autonomous mode."""
        l1, l2, now, issuer, user, agent = _build_l1_l2()
        merchant = get_merchant_keys()

        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
        _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="ref-nonce-2",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"

    def test_chain_passes_with_payment_only_l2(self):
        """verify_chain(, skip_issuer_verification=True) with only L2 payment disclosure skips reference binding."""
        l1, l2, now, issuer, user, agent = _build_l1_l2()
        merchant = get_merchant_keys()

        # Strip checkout disclosure from L2
        checkout_disc_indices = []
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if len(disc_val) >= 2 else None
            if isinstance(value, dict) and value.get("vct") == "mandate.checkout.open.1":
                checkout_disc_indices.append(i)
        # Also strip item disclosures
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if len(disc_val) >= 2 else None
            if isinstance(value, dict) and "id" in value and "title" in value:
                checkout_disc_indices.append(i)
        stripped_disclosures = [d for i, d in enumerate(l2.disclosures) if i not in checkout_disc_indices]
        stripped_values = [v for i, v in enumerate(l2.disclosure_values) if i not in checkout_disc_indices]
        l2_stripped = SdJwt(
            header=l2.header,
            payload=l2.payload,
            signature=l2.signature,
            disclosures=stripped_disclosures,
            disclosure_values=stripped_values,
        )
        l2_stripped_ser = l2_stripped.serialize()
        l2_base_jwt = l2_stripped_ser.split("~")[0]

        payment_disc = _find_disclosure(
            l2_stripped, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
        )
        merchant_disc = _find_disclosure(
            l2_stripped, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse"
        )

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="ref-nonce-3",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        result = verify_chain(
            l1,
            l2_stripped,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_stripped_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert result.valid, f"Chain should pass with payment-only L2: {result.errors}"
        assert result.l2_checkout_disclosed is False
        assert result.l2_payment_disclosed is True
        assert any("reference" in s.lower() for s in result.checks_skipped)

    def test_chain_fails_with_no_mandates_disclosed(self):
        """verify_chain(, skip_issuer_verification=True) should fail if both L2 mandates are withheld."""
        l1, l2, now, issuer, user, agent = _build_l1_l2()
        merchant = get_merchant_keys()

        # Strip ALL mandate disclosures from L2
        mandate_indices = []
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if len(disc_val) >= 2 else None
            if isinstance(value, dict) and value.get("vct", "").startswith("mandate."):
                mandate_indices.append(i)
        stripped_disclosures = [d for i, d in enumerate(l2.disclosures) if i not in mandate_indices]
        stripped_values = [v for i, v in enumerate(l2.disclosure_values) if i not in mandate_indices]
        l2_stripped = SdJwt(
            header=l2.header,
            payload=l2.payload,
            signature=l2.signature,
            disclosures=stripped_disclosures,
            disclosure_values=stripped_values,
        )
        l2_stripped_ser = l2_stripped.serialize()
        l2_base_jwt = l2_stripped_ser.split("~")[0]

        # We need disclosures for L3a but they're stripped from the L2 presentation
        # Just use any valid disclosure strings from the original L2
        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="ref-nonce-no-mandates",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        result = verify_chain(
            l1,
            l2_stripped,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_stripped_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert not result.valid, "Chain should fail with no L2 mandates"
        # When mandate disclosures are stripped, mode inference cannot detect open VCTs and defaults
        # to immediate. The autonomous L2 typ (kb-sd-jwt+kb) then fails the immediate-mode typ check.
        # Any rejection is acceptable here — the important invariant is not result.valid.
        assert result.errors, "Expected at least one error, got none"

    def test_chain_reports_disclosure_status(self):
        """verify_chain(, skip_issuer_verification=True) should report both mandates as disclosed for full chain."""
        l1, l2, now, issuer, user, agent = _build_l1_l2()
        merchant = get_merchant_keys()

        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        checkout_disc = _find_disclosure(
            l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )
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
            nonce="ref-nonce-status",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
        l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_ser,
            l2_payment_serialized=l2_payment_ser,
            l2_checkout_serialized=l2_checkout_ser,
        )
        assert result.valid, f"Full chain should pass: {result.errors}"
        assert result.l2_checkout_disclosed is True
        assert result.l2_payment_disclosed is True
        assert "l2_reference_binding" in result.checks_performed

    def test_chain_reports_skipped_checks(self):
        """verify_chain(, skip_issuer_verification=True) should report skipped checks for partial disclosure."""
        l1, l2, now, issuer, user, agent = _build_l1_l2()
        merchant = get_merchant_keys()

        # Strip checkout disclosure from L2
        checkout_disc_indices = []
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if len(disc_val) >= 2 else None
            if isinstance(value, dict) and value.get("vct") == "mandate.checkout.open.1":
                checkout_disc_indices.append(i)
        for i, disc_val in enumerate(l2.disclosure_values):
            value = disc_val[-1] if len(disc_val) >= 2 else None
            if isinstance(value, dict) and "id" in value and "title" in value:
                checkout_disc_indices.append(i)
        l2_stripped = SdJwt(
            header=l2.header,
            payload=l2.payload,
            signature=l2.signature,
            disclosures=[d for i, d in enumerate(l2.disclosures) if i not in checkout_disc_indices],
            disclosure_values=[v for i, v in enumerate(l2.disclosure_values) if i not in checkout_disc_indices],
        )
        l2_stripped_ser = l2_stripped.serialize()
        l2_base_jwt = l2_stripped_ser.split("~")[0]

        payment_disc = _find_disclosure(
            l2_stripped, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
        )
        merchant_disc = _find_disclosure(
            l2_stripped, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse"
        )

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="ref-nonce-skipped",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        result = verify_chain(
            l1,
            l2_stripped,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_stripped_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert result.valid, f"Partial chain should pass: {result.errors}"
        assert len(result.checks_skipped) > 0
        assert any("l2_reference" in s for s in result.checks_skipped)
