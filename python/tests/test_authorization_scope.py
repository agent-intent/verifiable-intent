"""Tests for L2 authorization scoping: SD refs must match constraint subset (Finding 1).

Verifies that create_layer2_autonomous() only includes disclosure refs
for merchants/items that the constraint actually references, not all
merchants/items in the mandate.
"""

from __future__ import annotations

import time

import pytest

from helpers import ACCEPTABLE_ITEMS, MERCHANTS, PAYMENT_INSTRUMENT, get_agent_keys, get_issuer_keys, get_user_keys
from verifiable_intent import (
    CheckoutMandate,
    IssuerCredential,
    MandateMode,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
)


def _build_l2_with_constraints(checkout_constraints=None, payment_constraints=None):
    """Build L1+L2 with custom constraints for scope testing."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    now = int(time.time())

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    l1 = create_layer1(cred, issuer.private_key)

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=checkout_constraints or [],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=payment_constraints or [],
    )
    user_mandate = UserMandate(
        nonce="scope-test",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
        merchants=MERCHANTS,  # 2 merchants
        acceptable_items=ACCEPTABLE_ITEMS,  # 2 items
    )
    l2 = create_layer2_autonomous(user_mandate, user.private_key)
    return l2


def _count_sd_refs(constraint_dict, field_name):
    """Count SD refs ({"...": hash}) in a constraint field."""
    refs = constraint_dict.get(field_name, [])
    return sum(1 for r in refs if isinstance(r, dict) and "..." in r)


class TestMerchantConstraintSubset:
    def test_l2_merchant_constraint_subset(self):
        """Constraint with 1 of 2 merchants → L2 only refs that 1 merchant."""
        # Only allow first merchant
        l2 = _build_l2_with_constraints(
            checkout_constraints=[
                AllowedMerchantConstraint(allowed=[MERCHANTS[0]]),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.allowed_merchants":
                        assert _count_sd_refs(c, "allowed") == 1, (
                            f"Expected 1 merchant SD ref, got {_count_sd_refs(c, 'allowed')}"
                        )
                        return
        pytest.fail("checkout mandate with allowed_merchant constraint not found")

    def test_l2_merchant_constraint_all(self):
        """Constraint with all merchants → L2 refs all merchants."""
        l2 = _build_l2_with_constraints(
            checkout_constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.allowed_merchants":
                        assert _count_sd_refs(c, "allowed") == 2
                        return
        pytest.fail("checkout mandate with allowed_merchant constraint not found")


class TestItemConstraintSubset:
    def test_l2_item_constraint_subset(self):
        """Constraint with 1 of 2 items → L2 only refs that 1 item."""
        l2 = _build_l2_with_constraints(
            checkout_constraints=[
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-item-1", "acceptable_items": [ACCEPTABLE_ITEMS[0]], "quantity": 1}],
                ),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.line_items":
                        items_list = c.get("items", [])
                        assert len(items_list) == 1, f"Expected 1 item entry, got {len(items_list)}"
                        assert _count_sd_refs(items_list[0], "acceptable_items") == 1, (
                            f"Expected 1 item SD ref, got {_count_sd_refs(items_list[0], 'acceptable_items')}"
                        )
                        return
        pytest.fail("checkout mandate with line_items constraint not found")

    def test_l2_item_constraint_subset_by_sku(self):
        """Constraint using sku key (spec-valid) resolves to scoped SD refs."""
        l2 = _build_l2_with_constraints(
            checkout_constraints=[
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-item-1", "acceptable_items": [{"sku": "BAB86345"}], "quantity": 1}],
                ),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.line_items":
                        items_list = c.get("items", [])
                        assert len(items_list) == 1
                        assert _count_sd_refs(items_list[0], "acceptable_items") == 1
                        return
        pytest.fail("checkout mandate with line_items constraint not found")

    def test_l2_item_constraint_all(self):
        """Constraint with all items → L2 refs all items."""
        l2 = _build_l2_with_constraints(
            checkout_constraints=[
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS, "quantity": 2}],
                ),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.line_items":
                        items_list = c.get("items", [])
                        assert len(items_list) == 1, f"Expected 1 item entry, got {len(items_list)}"
                        assert _count_sd_refs(items_list[0], "acceptable_items") == 2
                        return
        pytest.fail("checkout mandate with line_items constraint not found")


class TestPayeeConstraintSubset:
    def test_l2_payee_constraint_subset(self):
        """Payee constraint with 1 merchant → L2 only refs that 1."""
        l2 = _build_l2_with_constraints(
            payment_constraints=[
                AllowedPayeeConstraint(allowed=[MERCHANTS[0]]),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.payment.allowed_payees":
                        assert _count_sd_refs(c, "allowed") == 1, (
                            f"Expected 1 payee SD ref, got {_count_sd_refs(c, 'allowed')}"
                        )
                        return
        pytest.fail("payment mandate with allowed_payee constraint not found")

    def test_l2_payee_constraint_all(self):
        """Payee constraint with all merchants → L2 refs all."""
        l2 = _build_l2_with_constraints(
            payment_constraints=[
                AllowedPayeeConstraint(allowed=MERCHANTS),
            ],
        )
        l2_claims = resolve_disclosures(l2)
        for delegate in l2_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.payment.allowed_payees":
                        assert _count_sd_refs(c, "allowed") == 2
                        return
        pytest.fail("payment mandate with allowed_payee constraint not found")


class TestUnknownMerchantRejection:
    def test_unknown_merchant_raises(self):
        """Constraint referencing merchant not in mandate.merchants raises ValueError."""
        unknown_merchant = {"id": "unknown-uuid", "name": "Unknown Store", "website": "https://unknown.com"}
        with pytest.raises(ValueError, match="unknown merchant"):
            _build_l2_with_constraints(
                checkout_constraints=[
                    AllowedMerchantConstraint(allowed=[unknown_merchant]),
                ],
            )

    def test_unknown_item_raises(self):
        """Constraint referencing item not in mandate.acceptable_items raises ValueError."""
        unknown_item = {"id": "UNKNOWN-SKU", "title": "Unknown Product"}
        with pytest.raises(ValueError, match="unknown item"):
            _build_l2_with_constraints(
                checkout_constraints=[
                    CheckoutLineItemsConstraint(
                        items=[{"id": "line-item-1", "acceptable_items": [unknown_item], "quantity": 1}],
                    ),
                ],
            )

    def test_unknown_payee_raises(self):
        """Payee constraint referencing unknown merchant raises ValueError."""
        unknown_merchant = {"id": "unknown-uuid", "name": "Unknown Store", "website": "https://unknown.com"}
        with pytest.raises(ValueError, match="unknown merchant"):
            _build_l2_with_constraints(
                payment_constraints=[
                    AllowedPayeeConstraint(allowed=[unknown_merchant]),
                ],
            )
