"""Tests for constraints=None crash guard (Finding F3).

Verifies that when a mandate dict has "constraints": null (Python None),
iterating over constraints does not raise a TypeError.
"""

from verifiable_intent.verification.chain import _MandateInfo, _pair_autonomous, _verify_mandate_pair
from verifiable_intent.verification.integrity import verify_l2_reference_binding


class TestConstraintsNoneGuard:
    """Tests that constraints=None is handled gracefully (not crashed on)."""

    def test_checkout_mandate_constraints_none_no_crash(self):
        """Open checkout mandate with constraints=None must not raise TypeError."""
        checkout = {
            "vct": "mandate.checkout.open.1",
            "constraints": None,
        }
        payment = {
            "vct": "mandate.payment.open.1",
            "constraints": [
                {"type": "mandate.payment.reference", "conditional_transaction_id": "abc123"},
            ],
        }
        # Must not raise TypeError — should return a clean validation error instead
        errors, checks, skipped = _verify_mandate_pair(checkout, payment, "disc123", is_autonomous=True)
        assert isinstance(errors, list)
        assert isinstance(checks, list)
        assert isinstance(skipped, list)
        # The open checkout mandate is missing line_items — expect a validation error
        assert len(errors) > 0
        assert any("line_items" in e for e in errors)

    def test_payment_mandate_constraints_none_no_crash(self):
        """Open payment mandate with constraints=None must not raise TypeError."""
        checkout = {
            "vct": "mandate.checkout.open.1",
            "constraints": [
                {
                    "type": "mandate.checkout.line_items",
                    "items": [
                        {
                            "id": "BAB86345",
                            "acceptable_items": [{"id": "BAB86345", "title": "Babolat Pure Aero"}],
                            "quantity": 1,
                        }
                    ],
                }
            ],
        }
        payment = {
            "vct": "mandate.payment.open.1",
            "constraints": None,
        }
        # Must not raise TypeError — should return a clean validation error instead
        errors, checks, skipped = _verify_mandate_pair(checkout, payment, "disc123", is_autonomous=True)
        assert isinstance(errors, list)
        assert isinstance(checks, list)
        assert isinstance(skipped, list)
        # The open payment mandate is missing payment.reference — expect a validation error
        assert len(errors) > 0
        assert any("reference" in e for e in errors)

    def test_pair_autonomous_payment_constraints_none_no_crash(self):
        """_pair_autonomous with constraints=None on payment mandate must not raise TypeError."""
        checkout_info = _MandateInfo(
            resolved={"vct": "mandate.checkout.open.1", "constraints": []},
            ref_hash="ref_hash_abc",
            disc_b64="disc123",
        )
        payment_info = _MandateInfo(
            resolved={
                "vct": "mandate.payment.open.1",
                "constraints": None,  # <-- the null case
            },
            ref_hash=None,
            disc_b64="disc456",
        )
        # Must not raise TypeError — should return a clean error about missing reference constraint
        pairs, errors = _pair_autonomous([checkout_info], [payment_info])
        assert isinstance(pairs, list)
        assert isinstance(errors, list)
        assert len(errors) > 0
        assert any("reference" in e for e in errors)

    def test_integrity_verify_l2_reference_binding_constraints_none_no_crash(self):
        """verify_l2_reference_binding with constraints=None must not raise TypeError."""
        checkout_mandate = {
            "vct": "mandate.checkout.open.1",
            "constraints": [],
        }
        payment_mandate = {
            "vct": "mandate.payment.open.1",
            "constraints": None,  # <-- the null case
        }
        # No reference constraint present — function should return (True, "") gracefully
        valid, msg = verify_l2_reference_binding(checkout_mandate, payment_mandate, "dummy_checkout_disc_b64")
        assert valid is True
        assert msg == ""
