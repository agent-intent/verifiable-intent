"""Negative-case security tests for verification bypass fixes (Findings 4, 5, 6).

Each test targets a fail-open pattern that was fixed to fail-closed.
"""

from __future__ import annotations

from verifiable_intent.verification.constraint_checker import check_constraints
from verifiable_intent.verification.integrity import verify_checkout_hash_binding, verify_l3_cross_reference

# ---------------------------------------------------------------------------
# Finding 4: verify_checkout_hash_binding — checkout_jwt present but
# checkout_hash missing must fail (not silently pass)
# ---------------------------------------------------------------------------


class TestCheckoutHashBindingBypass:
    def test_checkout_hash_missing_from_checkout_fails(self):
        """checkout_jwt present + checkout_hash absent from checkout mandate → False."""
        checkout = {"vct": "mandate.checkout.1", "checkout_jwt": "eyJhbGciOi..."}
        payment = {"vct": "mandate.payment.1", "transaction_id": "some-hash"}
        valid, error = verify_checkout_hash_binding(checkout, payment)
        assert not valid, "Must fail when checkout_hash missing from checkout mandate"
        assert "checkout_hash" in error

    def test_transaction_id_missing_from_payment_fails(self):
        """checkout_jwt present + transaction_id absent from payment mandate → False."""
        import hashlib

        from verifiable_intent.crypto.disclosure import _b64url_encode

        jwt_str = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig"
        expected_hash = _b64url_encode(hashlib.sha256(jwt_str.encode("utf-8")).digest())
        checkout = {"vct": "mandate.checkout.1", "checkout_jwt": jwt_str, "checkout_hash": expected_hash}
        payment = {"vct": "mandate.payment.1"}  # no transaction_id
        valid, error = verify_checkout_hash_binding(checkout, payment)
        assert not valid, "Must fail when transaction_id missing from payment mandate"
        assert "transaction_id" in error

    def test_checkout_jwt_absent_skips_binding(self):
        """Neither checkout_jwt nor checkout_hash present → True (legitimate skip)."""
        checkout = {"vct": "mandate.checkout.1"}  # no checkout_jwt
        payment = {"vct": "mandate.payment.1"}  # no transaction_id
        valid, error = verify_checkout_hash_binding(checkout, payment)
        assert valid, "Should skip binding when no checkout_jwt to bind"
        assert error == ""

    def test_checkout_hash_mismatch_fails(self):
        """checkout_jwt present + wrong checkout_hash → False."""
        checkout = {"vct": "mandate.checkout.1", "checkout_jwt": "eyJhbGciOi...", "checkout_hash": "wrong-hash-value"}
        payment = {"vct": "mandate.payment.1", "transaction_id": "wrong-hash-value"}
        valid, error = verify_checkout_hash_binding(checkout, payment)
        assert not valid, "Must fail when checkout_hash doesn't match computed"
        assert "mismatch" in error.lower()

    def test_transaction_id_checkout_hash_mismatch_fails(self):
        """transaction_id != checkout_hash → False."""
        import hashlib

        from verifiable_intent.crypto.disclosure import _b64url_encode

        jwt_str = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig"
        expected_hash = _b64url_encode(hashlib.sha256(jwt_str.encode("utf-8")).digest())
        checkout = {"vct": "mandate.checkout.1", "checkout_jwt": jwt_str, "checkout_hash": expected_hash}
        payment = {"vct": "mandate.payment.1", "transaction_id": "different-hash"}
        valid, error = verify_checkout_hash_binding(checkout, payment)
        assert not valid, "Must fail when transaction_id != checkout_hash"
        assert "transaction_id" in error.lower() or "mismatch" in error.lower()


# ---------------------------------------------------------------------------
# Finding 5: verify_l3_cross_reference — missing transaction_id or
# checkout_hash must fail (not silently pass)
# ---------------------------------------------------------------------------


class TestL3CrossReferenceBypass:
    def test_l3_cross_ref_missing_transaction_id(self):
        """L3a mandate without transaction_id → False."""
        l3a_claims = {
            "delegate_payload": [
                {"vct": "mandate.payment.1"}  # no transaction_id
            ]
        }
        l3b_claims = {"delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": "abc123"}]}
        valid, error = verify_l3_cross_reference(l3a_claims, l3b_claims)
        assert not valid, "Must fail when L3a missing transaction_id"
        assert "transaction_id" in error

    def test_l3_cross_ref_missing_checkout_hash(self):
        """L3b mandate without checkout_hash → False."""
        l3a_claims = {"delegate_payload": [{"vct": "mandate.payment.1", "transaction_id": "abc123"}]}
        l3b_claims = {
            "delegate_payload": [
                {"vct": "mandate.checkout.1"}  # no checkout_hash
            ]
        }
        valid, error = verify_l3_cross_reference(l3a_claims, l3b_claims)
        assert not valid, "Must fail when L3b missing checkout_hash"
        assert "checkout_hash" in error

    def test_l3_cross_ref_both_present_match(self):
        """Happy path: both present and matching → True."""
        l3a_claims = {"delegate_payload": [{"vct": "mandate.payment.1", "transaction_id": "hash-abc"}]}
        l3b_claims = {"delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": "hash-abc"}]}
        valid, error = verify_l3_cross_reference(l3a_claims, l3b_claims)
        assert valid, f"Should pass when both match: {error}"

    def test_l3_cross_ref_mismatch(self):
        """Different values → False."""
        l3a_claims = {"delegate_payload": [{"vct": "mandate.payment.1", "transaction_id": "hash-abc"}]}
        l3b_claims = {"delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": "hash-xyz"}]}
        valid, error = verify_l3_cross_reference(l3a_claims, l3b_claims)
        assert not valid, "Must fail when values differ"
        assert "mismatch" in error.lower()


# ---------------------------------------------------------------------------
# Finding 6: _check_allowed_payee / _check_allowed_merchant — empty
# merchants list must fail (not silently pass)
# ---------------------------------------------------------------------------


class TestAllowedPayeeEmptyMerchants:
    def test_allowed_payee_empty_merchants_fails(self):
        """Empty allowed_payees list → violation (not silent pass)."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": []}],
            {
                "payee": {"id": "m1", "name": "Test Merchant", "website": "https://test.com"},
                "allowed_merchants": [],
            },
        )
        assert not result.satisfied, "Must fail when allowed list is empty"
        assert any("allowed_payees" in v.lower() for v in result.violations)

    def test_allowed_payee_resolved_merchants_works(self):
        """Constraint with inline merchant + valid payee → satisfied."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "Test Merchant"}]}],
            {
                "payee": {"id": "m1", "name": "Test Merchant", "website": "https://test.com"},
                "allowed_merchants": [
                    {"id": "m1", "name": "Test Merchant", "website": "https://test.com"},
                ],
            },
        )
        assert result.satisfied, f"Should pass with resolved merchants: {result.violations}"

    def test_allowed_payee_no_fulfillment_payee_fails(self):
        """Missing payee in fulfillment → violation."""
        result = check_constraints(
            [{"type": "mandate.payment.allowed_payees", "allowed": [{"id": "m1", "name": "Shop"}]}],
            {"allowed_merchants": [{"id": "m1"}]},
        )
        assert not result.satisfied
        assert any("payee" in v.lower() for v in result.violations)


class TestAllowedMerchantEmptyList:
    def test_allowed_merchant_empty_list_fails(self):
        """Empty allowed_merchants list → violation (not silent pass)."""
        result = check_constraints(
            [{"type": "mandate.checkout.allowed_merchants", "allowed": []}],
            {
                "merchant": {"id": "m1", "name": "Test Merchant", "website": "https://test.com"},
                "allowed_merchants": [],
            },
        )
        assert not result.satisfied, "Must fail when merchants list is empty"
        assert any("allowed_merchants" in v.lower() for v in result.violations)
