"""Tests for checkout_jwt type guard in verify_checkout_hash_binding."""

from __future__ import annotations

import hashlib

from verifiable_intent.crypto.disclosure import _b64url_encode
from verifiable_intent.verification.integrity import verify_checkout_hash_binding


class TestCheckoutJwtTypeGuard:
    """Type guard for checkout_jwt: must be a string when present."""

    def test_integer_checkout_jwt_returns_false(self):
        valid, msg = verify_checkout_hash_binding(
            {"checkout_jwt": 12345},
            {},
        )
        assert valid is False
        assert msg == "checkout_jwt must be a string, got int"

    def test_list_checkout_jwt_returns_false(self):
        valid, msg = verify_checkout_hash_binding(
            {"checkout_jwt": ["not", "a", "string"]},
            {},
        )
        assert valid is False
        assert msg == "checkout_jwt must be a string, got list"

    def test_none_checkout_jwt_passes_through(self):
        # None means no checkout_jwt — treated as absent, returns (True, "")
        valid, msg = verify_checkout_hash_binding(
            {"checkout_jwt": None},
            {},
        )
        assert valid is True
        assert msg == ""

    def test_valid_string_checkout_jwt_passes_type_guard(self):
        # A real JWT string should pass the type guard and proceed to hash checks.
        # Here we supply a matching checkout_hash and transaction_id so the full
        # binding check also passes — confirming no crash on the string path.
        jwt_str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
        expected_hash = _b64url_encode(hashlib.sha256(jwt_str.encode("utf-8")).digest())

        valid, msg = verify_checkout_hash_binding(
            {"checkout_jwt": jwt_str, "checkout_hash": expected_hash},
            {"transaction_id": expected_hash},
        )
        assert valid is True
        assert msg == ""
