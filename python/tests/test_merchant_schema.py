"""Tests for merchant/payee schema: id OPTIONAL, name+website REQUIRED, matching fallback."""

from __future__ import annotations

import pytest

from verifiable_intent.issuance.user import _match_merchant_refs
from verifiable_intent.verification.constraint_checker import (
    _merchant_matches,
    check_constraints,
)

# ---------------------------------------------------------------------------
# _merchant_matches helper
# ---------------------------------------------------------------------------


def test_merchant_match_by_id():
    """Match when both merchants have id — primary key match."""
    assert _merchant_matches(
        {"id": "m-1", "name": "A", "website": "https://a.com"},
        {"id": "m-1", "name": "B", "website": "https://b.com"},
    )
    assert not _merchant_matches(
        {"id": "m-1", "name": "A", "website": "https://a.com"},
        {"id": "m-2", "name": "A", "website": "https://a.com"},
    )


def test_merchant_match_by_name_fallback():
    """Fall back to name match when one side lacks id."""
    # target has no id — fall back to name
    assert _merchant_matches(
        {"id": "m-1", "name": "Tennis Warehouse", "website": "https://tw.com"},
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
    )
    # candidate has no id — fall back to name
    assert _merchant_matches(
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
        {"id": "m-1", "name": "Tennis Warehouse", "website": "https://tw.com"},
    )
    # different names — no match
    assert not _merchant_matches(
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
        {"name": "Babolat", "website": "https://babolat.com"},
    )


# ---------------------------------------------------------------------------
# constraint checker: allowed_payee with name fallback
# ---------------------------------------------------------------------------


def test_merchant_missing_name_fails():
    """Payee with no name and no id fails to match."""
    result = check_constraints(
        [
            {
                "type": "mandate.payment.allowed_payees",
                "allowed": [{"website": "https://tw.com"}],
            }
        ],
        {"payee": {"website": "https://tw.com"}},
    )
    assert not result.satisfied
    assert any("no payees resolved" in v.lower() for v in result.violations)


# ---------------------------------------------------------------------------
# constraint checker: allowed_merchant with name fallback
# ---------------------------------------------------------------------------


def test_allowed_merchant_name_fallback():
    """Merchant without id matches allowed merchant by name."""
    result = check_constraints(
        [
            {
                "type": "mandate.checkout.allowed_merchants",
                "allowed": [{"name": "Tennis Warehouse", "website": "https://tw.com"}],
            }
        ],
        {"merchant": {"name": "Tennis Warehouse", "website": "https://tw.com"}},
    )
    assert result.satisfied, f"Name-only merchant should match: {result.violations}"


# ---------------------------------------------------------------------------
# user.py: _match_merchant_refs
# ---------------------------------------------------------------------------


def test_user_match_merchant_refs_by_name():
    """_match_merchant_refs works with name-only merchants (no id)."""
    mandate_merchants = [
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
        {"name": "Babolat", "website": "https://babolat.com"},
    ]
    disc_hashes = ["hash-0", "hash-1"]
    original = [{"name": "Babolat", "website": "https://babolat.com"}]

    matched = _match_merchant_refs(original, mandate_merchants, disc_hashes)
    assert len(matched) == 1
    # The matched ref should be a delegate ref for hash-1 (index 1)
    assert matched[0].get("...") == "hash-1"


def test_user_match_merchant_refs_no_id_no_name_fails():
    """_match_merchant_refs raises ValueError when merchant has neither id nor name."""
    mandate_merchants = [{"name": "Tennis Warehouse", "website": "https://tw.com"}]
    disc_hashes = ["hash-0"]
    original = [{"website": "https://tw.com"}]

    with pytest.raises(ValueError, match="missing both 'id' and 'name'"):
        _match_merchant_refs(original, mandate_merchants, disc_hashes)


# ---------------------------------------------------------------------------
# _merchant_matches: website required in name fallback (1C)
# ---------------------------------------------------------------------------


def test_merchant_same_name_different_website_no_match():
    """Merchants with same name but different website should NOT match in name fallback."""
    assert not _merchant_matches(
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
        {"name": "Tennis Warehouse", "website": "https://fake-tw.com"},
    )


def test_merchant_same_name_missing_website_no_match():
    """Merchants with same name but missing website should NOT match in name fallback."""
    assert not _merchant_matches(
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
        {"name": "Tennis Warehouse"},
    )
    assert not _merchant_matches(
        {"name": "Tennis Warehouse"},
        {"name": "Tennis Warehouse", "website": "https://tw.com"},
    )


# ---------------------------------------------------------------------------
# Unresolved SD refs: skip behavior (1D)
# ---------------------------------------------------------------------------


def test_allowed_merchant_all_sd_refs_skips():
    """Constraint with all-SD-ref merchants should skip, not fail."""
    result = check_constraints(
        [
            {
                "type": "mandate.checkout.allowed_merchants",
                "allowed": [{"...": "abc123"}, {"...": "def456"}],
            }
        ],
        {"merchant": {"id": "m-1", "name": "Tennis Warehouse", "website": "https://tw.com"}},
    )
    # Should be satisfied (skipped, not violated)
    assert result.satisfied, f"All-SD-ref merchants should skip: {result.violations}"
    assert any("skipped" in c.lower() for c in result.checked)


def test_allowed_payee_all_sd_refs_skips():
    """Constraint with all-SD-ref payees should skip, not fail."""
    result = check_constraints(
        [
            {
                "type": "mandate.payment.allowed_payees",
                "allowed": [{"...": "abc123"}],
            }
        ],
        {"payee": {"id": "m-1", "name": "Tennis Warehouse", "website": "https://tw.com"}},
    )
    assert result.satisfied, f"All-SD-ref payees should skip: {result.violations}"
    assert any("skipped" in c.lower() for c in result.checked)
