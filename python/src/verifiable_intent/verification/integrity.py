"""Checkout-payment integrity verification.

SHA-256-based mechanisms for cross-referencing mandate pairs:
  - verify_checkout_hash_binding: checkout_hash = SHA-256(checkout_jwt)
  - verify_l2_reference_binding: conditional_transaction_id = hash of checkout disclosure
  - verify_l3_cross_reference: L3a transaction_id == L3b checkout_hash
"""

from __future__ import annotations

import hashlib

from ..crypto.disclosure import _b64url_encode, hash_disclosure


def verify_checkout_hash_binding(
    checkout_mandate_dict: dict,
    payment_mandate_dict: dict,
) -> tuple[bool, str]:
    """Verify checkout_hash = SHA-256(checkout_jwt) and transaction_id = checkout_hash.

    AP2 field placement: checkout mandate has checkout_jwt + checkout_hash,
    payment mandate has transaction_id. All three must be consistent.

    Returns (valid, error_message).
    """
    checkout_jwt = checkout_mandate_dict.get("checkout_jwt")
    if checkout_jwt is not None and not isinstance(checkout_jwt, str):
        return False, f"checkout_jwt must be a string, got {type(checkout_jwt).__name__}"
    if not checkout_jwt:
        return True, ""  # No checkout_jwt to bind

    # Verify checkout mandate's checkout_hash matches SHA-256(checkout_jwt)
    checkout_hash = checkout_mandate_dict.get("checkout_hash")
    if not checkout_hash:
        return False, "checkout_jwt present but checkout_hash missing from checkout mandate"

    computed = _b64url_encode(hashlib.sha256(checkout_jwt.encode("ascii")).digest())
    if computed != checkout_hash:
        return False, f"checkout_hash mismatch: computed {computed} != expected {checkout_hash}"

    # Verify payment mandate's transaction_id matches checkout_hash
    transaction_id = payment_mandate_dict.get("transaction_id")
    if not transaction_id:
        return False, "checkout_jwt present but transaction_id missing from payment mandate"

    if transaction_id != checkout_hash:
        return False, f"transaction_id mismatch: {transaction_id} != checkout_hash {checkout_hash}"

    return True, ""


def verify_l2_reference_binding(
    checkout_mandate_dict: dict,
    payment_mandate_dict: dict,
    checkout_disclosure_b64: str,
) -> tuple[bool, str]:
    """Verify the L2 mandate.payment.reference constraint binds to the L2 checkout mandate.

    In Autonomous mode, the L2 payment mandate carries a mandate.payment.reference
    constraint with conditional_transaction_id = hash of the checkout disclosure.

    Returns (valid, error_message).
    """
    constraints = payment_mandate_dict.get("constraints") or []
    ref_constraint = None
    for c in constraints:
        if isinstance(c, dict) and c.get("type") == "mandate.payment.reference":
            ref_constraint = c
            break

    if ref_constraint is None:
        return True, ""  # No reference constraint to check

    expected_id = ref_constraint.get("conditional_transaction_id", "")
    if not expected_id:
        return False, "mandate.payment.reference missing required conditional_transaction_id"

    # Compute hash of the checkout disclosure string
    computed_hash = hash_disclosure(checkout_disclosure_b64)
    if computed_hash != expected_id:
        return False, (f"conditional_transaction_id mismatch: computed {computed_hash} != expected {expected_id}")

    return True, ""


def verify_l3_cross_reference(
    l3_payment_claims: dict,
    l3_checkout_claims: dict,
) -> tuple[bool, str]:
    """Verify L3a transaction_id matches L3b checkout_hash.

    Both L3a and L3b must agree on the cross-reference value that
    links the payment authorization to the checkout.

    Returns (valid, error_message).
    """
    # Extract from L3a payment mandate
    l3a_delegates = l3_payment_claims.get("delegate_payload", [])
    transaction_id = None
    for delegate in l3a_delegates:
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.1":
            transaction_id = delegate.get("transaction_id")
            break

    # Extract from L3b checkout mandate
    l3b_delegates = l3_checkout_claims.get("delegate_payload", [])
    checkout_hash = None
    for delegate in l3b_delegates:
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.1":
            checkout_hash = delegate.get("checkout_hash")
            break

    if transaction_id is None:
        return False, "L3a payment mandate missing transaction_id"
    if checkout_hash is None:
        return False, "L3b checkout mandate missing checkout_hash"

    if transaction_id != checkout_hash:
        return False, f"L3 cross-reference mismatch: transaction_id={transaction_id} != checkout_hash={checkout_hash}"

    return True, ""
