"""Lock the top-level public API surface against accidental regressions (v2)."""

import verifiable_intent

EXPECTED_EXPORTS = [
    # Issuance
    "create_layer1",
    "create_layer2_immediate",
    "create_layer2_autonomous",
    "create_layer3_payment",
    "create_layer3_checkout",
    "ImmediateL2Result",
    # Verification
    "verify_chain",
    "ChainVerificationResult",
    "check_constraints",
    "ConstraintCheckResult",
    "StrictnessMode",
    "verify_checkout_hash_binding",
    "verify_l2_reference_binding",
    "verify_l3_cross_reference",
    "SplitL3",
    "MandatePairResult",
    # Models
    "IssuerCredential",
    "UserMandate",
    "MandateMode",
    "CheckoutMandate",
    "PaymentMandate",
    "PaymentL3Mandate",
    "CheckoutL3Mandate",
    "FinalCheckoutMandate",
    "FinalPaymentMandate",
    "Constraint",
    "AllowedMerchantConstraint",
    "CheckoutLineItemsConstraint",
    "AllowedPayeeConstraint",
    "PaymentAmountConstraint",
    "PaymentBudgetConstraint",
    "PaymentRecurrenceConstraint",
    "AgentRecurrenceConstraint",
    "ReferenceConstraint",
    "parse_constraint",
    # Crypto
    "SdJwt",
    "KbSdJwt",
    "resolve_disclosures",
]


def test_all_expected_names_importable():
    """Every name in EXPECTED_EXPORTS must be importable from the package root."""
    missing = [name for name in EXPECTED_EXPORTS if not hasattr(verifiable_intent, name)]
    assert not missing, f"Missing from verifiable_intent: {missing}"


def test_all_matches_expected():
    """__all__ must contain exactly the expected exports (no accidental additions)."""
    actual = set(verifiable_intent.__all__) - {"__version__"}
    expected = set(EXPECTED_EXPORTS)
    extra = actual - expected
    missing = expected - actual
    assert not extra, f"Unexpected exports in __all__: {extra}"
    assert not missing, f"Missing from __all__: {missing}"


def test_version_is_string():
    assert isinstance(verifiable_intent.__version__, str)
    assert verifiable_intent.__version__ == "0.1.0"
