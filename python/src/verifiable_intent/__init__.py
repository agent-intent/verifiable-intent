"""Verifiable Intent - Open specification for cryptographic agent authorization in commerce."""

__version__ = "0.1.0"

# Crypto primitives
from .crypto import KbSdJwt, SdJwt, resolve_disclosures

# Issuance
from .issuance import (
    ImmediateL2Result,
    create_layer1,
    create_layer2_autonomous,
    create_layer2_immediate,
    create_layer3_checkout,
    create_layer3_payment,
)

# Models
from .models import (
    AgentRecurrenceConstraint,
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutL3Mandate,
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    Constraint,
    FinalCheckoutMandate,
    FinalPaymentMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentBudgetConstraint,
    PaymentL3Mandate,
    PaymentMandate,
    PaymentRecurrenceConstraint,
    ReferenceConstraint,
    UserMandate,
    parse_constraint,
)

# Verification
from .verification import (
    ChainVerificationResult,
    ConstraintCheckResult,
    MandatePairResult,
    SplitL3,
    StrictnessMode,
    check_constraints,
    verify_chain,
    verify_checkout_hash_binding,
    verify_l2_reference_binding,
    verify_l3_cross_reference,
)

__all__ = [
    "__version__",
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
