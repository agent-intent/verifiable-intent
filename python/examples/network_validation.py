"""Network validation pipeline: chain verification + constraint enforcement.

Shows the complete payment-side validation that the Network performs,
step by step, using SDK functions directly.

Also explains COLLAPSED vs FOUR_PARTY deployment modes.

Run: python examples/network_validation.py

**Production Note:** This example demonstrates cryptographic verification only.
Production implementations MUST additionally implement stateful checks including:
mandate pair reuse tracking, cumulative spend enforcement, nonce replay
detection, and rate limiting. See security-model.md §4.1 for the full
threat model and required mitigations.
"""

from __future__ import annotations

import time
import uuid

# Import helpers first — bootstraps sys.path for SDK imports.
from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    banner,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    error,
    get_agent_keys,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
    print_sd_jwt,
    result_box,
    role_log,
    step,
    success,
    visible,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes, hash_disclosure
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
from verifiable_intent.issuance.agent import create_layer3_payment
from verifiable_intent.issuance.issuer import create_layer1
from verifiable_intent.issuance.user import create_layer2_autonomous
from verifiable_intent.models.agent_mandate import (
    FinalPaymentMandate,
    PaymentL3Mandate,
)
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import (
    CheckoutMandate,
    MandateMode,
    PaymentMandate,
    UserMandate,
)
from verifiable_intent.verification.chain import verify_chain
from verifiable_intent.verification.constraint_checker import StrictnessMode, check_constraints


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def main():
    banner("Network Validation Pipeline")
    now = int(time.time())

    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    # ------------------------------------------------------------------
    # Build credentials (condensed — see autonomous_flow.py for details)
    # ------------------------------------------------------------------
    step(1, "Build 3-layer chain for validation")

    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user-net-001",
            iat=now,
            exp=now + 86400,
            aud="https://wallet.example.com",
            cnf_jwk=user.public_jwk,
            email="alice@example.com",
            pan_last_four="1234",
            scheme="Mastercard",
        ),
        issuer.private_key,
    )
    l1_ser = l1.serialize()

    l2 = create_layer2_autonomous(
        UserMandate(
            nonce=str(uuid.uuid4()),
            aud="https://agent.example",
            iat=now,
            iss="https://wallet.example.com",
            exp=now + 86400,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_ser.encode("ascii")),
            checkout_mandate=CheckoutMandate(
                vct="mandate.checkout.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                constraints=[
                    AllowedMerchantConstraint(allowed=MERCHANTS),
                    CheckoutLineItemsConstraint(
                        items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
                    ),
                ],
            ),
            payment_mandate=PaymentMandate(
                vct="mandate.payment.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                payment_instrument=PAYMENT_INSTRUMENT,
                constraints=[
                    PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                    AllowedPayeeConstraint(allowed=MERCHANTS),
                ],
            ),
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        ),
        user.private_key,
    )
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    # Find L2 disclosures
    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")

    # Create checkout JWT and hash
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    # L3a: Payment mandate for network
    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce=str(uuid.uuid4()),
        aud="https://www.mastercard.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # Compute selective L2 presentation for sd_hash verification
    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

    role_log("agent", "Chain built: L1 + L2 + L3a ready for validation")
    print_sd_jwt("issuer", "L1 SD-JWT", l1_ser)
    print_sd_jwt("user", "L2 SD-JWT", l2_ser)
    print_sd_jwt("agent", "L3a SD-JWT (payment)", l3a.serialize())

    # ------------------------------------------------------------------
    # Step 2: Chain signature verification
    # ------------------------------------------------------------------
    step(2, "Chain signature verification")
    print("  In production, this is the core of validate_intent().\n")

    role_log("network", "COLLAPSED mode: validate locally with issuer's public key")
    print("  (FOUR_PARTY mode would POST the chain to the Issuer instead)\n")

    l1_parsed = decode_sd_jwt(l1_ser)
    l2_parsed = decode_sd_jwt(l2_ser)

    chain_result = verify_chain(
        l1_parsed,
        l2_parsed,
        l3_payment=l3a,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_ser,
        l2_serialized=l2_ser,
        l2_payment_serialized=l2_payment_ser,
    )

    visible("L1 issuer signature", "verified against trusted JWKS")
    visible("L1 vct", f"{l1_parsed.payload.get('vct')} (must be 'https://credentials.mastercard.com/card')")
    visible("L1 -> L2 binding", "L2 KB-JWT signed by key in L1 cnf.jwk")
    visible("L2 sd_hash", "matches SHA-256 of L1 serialization")
    visible("L2 -> L3a binding", "L3a header jwk matches L2 mandate cnf.jwk")
    visible("L3a sd_hash", "matches SHA-256 of L2 selective presentation")
    visible("_sd_alg", "sha-256 at each layer")
    role_log("network", f"Chain verification result: valid={chain_result.valid}")

    if not chain_result.valid:
        for e in chain_result.errors:
            role_log("network", f"  Error: {e}")
        return False

    # ------------------------------------------------------------------
    # Step 3: Detect autonomous vs immediate mode
    # ------------------------------------------------------------------
    step(3, "Mode detection")

    l2_claims = chain_result.l2_claims
    autonomous_mode = False
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("cnf"):
            autonomous_mode = True
            break

    role_log("network", f"Detected mode: {'AUTONOMOUS' if autonomous_mode else 'IMMEDIATE'}")
    if autonomous_mode:
        role_log("network", "  L2 mandates contain cnf.jwk -> agent delegation present")
        role_log("network", "  Layer 3 is REQUIRED")
    else:
        role_log("network", "  L2 mandates have NO cnf -> user signed final values directly")
        role_log("network", "  Layer 3 is NOT expected")

    # ------------------------------------------------------------------
    # Step 4: Extract constraints and fulfillment
    # ------------------------------------------------------------------
    step(4, "Extract L2 constraints and L3 fulfillment")

    l3_claims = chain_result.l3_payment_claims

    payment_constraints = []
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
            payment_constraints = delegate.get("constraints", [])
            break

    fulfillment = {}
    for delegate in l3_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.1":
            fulfillment = delegate
            break

    role_log("network", f"Payment constraints: {len(payment_constraints)} rules")
    for c in payment_constraints:
        role_log("network", f"  - {c.get('type')}")
    role_log("network", f"Fulfillment present: payment={bool(fulfillment)}")

    # ------------------------------------------------------------------
    # Step 5: Merchant disclosure resolution (for payee constraint)
    # ------------------------------------------------------------------
    step(5, "Merchant disclosure resolution")

    disc_by_hash = {}
    for disc_str, disc_val in zip(l2_parsed.disclosures, l2_parsed.disclosure_values):
        disc_by_hash[hash_disclosure(disc_str)] = disc_val

    for c in payment_constraints:
        if c.get("type") == "mandate.payment.allowed_payees":
            allowed_refs = c.get("allowed", [])
            resolved_merchants = []
            for ref in allowed_refs:
                ref_hash = ref.get("...", "") if isinstance(ref, dict) else ""
                if ref_hash and ref_hash in disc_by_hash:
                    merchant_data = disc_by_hash[ref_hash][-1]
                    resolved_merchants.append(merchant_data)
                    visible("Resolved merchant", f"{merchant_data.get('name')}")
            fulfillment["allowed_merchants"] = resolved_merchants
            break

    # ------------------------------------------------------------------
    # Step 6: Constraint enforcement
    # ------------------------------------------------------------------
    step(6, "Constraint enforcement")

    # Payment networks SHOULD enforce STRICT mode — unknown constraints are violations, not skips
    constraint_result = check_constraints(payment_constraints, fulfillment, mode=StrictnessMode.STRICT)

    for c in payment_constraints:
        ctype = c.get("type", "")
        role_log("network", f"  {ctype}")
    role_log("network", f"Result: satisfied={constraint_result.satisfied}")
    if constraint_result.violations:
        for v in constraint_result.violations:
            role_log("network", f"  Violation: {v}")
    if constraint_result.skipped:
        role_log("network", f"  Skipped: {constraint_result.skipped}")

    # ------------------------------------------------------------------
    # Step 7: Deployment mode comparison
    # ------------------------------------------------------------------
    step(7, "Deployment modes: COLLAPSED vs FOUR_PARTY")

    print("""
  COLLAPSED mode (default):
    Network fetches Issuer's JWKS and validates chain locally.
    +----------+    JWKS     +----------+
    | Network  | <---------- |  Issuer  |
    | (local   |             +----------+
    |  verify) |
    +----------+

  FOUR_PARTY mode:
    Network forwards entire chain to Issuer for validation.
    +----------+  POST chain +----------+
    | Network  | ----------> |  Issuer  |
    | (relay)  | <---------- | (verify) |
    +----------+   result    +----------+

  Both modes use the same verify_chain() function.
  The difference is WHERE it runs:
    COLLAPSED: in the Network's process
    FOUR_PARTY: in the Issuer's process
""")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    step(8, "Summary")

    assert chain_result.valid, f"Chain verification failed: {chain_result.errors}"
    assert constraint_result.satisfied, f"Constraints violated: {constraint_result.violations}"

    if chain_result.valid and constraint_result.satisfied:
        success("Payment intent validated successfully")
        order_id = f"VI-{uuid.uuid4().hex[:12].upper()}"
        result_box(
            "Assurance Data",
            {
                "order_id": order_id,
                "chain_valid": True,
                "constraints_checked": True,
                "mode": "COLLAPSED",
            },
        )
    else:
        error("Validation failed")

    return True


if __name__ == "__main__":
    main()
