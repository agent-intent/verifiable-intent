"""Complete autonomous (3-layer) VI purchase flow.

Demonstrates the full delegation chain:
  L1: Issuer credential (binds user's public key via cnf.jwk)
  L2: User mandate with constraints + agent delegation (cnf.jwk)
  L3a: Agent payment fulfillment for network
  L3b: Agent checkout fulfillment for merchant

Run: python examples/autonomous_flow.py
"""

from __future__ import annotations

import time
import uuid

# Import helpers first — it bootstraps sys.path so the SDK is importable
# even without an editable install.
from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    banner,
    build_role_presentations,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    error,
    find_product,
    get_agent_keys,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
    print_sd_jwt,
    result_box,
    role_log,
    step,
    success,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures
from verifiable_intent.issuance.agent import create_layer3_checkout, create_layer3_payment
from verifiable_intent.issuance.issuer import create_layer1
from verifiable_intent.issuance.user import create_layer2_autonomous
from verifiable_intent.models.agent_mandate import (
    CheckoutL3Mandate,
    FinalCheckoutMandate,
    FinalPaymentMandate,
    PaymentL3Mandate,
)
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
    PaymentRecurrenceConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import (
    CheckoutMandate,
    MandateMode,
    PaymentMandate,
    UserMandate,
)
from verifiable_intent.verification.chain import verify_chain
from verifiable_intent.verification.constraint_checker import check_constraints


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def main():
    banner("Autonomous (3-Layer) Purchase Flow")
    now = int(time.time())

    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    # ------------------------------------------------------------------
    # Step 1: Issuer creates L1 credential binding user's public key
    # ------------------------------------------------------------------
    step(1, "Issuer creates Layer 1 credential")

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="user-alice-001",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        cnf_jwk=user.public_jwk,
        email="alice@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
    )
    l1 = create_layer1(cred, issuer.private_key)

    role_log("issuer", f"Created L1: {len(l1.disclosures)} selective disclosure (email)")
    role_log("issuer", f"  typ={l1.header['typ']}, vct={l1.payload['vct']}")
    role_log("issuer", f"  cnf.jwk binds user key (kid={user.kid})")
    print_sd_jwt("issuer", "L1 SD-JWT", l1.serialize())

    # ------------------------------------------------------------------
    # Step 2: User creates L2 mandate with constraints + agent delegation
    # ------------------------------------------------------------------
    step(2, "User creates Layer 2 mandate (autonomous)")

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud="https://agent.verifiable-intent.example",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy a Babolat tennis racket under $400",
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS, "quantity": 1}],
                ),
            ],
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            risk_data={"device_id": "android1234", "ip_address": "192.168.1.100"},
            constraints=[
                PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                AllowedPayeeConstraint(allowed=MERCHANTS),
                PaymentRecurrenceConstraint(frequency="YEAR", start_date="2026-01-01", end_date="2028-01-01", number=3),
            ],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user.private_key)

    role_log("user", f"Created L2: {len(l2.disclosures)} disclosures (mandates + merchants + items)")
    role_log("user", f"  mode=AUTONOMOUS, cnf.jwk delegates to agent (kid={agent.kid})")
    role_log("user", "  sd_hash binds L2 to L1 serialization")
    print_sd_jwt("user", "L2 SD-JWT", l2.serialize())

    # ------------------------------------------------------------------
    # Step 3: Agent receives L1+L2, extracts constraints, selects product
    # ------------------------------------------------------------------
    step(3, "Agent extracts constraints and selects product")

    l2_claims = resolve_disclosures(l2)

    # Resolve acceptable items from L2 standalone disclosures.
    # The checkout constraint's acceptable_items contain SD refs ({"...": hash}).
    # The agent resolves them by matching hashes against L2 disclosure hashes.
    from verifiable_intent.crypto.disclosure import hash_disclosure

    disc_by_hash = {}
    for disc_str, disc_val in zip(l2.disclosures, l2.disclosure_values):
        disc_by_hash[hash_disclosure(disc_str)] = disc_val[-1] if disc_val else None

    checkout_constraints = {}
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict):
            if delegate.get("vct") == "mandate.checkout.open.1":
                for c in delegate.get("constraints", []):
                    if c.get("type") == "mandate.checkout.line_items":
                        checkout_constraints = c

    # Resolve acceptable item IDs from SD refs in the constraint
    acceptable_ids = []
    for item_entry in checkout_constraints.get("items", []):
        for ai in item_entry.get("acceptable_items", []):
            if isinstance(ai, dict):
                ref_hash = ai.get("...", "")
                if ref_hash and ref_hash in disc_by_hash:
                    resolved = disc_by_hash[ref_hash]
                    if isinstance(resolved, dict) and "id" in resolved:
                        acceptable_ids.append(resolved["id"])
                elif "id" in ai:
                    acceptable_ids.append(ai["id"])
    role_log("agent", f"Acceptable item IDs: {acceptable_ids}")

    # Agent selects a racket from acceptable items
    racket = None
    for aid in acceptable_ids:
        product = find_product(aid)
        if product and product["category"] == "racket":
            racket = product
            break
    if not racket:
        error("No matching racket found")
        return False
    role_log("agent", f"Selected: {racket['name']} ({racket['price']} cents)")

    # ------------------------------------------------------------------
    # Step 4: Agent creates checkout JWT at merchant
    # ------------------------------------------------------------------
    step(4, "Agent creates checkout at merchant")

    checkout_jwt = create_checkout_jwt(
        [{"sku": racket["sku"], "quantity": 1}],
        merchant,
    )
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    role_log("merchant", f"Checkout JWT created for {racket['name']}")
    role_log("merchant", f"  checkout_hash: {c_hash[:32]}...")

    # ------------------------------------------------------------------
    # Step 5: Agent builds L3a (payment) and L3b (checkout)
    # ------------------------------------------------------------------
    step(5, "Agent creates Layer 3 fulfillment (split L3a/L3b)")

    nonce = str(uuid.uuid4())
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    # Find L2 disclosures for sd_hash computation
    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    # L3a: Payment mandate for network
    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": racket["price"]},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce=nonce,
        aud="https://www.mastercard.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # L3b: Checkout mandate for merchant
    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce=nonce,
        aud="https://tennis-warehouse.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    role_log("agent", "Created L3a (payment) for network")
    role_log("agent", "Created L3b (checkout) for merchant")
    print_sd_jwt("agent", "L3a SD-JWT (payment)", l3a.serialize())
    print_sd_jwt("agent", "L3b SD-JWT (checkout)", l3b.serialize())

    # ------------------------------------------------------------------
    # Step 6: Build selective L2 presentations for each recipient
    # ------------------------------------------------------------------
    step(6, "Selective disclosure routing")

    # Role-specific L2 presentations:
    # - Merchant: L2 with checkout mandate + item disclosures
    # - Network: L2 with payment mandate + merchant disclosures
    l2_checkout_only, l2_payment_only = build_role_presentations(l2, l2_ser)
    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

    role_log("agent", "Merchant sees: L1 + L2(checkout) + L3b(checkout)")
    role_log("agent", "Network sees:  L1 + L2(payment) + L3a(payment)")

    # Show what each party sees
    merchant_l2 = resolve_disclosures(decode_sd_jwt(l2_checkout_only))
    network_l2 = resolve_disclosures(decode_sd_jwt(l2_payment_only))

    merchant_delegates = [d.get("vct") for d in merchant_l2.get("delegate_payload", []) if isinstance(d, dict)]
    network_delegates = [d.get("vct") for d in network_l2.get("delegate_payload", []) if isinstance(d, dict)]

    role_log("merchant", f"Sees delegate types: {merchant_delegates}")
    role_log("network", f"Sees delegate types: {network_delegates}")

    # ------------------------------------------------------------------
    # Step 7: Merchant verifies checkout-side chain (L3b)
    # ------------------------------------------------------------------
    step(7, "Merchant verifies checkout-side chain")

    l1_parsed = decode_sd_jwt(l1.serialize())
    l2_checkout_parsed = decode_sd_jwt(l2_checkout_only)

    merchant_result = verify_chain(
        l1_parsed,
        l2_checkout_parsed,
        l3_checkout=l3b,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_checkout_serialized=l2_checkout_ser,
    )
    role_log("merchant", f"Checkout-side chain valid: {merchant_result.valid}")
    role_log("merchant", f"  L2 checkout disclosed: {merchant_result.l2_checkout_disclosed}")
    role_log("merchant", f"  L2 payment disclosed: {merchant_result.l2_payment_disclosed}")
    if merchant_result.checks_skipped:
        role_log("merchant", f"  Checks skipped: {merchant_result.checks_skipped}")
    if not merchant_result.valid:
        for e in merchant_result.errors:
            role_log("merchant", f"  Error: {e}")

    # ------------------------------------------------------------------
    # Step 8: Network verifies payment-side chain + constraints
    # ------------------------------------------------------------------
    step(8, "Network validates payment chain + constraints")

    l2_full_parsed = decode_sd_jwt(l2_ser)

    network_result = verify_chain(
        l1_parsed,
        l2_full_parsed,
        l3_payment=l3a,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_payment_serialized=l2_payment_ser,
    )
    role_log("network", f"Chain valid: {network_result.valid}")

    constraint_result = None
    if network_result.valid:
        # Extract L2 payment constraints and L3 fulfillment
        l2_pay_claims = resolve_disclosures(l2_full_parsed)
        l3_pay_claims = network_result.l3_payment_claims

        payment_constraints = []
        for delegate in l2_pay_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                payment_constraints = delegate.get("constraints", [])
                break

        fulfillment = {}
        for delegate in l3_pay_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.1":
                fulfillment = delegate
                break

        # Resolve merchant disclosures for payee constraint
        from verifiable_intent.crypto.disclosure import hash_disclosure

        disc_by_hash = {}
        for disc_str, disc_val in zip(l2_full_parsed.disclosures, l2_full_parsed.disclosure_values):
            disc_by_hash[hash_disclosure(disc_str)] = disc_val

        for c in payment_constraints:
            if c.get("type") == "mandate.payment.allowed_payees":
                resolved_merchants = []
                for ref in c.get("allowed", []):
                    ref_hash = ref.get("...", "") if isinstance(ref, dict) else ""
                    if ref_hash and ref_hash in disc_by_hash:
                        resolved_merchants.append(disc_by_hash[ref_hash][-1])
                fulfillment["allowed_merchants"] = resolved_merchants
                break

        constraint_result = check_constraints(payment_constraints, fulfillment)
        role_log("network", f"Constraints satisfied: {constraint_result.satisfied}")
        if constraint_result.violations:
            for v in constraint_result.violations:
                role_log("network", f"  Violation: {v}")
        if constraint_result.skipped:
            role_log("network", f"  Skipped: {constraint_result.skipped}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    step(9, "Summary")

    assert merchant_result.valid, f"Merchant chain failed: {merchant_result.errors}"
    assert network_result.valid, f"Network chain failed: {network_result.errors}"
    assert constraint_result is not None and constraint_result.satisfied, (
        f"Constraints violated: {constraint_result.violations if constraint_result else 'no result'}"
    )

    if merchant_result.valid and network_result.valid:
        success("Autonomous purchase completed successfully")
        result_box(
            "Assurance Data",
            {
                "chain_valid": True,
                "constraints_checked": constraint_result.satisfied,
                "mode": "AUTONOMOUS",
                "product": racket["name"],
                "total_cents": racket["price"],
            },
        )
    else:
        error("Purchase failed")
        all_errors = merchant_result.errors + network_result.errors
        for e in all_errors:
            print(f"  - {e}")

    return True


if __name__ == "__main__":
    main()
