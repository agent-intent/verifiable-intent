"""Selective disclosure deep-dive: same credential, different views per party.

Shows how a single L2 credential produces different presentations for
Merchant (checkout mandate only) vs Network (payment mandate + merchant entries).

Also demonstrates L1 and L3 selective disclosure.

Run: python examples/selective_disclosure.py
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
    build_role_presentations,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    get_agent_keys,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
    print_sd_jwt,
    redacted,
    role_log,
    step,
    success,
    visible,
)
from verifiable_intent.crypto.disclosure import hash_bytes
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


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def main():
    banner("Selective Disclosure Deep-Dive")
    now = int(time.time())

    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    # ------------------------------------------------------------------
    # Build a complete 3-layer chain
    # ------------------------------------------------------------------
    step(1, "Create full 3-layer chain")

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="user-sd-001",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        cnf_jwk=user.public_jwk,
        email="alice@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
    )
    l1 = create_layer1(cred, issuer.private_key)

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud="https://agent.example",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy tennis racket",
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
            constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user.private_key)
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    # Find L2 disclosures
    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    # Create checkout JWT and hash
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    # L3a: Payment for network
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

    # L3b: Checkout for merchant
    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce=str(uuid.uuid4()),
        aud="https://tennis-warehouse.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    role_log("agent", "Full chain created: L1 + L2 + L3a + L3b")
    print_sd_jwt("issuer", "L1 SD-JWT", l1.serialize())
    print_sd_jwt("user", "L2 SD-JWT", l2_ser)
    print_sd_jwt("agent", "L3a SD-JWT (payment)", l3a.serialize())
    print_sd_jwt("agent", "L3b SD-JWT (checkout)", l3b.serialize())

    # ------------------------------------------------------------------
    # L1 selective disclosure
    # ------------------------------------------------------------------
    step(2, "Layer 1: Issuer credential disclosures")

    print(f"\n  L1 has {len(l1.disclosures)} selectively disclosable claim (email):")
    print(f"  The base payload contains {len(l1.payload.get('_sd', []))} SD hash")

    # Without disclosures resolved
    print("\n  Without disclosures (verifier sees):")
    redacted("email")

    # With disclosures resolved
    resolved_l1 = resolve_disclosures(l1)
    print("\n  With disclosures (full view):")
    visible("email", resolved_l1.get("email", ""))

    # Always visible (v2: pan_last_four, scheme are always-visible)
    print("\n  Always visible (non-SD claims):")
    visible("iss", resolved_l1.get("iss", ""))
    visible("sub", resolved_l1.get("sub", ""))
    visible("vct", resolved_l1.get("vct", ""))
    visible("pan_last_four", resolved_l1.get("pan_last_four", ""))
    visible("scheme", resolved_l1.get("scheme", ""))

    # ------------------------------------------------------------------
    # L2 selective disclosure: role-specific views
    # ------------------------------------------------------------------
    step(3, "Layer 2: Role-specific presentations")

    l2_checkout_only, l2_payment_only = build_role_presentations(l2, l2_ser)

    # Merchant view
    merchant_l2 = decode_sd_jwt(l2_checkout_only)
    merchant_claims = resolve_disclosures(merchant_l2)
    merchant_delegates = merchant_claims.get("delegate_payload", [])

    print(f"\n  Merchant presentation ({len(merchant_l2.disclosures)} disclosures):")
    for d in merchant_delegates:
        if isinstance(d, dict):
            vct = d.get("vct", "unknown")
            if vct == "mandate.checkout.open.1":
                visible("mandate.checkout.open.1", f"constraints={len(d.get('constraints', []))}")
            elif vct == "mandate.payment.open.1":
                visible("mandate.payment.open.1", "(SHOULD NOT BE HERE)")
            elif "id" in d and "title" in d:
                visible(f"item: {d.get('title', 'unknown')}")
    # What merchant doesn't see
    redacted("mandate.payment.open (budget, payment instrument)")
    redacted("merchant entries (payee references)")

    # Network view
    network_l2 = decode_sd_jwt(l2_payment_only)
    network_claims = resolve_disclosures(network_l2)
    network_delegates = network_claims.get("delegate_payload", [])

    print(f"\n  Network presentation ({len(network_l2.disclosures)} disclosures):")
    for d in network_delegates:
        if isinstance(d, dict):
            vct = d.get("vct", "unknown")
            if vct == "mandate.payment.open.1":
                visible("mandate.payment.open.1", f"constraints={len(d.get('constraints', []))}")
            elif vct == "mandate.checkout.open.1":
                visible("mandate.checkout.open.1", "(SHOULD NOT BE HERE)")
            elif "name" in d and "website" in d:
                visible(f"merchant: {d['name']}", d.get("website", ""))
    # What network doesn't see
    redacted("mandate.checkout.open (product selection)")

    # ------------------------------------------------------------------
    # L3 selective disclosure (split L3a/L3b)
    # ------------------------------------------------------------------
    step(4, "Layer 3: Split L3a/L3b disclosures")

    # L3a disclosures (payment for network)
    print(f"\n  L3a has {len(l3a.disclosures)} disclosures (payment + merchant):")
    l3a_claims = resolve_disclosures(l3a)
    l3a_delegates = l3a_claims.get("delegate_payload", [])
    for d in l3a_delegates:
        if isinstance(d, dict):
            vct = d.get("vct", "")
            if vct == "mandate.payment.1":
                pa = d.get("payment_amount", {})
                visible("final payment", f"amount={pa.get('amount', '?')} cents")
            elif "name" in d:
                visible(f"merchant: {d.get('name', 'unknown')}")

    # L3b disclosures (checkout for merchant)
    print(f"\n  L3b has {len(l3b.disclosures)} disclosures (checkout):")
    l3b_claims = resolve_disclosures(l3b)
    l3b_delegates = l3b_claims.get("delegate_payload", [])
    for d in l3b_delegates:
        if isinstance(d, dict):
            vct = d.get("vct", "")
            if vct == "mandate.checkout.1":
                visible("final checkout", f"checkout_jwt present={bool(d.get('checkout_jwt'))}")

    print("\n  Network receives L3a: payment details only")
    redacted("checkout JWT (product details)")
    print("\n  Merchant receives L3b: checkout details only")
    redacted("final payment (amount, instrument, payee)")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    step(5, "Disclosure routing summary")

    print("""
  +----------------------------------------------------------+
  |  Merchant sees:                Network sees:              |
  |  ----------------              ----------------           |
  |  L1 (all)                      L1 (all)                  |
  |  L2 checkout mandate           L2 payment mandate         |
  |  L2 acceptable items           L2 merchant entries        |
  |  L3b checkout disclosure       L3a payment disclosure     |
  |                                L3a merchant disclosure    |
  |                                                           |
  |  Does NOT see:                 Does NOT see:              |
  |  - Payment details             - Checkout/product details |
  |  - Budget constraints          - Acceptable items         |
  |  - Merchant references         - Checkout JWT contents    |
  +----------------------------------------------------------+
""")

    # Assertions: verify disclosure routing produced correct views
    assert len(merchant_delegates) > 0, "Merchant should see at least one delegate"
    merchant_vcts = [d.get("vct") for d in merchant_delegates if isinstance(d, dict)]
    assert "mandate.checkout.open.1" in merchant_vcts, "Merchant should see checkout mandate"
    assert "mandate.payment.open.1" not in merchant_vcts, "Merchant should NOT see payment mandate"

    network_vcts = [d.get("vct") for d in network_delegates if isinstance(d, dict)]
    assert "mandate.payment.open.1" in network_vcts, "Network should see payment mandate"
    assert "mandate.checkout.open.1" not in network_vcts, "Network should NOT see checkout mandate"

    assert resolved_l1.get("email") == "alice@example.com", "L1 email should resolve"

    success("Selective disclosure demo complete")

    return True


if __name__ == "__main__":
    main()
