"""Complete immediate (2-layer) VI purchase flow.

Demonstrates the no-delegation pattern:
  L1: Issuer credential (binds user's public key via cnf.jwk)
  L2: User mandate with final values (NO cnf, NO agent delegation, NO L3)

The user is present, signs final checkout and payment values directly.
Agent assists with checkout but creates no credentials.

Run: python examples/immediate_flow.py
"""

from __future__ import annotations

import time
import uuid

# Import helpers first — bootstraps sys.path for SDK imports.
from helpers import (
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    banner,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    error,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
    print_sd_jwt,
    result_box,
    role_log,
    step,
    success,
)
from verifiable_intent.crypto.disclosure import hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures
from verifiable_intent.issuance.issuer import create_layer1
from verifiable_intent.issuance.user import create_layer2_immediate
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import (
    CheckoutMandate,
    MandateMode,
    PaymentMandate,
    UserMandate,
)
from verifiable_intent.verification.chain import verify_chain


def main():
    banner("Immediate (2-Layer) Purchase Flow")
    now = int(time.time())

    issuer = get_issuer_keys()
    user = get_user_keys()
    merchant = get_merchant_keys()

    # ------------------------------------------------------------------
    # Step 1: Issuer creates L1 credential
    # ------------------------------------------------------------------
    step(1, "Issuer creates Layer 1 credential")

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="user-bob-001",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        cnf_jwk=user.public_jwk,
        email="bob@example.com",
        pan_last_four="5678",
        scheme="Mastercard",
    )
    l1 = create_layer1(cred, issuer.private_key)

    role_log("issuer", f"Created L1: {len(l1.disclosures)} selective disclosure (email)")
    role_log("issuer", f"  cnf.jwk binds user key (kid={user.kid})")
    print_sd_jwt("issuer", "L1 SD-JWT", l1.serialize())

    # ------------------------------------------------------------------
    # Step 2: User browses catalog and creates checkout directly
    # ------------------------------------------------------------------
    step(2, "User creates checkout at merchant (human present)")

    checkout_jwt = create_checkout_jwt(
        [{"sku": "BAB86345", "quantity": 1}],
        merchant,
    )
    c_hash = checkout_hash_from_jwt(checkout_jwt)
    role_log("merchant", f"Checkout JWT created, hash: {c_hash[:32]}...")
    role_log("user", "User reviewed checkout and confirmed items")

    # ------------------------------------------------------------------
    # Step 3: User signs L2 with final values (no delegation)
    # ------------------------------------------------------------------
    step(3, "User creates Layer 2 mandate (immediate)")

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud="https://agent.verifiable-intent.example",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 900,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Purchase Babolat Pure Aero racket",
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.1",
            # No cnf_jwk — user signs final values directly
            checkout_jwt=checkout_jwt,
            checkout_hash=c_hash,
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.1",
            # No cnf_jwk — final payment values set by user
            payment_instrument=PAYMENT_INSTRUMENT,
            payee=MERCHANTS[0],
            currency="USD",
            amount=27999,
            transaction_id=c_hash,
        ),
    )
    result = create_layer2_immediate(mandate, user.private_key)
    l2 = result.sd_jwt

    role_log("user", f"Created L2: {len(l2.disclosures)} disclosures")
    role_log("user", "  mode=IMMEDIATE — NO cnf.jwk, NO agent delegation")
    role_log("user", "  Mandates contain final values (checkout JWT + payment details)")

    # Verify no cnf in mandates
    l2_claims = resolve_disclosures(l2)
    has_cnf = False
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and "cnf" in delegate:
            has_cnf = True
    role_log("user", f"  cnf in mandates: {has_cnf} (expected: False)")
    print_sd_jwt("user", "L2 SD-JWT", l2.serialize())

    # ------------------------------------------------------------------
    # Step 4: Agent assists with checkout (forwards L1+L2, no L3)
    # ------------------------------------------------------------------
    step(4, "Agent forwards credentials (no L3 creation)")

    role_log("agent", "Immediate mode: agent forwards L1+L2 only")
    role_log("agent", "No Layer 3 needed — user signed final values directly")

    # ------------------------------------------------------------------
    # Step 5: Verification (2-layer chain)
    # ------------------------------------------------------------------
    step(5, "Verify 2-layer chain")

    # Merchant: structural verification (using issuer key obtained from JWKS endpoint)
    # NOTE: In production the merchant MUST supply issuer_public_key obtained from
    # the issuer's JWKS endpoint. skip_issuer_verification=True is shown here only
    # to illustrate the structural checks in isolation; do not use it in production.
    merchant_result = verify_chain(l1, l2, l3_payment=None, skip_issuer_verification=True)
    role_log("merchant", f"Structural chain valid: {merchant_result.valid}")

    # Network: full verification with issuer signature
    network_result = verify_chain(
        l1,
        l2,
        l3_payment=None,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
    )
    role_log("network", f"Full chain valid: {network_result.valid}")

    if not network_result.valid:
        for e in network_result.errors:
            role_log("network", f"  Error: {e}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    step(6, "Summary")

    assert merchant_result.valid, f"Merchant chain failed: {merchant_result.errors}"
    assert network_result.valid, f"Network chain failed: {network_result.errors}"

    if merchant_result.valid and network_result.valid:
        success("Immediate purchase completed successfully")
        result_box(
            "Assurance Data",
            {
                "chain_valid": True,
                "mode": "IMMEDIATE (2-layer)",
                "total_cents": "27999",
                "layers": "L1 + L2 only (no L3)",
                "delegation": "None — user signed directly",
            },
        )
    else:
        error("Purchase failed")

    return True


if __name__ == "__main__":
    main()
