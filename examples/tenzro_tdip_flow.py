"""TDIP-rooted Verifiable Intent flow.

Demonstrates how a Verifiable Intent credential chain composes with the
Tenzro Decentralized Identity Protocol (TDIP). The user is identified by
a `did:tenzro:human:` DID, the agent by a `did:tenzro:machine:` DID, and
both VI constraints AND a mocked TDIP `DelegationScope::enforce_operation`
must pass for the purchase to proceed.

The TDIP primitives are mocked here for the sake of a self-contained
example; in production they live on-chain in the Tenzro Ledger identity
registry. See:
- TDIP spec: https://github.com/tenzro/tenzro-network/blob/main/TDIP.md
- Reference implementation: crates/tenzro-identity in the same repo.

Run: python examples/tenzro_tdip_flow.py
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

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


# ----------------------------------------------------------------------
# Mocked TDIP primitives
# ----------------------------------------------------------------------
#
# In production these live on-chain in the Tenzro Ledger identity
# registry and are queried via the TDIP `IdentityRegistry`. The Rust
# reference implementation lives at:
#   crates/tenzro-identity/src/registry.rs
#   crates/tenzro-identity/src/delegation.rs
#
# Here we model only enough of the surface to demonstrate composition
# with VI: a Machine identity bound to a Human controller, with a
# DelegationScope ceiling and a runtime SpendingPolicy.


@dataclass
class DelegationScope:
    """Structural ceiling on what an agent is authorized to do.

    Set at machine-identity registration time. Immutable for the life of
    the binding.
    """

    max_transaction_value: int  # in payment_currency base units (cents)
    max_daily_spend: int        # in payment_currency base units
    allowed_operations: set[str] = field(default_factory=set)
    allowed_payment_protocols: set[str] = field(default_factory=set)
    time_bound: int | None = None  # unix seconds

    def enforce_operation(
        self, operation: str, amount_cents: int, protocol: str, now: int
    ) -> tuple[bool, str | None]:
        """Returns (allowed, reason_if_denied)."""
        if operation not in self.allowed_operations:
            return False, f"operation {operation!r} not in allowed_operations"
        if amount_cents > self.max_transaction_value:
            return (
                False,
                f"amount {amount_cents} exceeds max_transaction_value {self.max_transaction_value}",
            )
        if protocol not in self.allowed_payment_protocols:
            return False, f"protocol {protocol!r} not in allowed_payment_protocols"
        if self.time_bound is not None and now > self.time_bound:
            return False, f"delegation expired at {self.time_bound}"
        return True, None


@dataclass
class SpendingPolicy:
    """Mutable runtime ceiling on per-day spend.

    Controllers dial this up or down without re-issuing the
    DelegationScope. Tracks current daily spend across a rolling window.
    """

    max_per_transaction: int
    max_daily_spend: int
    current_daily_spend: int = 0
    enabled: bool = True

    def check(self, amount_cents: int) -> tuple[bool, str | None]:
        if not self.enabled:
            return False, "spending policy disabled"
        if amount_cents > self.max_per_transaction:
            return (
                False,
                f"amount {amount_cents} exceeds max_per_transaction {self.max_per_transaction}",
            )
        if self.current_daily_spend + amount_cents > self.max_daily_spend:
            return (
                False,
                f"would exceed max_daily_spend (current {self.current_daily_spend} + {amount_cents} > {self.max_daily_spend})",
            )
        return True, None


@dataclass
class TdipMachineIdentity:
    """Mock of the on-chain TDIP machine identity record."""

    did: str                   # e.g. did:tenzro:machine:hilal:abc-123
    controller_did: str        # e.g. did:tenzro:human:hilal:def-456
    controller_jwk: dict[str, Any]
    delegation_scope: DelegationScope
    spending_policy: SpendingPolicy


def mock_tdip_resolve(did: str, registry: dict[str, TdipMachineIdentity]) -> TdipMachineIdentity:
    """Mock of TDIP `IdentityRegistry::resolve_identity`."""
    if did not in registry:
        raise KeyError(f"DID {did!r} not in TDIP registry")
    return registry[did]


# ----------------------------------------------------------------------
# Main flow
# ----------------------------------------------------------------------


def _find_disclosure(sd_jwt, predicate):
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def main():
    banner("TDIP-Rooted Verifiable Intent Flow")
    now = int(time.time())

    # Cryptographic keypairs (re-using the example helpers).
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    # TDIP-style DIDs for the human controller and the machine agent.
    user_did = "did:tenzro:human:hilal:def-456"
    agent_did = "did:tenzro:machine:hilal:abc-123"

    # Mock the TDIP registry binding the agent DID to its delegation
    # scope and runtime spending policy. The agent's controller key is
    # the human user's key.
    tdip_registry: dict[str, TdipMachineIdentity] = {
        agent_did: TdipMachineIdentity(
            did=agent_did,
            controller_did=user_did,
            controller_jwk=user.public_jwk,
            delegation_scope=DelegationScope(
                max_transaction_value=50000,    # $500.00
                max_daily_spend=100000,         # $1000.00 / day
                allowed_operations={"payment_send"},
                allowed_payment_protocols={"mpp", "tenzro"},
                time_bound=now + 86400 * 7,     # one week
            ),
            spending_policy=SpendingPolicy(
                max_per_transaction=50000,
                max_daily_spend=80000,           # tighter than the structural ceiling
                current_daily_spend=12000,       # $120 already spent today
            ),
        )
    }

    role_log("tdip", f"Registered machine identity: {agent_did}")
    role_log("tdip", f"  controller: {user_did}")
    role_log(
        "tdip",
        f"  scope: max_tx=${tdip_registry[agent_did].delegation_scope.max_transaction_value/100:.2f}, "
        f"max_daily=${tdip_registry[agent_did].delegation_scope.max_daily_spend/100:.2f}",
    )
    role_log(
        "tdip",
        f"  spending policy: max_tx=${tdip_registry[agent_did].spending_policy.max_per_transaction/100:.2f}, "
        f"max_daily=${tdip_registry[agent_did].spending_policy.max_daily_spend/100:.2f}, "
        f"spent today=${tdip_registry[agent_did].spending_policy.current_daily_spend/100:.2f}",
    )

    # ------------------------------------------------------------------
    # Step 1: Issuer creates L1 credential binding user's public key
    # ------------------------------------------------------------------
    step(1, "Issuer creates Layer 1 credential")

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub=user_did,             # subject is the user's TDIP DID
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        cnf_jwk=user.public_jwk,
        email="alice@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
    )
    l1 = create_layer1(cred, issuer.private_key)

    role_log("issuer", f"Created L1: subject={user_did}")
    role_log("issuer", f"  cnf.jwk binds the user's TDIP controller key (kid={user.kid})")
    print_sd_jwt("issuer", "L1 SD-JWT", l1.serialize())

    # ------------------------------------------------------------------
    # Step 2: User creates L2 mandate. The mandate's `aud` is the
    # agent's TDIP DID — this is what verifiers resolve against the
    # TDIP registry to fetch the structural DelegationScope.
    # ------------------------------------------------------------------
    step(2, "User creates Layer 2 mandate (TDIP-bound agent)")

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud=agent_did,                 # agent's TDIP DID
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy a Babolat tennis racket under $400 (TDIP-bound agent)",
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                AllowedMerchantConstraint(allowed=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[
                        {
                            "id": "line-item-1",
                            "acceptable_items": ACCEPTABLE_ITEMS,
                            "quantity": 1,
                        }
                    ],
                ),
            ],
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
            risk_data={"device_id": "tenzro-cli", "ip_address": "192.168.1.100"},
            constraints=[
                # Per-purchase intent: $100..$400.
                PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                AllowedPayeeConstraint(allowed=MERCHANTS),
            ],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user.private_key)

    role_log("user", f"L2 aud (agent DID): {agent_did}")
    role_log(
        "user",
        f"L2 payment constraint window: ${mandate.payment_mandate.constraints[0].min/100:.2f}-${mandate.payment_mandate.constraints[0].max/100:.2f}",
    )
    print_sd_jwt("user", "L2 SD-JWT", l2.serialize())

    # ------------------------------------------------------------------
    # Step 3: Agent picks a product and constructs the checkout
    # ------------------------------------------------------------------
    step(3, "Agent selects product and creates checkout")

    racket = next(
        (find_product(aid) for aid in [it["id"] for it in ACCEPTABLE_ITEMS] if find_product(aid)),
        None,
    )
    if racket is None or racket["category"] != "racket":
        # Fall back to the first racket in the catalog.
        for aid in [it["id"] for it in ACCEPTABLE_ITEMS]:
            p = find_product(aid)
            if p and p["category"] == "racket":
                racket = p
                break
    role_log("agent", f"Selected: {racket['name']} ({racket['price']} cents)")

    checkout_jwt = create_checkout_jwt(
        [{"sku": racket["sku"], "quantity": 1}],
        merchant,
    )
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    # ------------------------------------------------------------------
    # Step 4: Agent builds L3a (payment) and L3b (checkout)
    # ------------------------------------------------------------------
    step(4, "Agent creates Layer 3 fulfillment (split L3a/L3b)")

    nonce = str(uuid.uuid4())
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    payment_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
    )
    checkout_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
    )
    merchant_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse"
    )
    item_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345"
    )

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
        iss=agent_did,                # iss is the agent's TDIP DID
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(
        l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc
    )

    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce=nonce,
        aud="https://tennis-warehouse.com",
        iat=now,
        iss=agent_did,                # iss is the agent's TDIP DID
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(
        l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc
    )

    role_log("agent", f"L3a iss={agent_did}")
    role_log("agent", f"L3b iss={agent_did}")
    print_sd_jwt("agent", "L3a SD-JWT (payment)", l3a.serialize())
    print_sd_jwt("agent", "L3b SD-JWT (checkout)", l3b.serialize())

    # ------------------------------------------------------------------
    # Step 5: Selective L2 presentations for each role
    # ------------------------------------------------------------------
    step(5, "Selective disclosure routing")

    l2_checkout_only, l2_payment_only = build_role_presentations(l2, l2_ser)
    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

    # ------------------------------------------------------------------
    # Step 6: Network verifies the VI chain (L1+L2+L3a) AND
    # independently verifies the TDIP DelegationScope + SpendingPolicy.
    # Both must pass.
    # ------------------------------------------------------------------
    step(6, "Network verifies VI chain + TDIP DelegationScope + SpendingPolicy")

    l1_parsed = decode_sd_jwt(l1.serialize())
    l2_full_parsed = decode_sd_jwt(l2_ser)

    # 6a — VI chain.
    network_result = verify_chain(
        l1_parsed,
        l2_full_parsed,
        l3_payment=l3a,
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_payment_serialized=l2_payment_ser,
    )
    role_log("network", f"VI chain valid: {network_result.valid}")

    # 6b — VI per-purchase constraints.
    constraint_result = None
    if network_result.valid:
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

        from verifiable_intent.crypto.disclosure import hash_disclosure

        disc_by_hash = {}
        for disc_str, disc_val in zip(
            l2_full_parsed.disclosures, l2_full_parsed.disclosure_values
        ):
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
        role_log("network", f"VI constraints satisfied: {constraint_result.satisfied}")

    # 6c — TDIP DelegationScope (resolves L2 aud → machine identity).
    machine = mock_tdip_resolve(agent_did, tdip_registry)
    scope_ok, scope_reason = machine.delegation_scope.enforce_operation(
        operation="payment_send",
        amount_cents=racket["price"],
        protocol="mpp",
        now=now,
    )
    role_log(
        "tdip",
        f"DelegationScope.enforce_operation: ok={scope_ok}"
        + (f" (denied: {scope_reason})" if not scope_ok else ""),
    )

    # 6d — TDIP runtime SpendingPolicy.
    policy_ok, policy_reason = machine.spending_policy.check(racket["price"])
    role_log(
        "tdip",
        f"SpendingPolicy.check: ok={policy_ok}"
        + (f" (denied: {policy_reason})" if not policy_ok else ""),
    )

    # ------------------------------------------------------------------
    # Step 7: Merchant verifies the checkout-side chain (no TDIP
    # involvement on the merchant side — the merchant only cares that
    # the agent was authorized for *this* checkout, not what the
    # agent's overall daily spend looks like).
    # ------------------------------------------------------------------
    step(7, "Merchant verifies checkout-side chain")

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

    # ------------------------------------------------------------------
    # Step 8: Combined go/no-go
    # ------------------------------------------------------------------
    step(8, "Combined go/no-go")

    all_pass = (
        merchant_result.valid
        and network_result.valid
        and (constraint_result is not None and constraint_result.satisfied)
        and scope_ok
        and policy_ok
    )

    assert merchant_result.valid, f"Merchant chain failed: {merchant_result.errors}"
    assert network_result.valid, f"Network chain failed: {network_result.errors}"
    assert constraint_result is not None and constraint_result.satisfied, (
        f"VI constraints violated: "
        f"{constraint_result.violations if constraint_result else 'no result'}"
    )
    assert scope_ok, f"TDIP DelegationScope denied: {scope_reason}"
    assert policy_ok, f"TDIP SpendingPolicy denied: {policy_reason}"

    if all_pass:
        success("TDIP-rooted purchase completed successfully")
        result_box(
            "Assurance Data",
            {
                "vi_chain_valid": True,
                "vi_constraints_checked": constraint_result.satisfied,
                "tdip_delegation_scope_ok": scope_ok,
                "tdip_spending_policy_ok": policy_ok,
                "agent_did": agent_did,
                "controller_did": user_did,
                "product": racket["name"],
                "total_cents": racket["price"],
            },
        )
    else:
        error("Purchase failed")

    return all_pass


if __name__ == "__main__":
    main()
