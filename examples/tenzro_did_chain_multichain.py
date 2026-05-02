"""Multi-chain TDIP-rooted Verifiable Intent flow.

Companion to ``examples/tenzro_tdip_flow.py`` (PR #25). That example showed
how a single VI credential chain composes with TDIP on a single
settlement chain. This example takes the same delegation chain and
exercises ``DelegationScope.allowed_chains`` across **four** Tenzro VM
facades in a single shopping run:

  1. Ethereum  — wTNZO ERC-20 pointer at 0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93
  2. Solana    — wTNZO-SPL adapter
  3. Canton    — TNZO CIP-56 holding
  4. Polygon   — *not* in ``allowed_chains``; expected to be rejected

For each accepted purchase, a Plonky3 STARK is generated over a
per-purchase ``cart_hash`` and the resulting 32-byte commitment is
recorded in Tenzro's on-chain ``ZkCommitmentRegistry``. Anyone with a
copy of the cart contents can later reconstruct the same commitment and
do an O(1) registry lookup, without re-running the prover. This binds
the off-chain VI L3 record to an on-chain artefact.

All four ceilings of the original example continue to apply:

    1. VI chain validity (`verify_chain`)
    2. VI per-purchase constraints (`check_constraints`)
    3. TDIP `DelegationScope::enforce_operation` — including per-chain
       gating via the `allowed_chains` field
    4. TDIP runtime `SpendingPolicy::check`

Run::

    python examples/tenzro_did_chain_multichain.py

By default, all RPC calls to ``rpc.tenzro.network`` are stubbed out — the
Plonky3 commitment is computed locally from the documented hash
construction (`SHA-256(circuit_id || proof_bytes ||
Σ(len_le(pi) || pi))`). To run against a live node, set
``TENZRO_RPC_URL`` (e.g. ``https://rpc.tenzro.network``) and the
example will issue real ``tenzro_createZkProof`` JSON-RPC calls instead.

References:
    - TDIP spec: https://github.com/tenzro/tenzro-network/blob/main/TDIP.md
    - DelegationScope.allowed_chains: crates/tenzro-identity/src/delegation.rs
    - ZkCommitmentRegistry: crates/tenzro-zk + crates/tenzro-vm
    - PR #25 (single-chain TDIP flow): docs/protocol-landscape/tenzro-tdip.md
"""

from __future__ import annotations

import hashlib
import json
import os
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
from verifiable_intent.verification.constraint_checker import check_constraints


# ----------------------------------------------------------------------
# Mocked TDIP primitives — see PR #25 for rationale
# ----------------------------------------------------------------------
#
# The single-chain example (PR #25) introduced these dataclasses; here we
# extend `DelegationScope` with `allowed_chains` and a corresponding
# `is_chain_allowed` helper. The Rust reference implementation in
# `crates/tenzro-identity/src/delegation.rs` is the source of truth; this
# Python mock tracks its semantics exactly:
#
#   - empty list  => all chains allowed (matches Rust behaviour)
#   - non-empty   => membership check, deny otherwise


CHAIN_NOT_ALLOWED = "ChainNotAllowed"  # Maps to IdentityError::DelegationViolation


@dataclass
class DelegationScope:
    """Structural ceiling on what an agent is authorized to do.

    Set at machine-identity registration time. Immutable for the life of
    the binding.
    """

    max_transaction_value: int  # base units (cents for USD examples)
    max_daily_spend: int
    allowed_operations: set[str] = field(default_factory=set)
    allowed_payment_protocols: set[str] = field(default_factory=set)
    allowed_chains: list[str] = field(default_factory=list)
    time_bound: int | None = None

    def is_chain_allowed(self, chain: str) -> bool:
        if not self.allowed_chains:
            return True
        return chain in self.allowed_chains

    def enforce_operation(
        self,
        operation: str,
        amount_cents: int,
        protocol: str,
        chain: str,
        now: int,
    ) -> tuple[bool, str | None]:
        """Returns (allowed, reason_if_denied).

        Returns the typed reason ``CHAIN_NOT_ALLOWED`` for chain denial
        so callers can branch on the failure mode.
        """
        if operation not in self.allowed_operations:
            return False, f"operation {operation!r} not in allowed_operations"
        if amount_cents > self.max_transaction_value:
            return (
                False,
                f"amount {amount_cents} exceeds max_transaction_value {self.max_transaction_value}",
            )
        if protocol not in self.allowed_payment_protocols:
            return False, f"protocol {protocol!r} not in allowed_payment_protocols"
        if not self.is_chain_allowed(chain):
            return False, f"{CHAIN_NOT_ALLOWED}: chain {chain!r} not in allowed_chains"
        if self.time_bound is not None and now > self.time_bound:
            return False, f"delegation expired at {self.time_bound}"
        return True, None


@dataclass
class SpendingPolicy:
    """Mutable runtime ceiling — see PR #25 example."""

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
                f"would exceed max_daily_spend (current {self.current_daily_spend} + "
                f"{amount_cents} > {self.max_daily_spend})",
            )
        return True, None

    def record(self, amount_cents: int) -> None:
        self.current_daily_spend += amount_cents


@dataclass
class TdipMachineIdentity:
    """Mock of the on-chain TDIP machine identity record."""

    did: str
    controller_did: str
    controller_jwk: dict[str, Any]
    delegation_scope: DelegationScope
    spending_policy: SpendingPolicy


# ----------------------------------------------------------------------
# Per-VM facade configuration
# ----------------------------------------------------------------------
#
# Each entry describes how the same TNZO native balance is exposed on a
# different VM. The agent presents a per-VM payment instrument; the
# `chain` field is what `DelegationScope.allowed_chains` is checked
# against; `vm_label` is purely descriptive.

CHAIN_FACADES: dict[str, dict[str, Any]] = {
    "ethereum": {
        "vm_label": "EVM",
        "facade": "wTNZO ERC-20 pointer",
        "address": "0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93",
        "instrument": {
            "type": "tenzro.wtnzo.erc20",
            "chain": "ethereum",
            "address": "0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93",
            "decimals": 18,
        },
    },
    "solana": {
        "vm_label": "SVM",
        "facade": "wTNZO-SPL adapter",
        "address": "wTNZOsoLqCYeYRCC9G2gC8oKEdFuzELhRaq3CaUq3JT",  # placeholder mint
        "instrument": {
            "type": "tenzro.wtnzo.spl",
            "chain": "solana",
            "mint": "wTNZOsoLqCYeYRCC9G2gC8oKEdFuzELhRaq3CaUq3JT",
            "decimals": 9,
        },
    },
    "canton": {
        "vm_label": "DAML",
        "facade": "TNZO CIP-56 holding",
        "address": "tenzro::TnzoToken",  # template id placeholder
        "instrument": {
            "type": "tenzro.tnzo.cip56",
            "chain": "canton",
            "template_id": "Tenzro.Tnzo:Holding",
            "decimals": 18,
        },
    },
    "polygon": {
        # Intentionally NOT in allowed_chains — used to demonstrate denial.
        "vm_label": "EVM",
        "facade": "wTNZO Polygon ERC-20 (hypothetical)",
        "address": "0x000000000000000000000000000000000000dEaD",
        "instrument": {
            "type": "tenzro.wtnzo.erc20",
            "chain": "polygon",
            "address": "0x000000000000000000000000000000000000dEaD",
            "decimals": 18,
        },
    },
}


# ----------------------------------------------------------------------
# Plonky3 cart-hash commitment
# ----------------------------------------------------------------------
#
# In production, validators run the Plonky3 prover and verifier against
# a small AIR (e.g. `settlement` or a dedicated `cart_purchase` AIR) and
# record the resulting 32-byte commitment in `ZkCommitmentRegistry`.
# Here we model only the commitment hash itself — the construction
# documented in `crates/tenzro-zk/README.md`:
#
#     compute_zk_commitment(circuit_id, proof_bytes, public_inputs)
#       = SHA-256(circuit_id ‖ proof_bytes ‖ Σ(len_le(pi) ‖ pi))
#
# A live run (with TENZRO_RPC_URL set) calls `tenzro_createZkProof`
# instead of fabricating proof_bytes locally.


def cart_payload_bytes(
    *,
    chain: str,
    merchant_id: str,
    sku: str,
    quantity: int,
    amount_minor: int,
    currency: str,
) -> bytes:
    """Canonical, deterministic byte representation of a cart payload.

    The same canonicalisation must be reproducible by any verifier; we
    use sorted-key JSON to stay portable across languages.
    """
    payload = {
        "amount_minor": amount_minor,
        "chain": chain,
        "currency": currency,
        "merchant_id": merchant_id,
        "quantity": quantity,
        "sku": sku,
        "version": 1,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def compute_zk_commitment(
    circuit_id: str, proof_bytes: bytes, public_inputs: list[bytes]
) -> bytes:
    """Replicates `tenzro_zk::compute_zk_commitment`.

    SHA-256(circuit_id || proof_bytes || Σ(len_le_4(pi) || pi))
    """
    h = hashlib.sha256()
    h.update(circuit_id.encode("ascii"))
    h.update(proof_bytes)
    for pi in public_inputs:
        h.update(len(pi).to_bytes(4, "little"))
        h.update(pi)
    return h.digest()


def stub_proof_bytes(cart_bytes: bytes) -> bytes:
    """Deterministic placeholder for `proof_bytes` in offline mode.

    A real Plonky3 STARK over the `settlement` AIR is ~64-128 KB; the
    commitment is a 32-byte SHA-256 over (circuit_id, proof_bytes,
    public_inputs) so the exact proof_bytes content is not relevant for
    this example as long as it is reproducible.
    """
    return b"plonky3-stark-stub:" + hashlib.sha256(cart_bytes).digest()


def create_zk_proof_via_rpc(
    circuit_id: str, public_inputs: list[bytes], rpc_url: str
) -> tuple[bytes, list[bytes]]:
    """Optional: call `tenzro_createZkProof` against a live Tenzro node.

    Stays import-free at module top-level (`requests` is only imported
    inside this function) so the offline path has stdlib-only deps.
    """
    import requests  # type: ignore[import-not-found]

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_createZkProof",
        "params": [
            {
                "circuit_id": circuit_id,
                # The settlement AIR's public-input layout is documented
                # in tenzro-zk/src/plonky3/settlement.rs. The exact
                # field-name conventions are RPC-specific; the example
                # passes the cart bytes hashed into 4-byte LE chunks.
                "public_inputs_hex": [pi.hex() for pi in public_inputs],
            }
        ],
    }
    resp = requests.post(rpc_url, json=body, timeout=30)
    resp.raise_for_status()
    result = resp.json()["result"]
    proof_bytes = bytes.fromhex(result["proof_bytes_hex"])
    returned_inputs = [bytes.fromhex(x) for x in result["public_inputs_hex"]]
    return proof_bytes, returned_inputs


# ----------------------------------------------------------------------
# Mock on-chain commitment registry
# ----------------------------------------------------------------------


class ZkCommitmentRegistry:
    """In-memory mock of the on-chain `ZkCommitmentRegistry`.

    The real registry is an O(1) HashSet on every validator that the
    EVM `ZK_VERIFY` precompile (0x100x) reads from. Here we model just
    enough to demonstrate "record then look up".
    """

    def __init__(self) -> None:
        self._commitments: set[bytes] = set()

    def record(self, commitment: bytes) -> None:
        self._commitments.add(commitment)

    def contains(self, commitment: bytes) -> bool:
        return commitment in self._commitments

    def __len__(self) -> int:
        return len(self._commitments)


# ----------------------------------------------------------------------
# VI L3a builder helper (shared across the three accepted purchases)
# ----------------------------------------------------------------------


def _find_disclosure(sd_jwt, predicate):
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


# ----------------------------------------------------------------------
# Main flow
# ----------------------------------------------------------------------


def main() -> bool:
    banner("Multi-Chain TDIP-Rooted Verifiable Intent Flow")
    rpc_url = os.environ.get("TENZRO_RPC_URL")
    role_log("env", f"TENZRO_RPC_URL = {rpc_url or '(unset; using offline stub)'}")

    now = int(time.time())

    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    user_did = "did:tenzro:human:alice"
    agent_did = "did:tenzro:machine:shopper"

    # Delegation scope explicitly enumerates four chains. Polygon is
    # absent on purpose — the fourth purchase will fail against this.
    allowed_chains = ["tenzro", "ethereum", "solana", "canton"]

    tdip_registry: dict[str, TdipMachineIdentity] = {
        agent_did: TdipMachineIdentity(
            did=agent_did,
            controller_did=user_did,
            controller_jwk=user.public_jwk,
            delegation_scope=DelegationScope(
                max_transaction_value=10000,            # $100 per tx
                max_daily_spend=50000,                  # $500 per day
                allowed_operations={"payment_send"},
                allowed_payment_protocols={"mpp", "x402", "tenzro"},
                allowed_chains=allowed_chains,
                time_bound=now + 86400 * 30,            # 30 days
            ),
            spending_policy=SpendingPolicy(
                max_per_transaction=10000,
                max_daily_spend=50000,
                current_daily_spend=0,
            ),
        )
    }
    machine = tdip_registry[agent_did]

    role_log("tdip", f"Registered {agent_did}")
    role_log("tdip", f"  controller: {user_did}")
    role_log(
        "tdip",
        f"  allowed_chains: {machine.delegation_scope.allowed_chains}",
    )
    role_log(
        "tdip",
        f"  max_per_tx=${machine.delegation_scope.max_transaction_value/100:.2f}, "
        f"max_daily=${machine.delegation_scope.max_daily_spend/100:.2f}",
    )

    # ------------------------------------------------------------------
    # Step 1: Issuer creates L1 credential
    # ------------------------------------------------------------------
    step(1, "Issuer creates Layer 1 credential (binds Alice's TDIP key)")

    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub=user_did,
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        cnf_jwk=user.public_jwk,
        email="alice@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
    )
    l1 = create_layer1(cred, issuer.private_key)
    role_log("issuer", f"L1 sub={user_did}")
    print_sd_jwt("issuer", "L1 SD-JWT", l1.serialize())

    # ------------------------------------------------------------------
    # Step 2: User creates a single L2 mandate covering the whole
    # multi-chain shopping run. Per-purchase intent (currency window)
    # lives in the L2 constraints; the per-chain ceiling lives in the
    # TDIP DelegationScope.
    # ------------------------------------------------------------------
    step(2, "User creates Layer 2 mandate (multi-chain shopping run)")

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud=agent_did,
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy tennis gear across whichever VM the merchant prefers",
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
                # Per-purchase window: $1..$100 (matches the 10000-cent
                # max_per_transaction TDIP ceiling).
                PaymentAmountConstraint(currency="USD", min=100, max=10000),
                AllowedPayeeConstraint(allowed=MERCHANTS),
            ],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user.private_key)
    role_log("user", f"L2 aud={agent_did}")
    print_sd_jwt("user", "L2 SD-JWT", l2.serialize())

    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]
    payment_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
    )
    merchant_disc = _find_disclosure(
        l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse"
    )

    l1_parsed = decode_sd_jwt(l1.serialize())
    l2_full_parsed = decode_sd_jwt(l2_ser)
    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

    # Pick a single product (USD price comfortably inside the $1..$100
    # window) and reuse the same SKU across all three accepted chains.
    sku = ACCEPTABLE_ITEMS[0]["id"]  # BAB86345
    product_record = find_product(sku)
    assert product_record is not None, "demo SKU missing from catalog"
    # The catalog price is too high for the multi-chain demo; we use a
    # per-purchase override anchored to the cart payload bytes.

    # Three accepted purchases on three different VMs, plus one denied
    # purchase to demonstrate the chain gate.
    purchases = [
        {
            "label": "Purchase A — Ethereum",
            "chain": "ethereum",
            "amount_cents": 5000,   # $50
        },
        {
            "label": "Purchase B — Solana",
            "chain": "solana",
            "amount_cents": 3000,   # $30
        },
        {
            "label": "Purchase C — Canton",
            "chain": "canton",
            "amount_cents": 4000,   # $40
        },
        {
            "label": "Purchase D — Polygon (DENIAL EXPECTED)",
            "chain": "polygon",
            "amount_cents": 2500,   # $25, but disallowed-chain
        },
    ]

    registry = ZkCommitmentRegistry()
    purchase_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Steps 3..N: For each purchase, run all four ceilings and (if
    # accepted) record a Plonky3 commitment.
    # ------------------------------------------------------------------
    for i, p in enumerate(purchases, start=3):
        step(i, p["label"])
        chain = p["chain"]
        amount_cents = p["amount_cents"]
        facade = CHAIN_FACADES[chain]

        role_log(
            "agent",
            f"VM={facade['vm_label']}, facade={facade['facade']}, addr={facade['address']}",
        )
        role_log("agent", f"Cart: 1x {sku} for ${amount_cents/100:.2f} on {chain}")

        # Build a per-purchase L3a payment fulfilment. We reuse the L2
        # mandate's open-payment template but stamp the chain-specific
        # instrument and a deterministic transaction_id derived from the
        # cart bytes so that the cart_hash binds the L3 record.
        cart_bytes = cart_payload_bytes(
            chain=chain,
            merchant_id=MERCHANTS[0]["id"],
            sku=sku,
            quantity=1,
            amount_minor=amount_cents,
            currency="USD",
        )
        cart_hash_hex = hashlib.sha256(cart_bytes).hexdigest()

        final_payment = FinalPaymentMandate(
            transaction_id=cart_hash_hex,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": amount_cents},
            payment_instrument=facade["instrument"],
        )
        l3a_mandate = PaymentL3Mandate(
            nonce=str(uuid.uuid4()),
            aud="https://www.mastercard.com",
            iat=now,
            iss=agent_did,
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(
            l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc
        )

        # Ceiling 1: VI chain.
        chain_result = verify_chain(
            l1_parsed,
            l2_full_parsed,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        role_log("network", f"VI chain valid: {chain_result.valid}")

        # Ceiling 2: VI per-purchase constraint.
        l2_pay_claims = resolve_disclosures(l2_full_parsed)
        l3_pay_claims = chain_result.l3_payment_claims if chain_result.valid else {}
        payment_constraints = []
        for delegate in l2_pay_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.open.1":
                payment_constraints = delegate.get("constraints", [])
                break
        fulfillment: dict[str, Any] = {}
        for delegate in l3_pay_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.1":
                fulfillment = delegate
                break
        # Resolve the merchant disclosure for AllowedPayeeConstraint.
        from verifiable_intent.crypto.disclosure import hash_disclosure

        disc_by_hash = {}
        for disc_str, disc_val in zip(
            l2_full_parsed.disclosures, l2_full_parsed.disclosure_values
        ):
            disc_by_hash[hash_disclosure(disc_str)] = disc_val
        for c in payment_constraints:
            if c.get("type") == "mandate.payment.allowed_payees":
                resolved = []
                for ref in c.get("allowed", []):
                    h = ref.get("...", "") if isinstance(ref, dict) else ""
                    if h and h in disc_by_hash:
                        resolved.append(disc_by_hash[h][-1])
                fulfillment["allowed_merchants"] = resolved
                break
        constraint_result = check_constraints(payment_constraints, fulfillment)
        role_log("network", f"VI constraints satisfied: {constraint_result.satisfied}")

        # Ceiling 3: TDIP DelegationScope (per-chain gate).
        scope_ok, scope_reason = machine.delegation_scope.enforce_operation(
            operation="payment_send",
            amount_cents=amount_cents,
            protocol="mpp",
            chain=chain,
            now=now,
        )
        role_log(
            "tdip",
            f"DelegationScope.enforce_operation: ok={scope_ok}"
            + (f" (denied: {scope_reason})" if not scope_ok else ""),
        )

        # Ceiling 4: TDIP runtime SpendingPolicy.
        policy_ok, policy_reason = machine.spending_policy.check(amount_cents)
        role_log(
            "tdip",
            f"SpendingPolicy.check: ok={policy_ok}"
            + (f" (denied: {policy_reason})" if not policy_ok else ""),
        )

        all_ok = (
            chain_result.valid
            and constraint_result.satisfied
            and scope_ok
            and policy_ok
        )

        commitment_hex: str | None = None
        if all_ok:
            # Record on-chain Plonky3 commitment.
            if rpc_url:
                role_log("zk", f"Calling tenzro_createZkProof on {rpc_url}")
                try:
                    proof_bytes, public_inputs = create_zk_proof_via_rpc(
                        "settlement",
                        [cart_bytes],
                        rpc_url,
                    )
                except Exception as exc:  # noqa: BLE001
                    role_log("zk", f"RPC failed ({exc}); falling back to offline stub")
                    proof_bytes = stub_proof_bytes(cart_bytes)
                    public_inputs = [cart_bytes]
            else:
                proof_bytes = stub_proof_bytes(cart_bytes)
                public_inputs = [cart_bytes]

            commitment = compute_zk_commitment("settlement", proof_bytes, public_inputs)
            registry.record(commitment)
            commitment_hex = commitment.hex()
            role_log("zk", f"Recorded commitment in registry: 0x{commitment_hex[:16]}...")
            assert registry.contains(commitment), "round-trip lookup must succeed"
            machine.spending_policy.record(amount_cents)

        purchase_log.append(
            {
                "label": p["label"],
                "chain": chain,
                "amount_cents": amount_cents,
                "vi_chain_valid": chain_result.valid,
                "vi_constraints_ok": constraint_result.satisfied,
                "tdip_scope_ok": scope_ok,
                "tdip_scope_reason": scope_reason,
                "tdip_policy_ok": policy_ok,
                "cart_hash": cart_hash_hex,
                "zk_commitment": commitment_hex,
                "settled": all_ok,
            }
        )

    # ------------------------------------------------------------------
    # Final assertions: A/B/C must succeed; D must fail with chain gate.
    # ------------------------------------------------------------------
    step(len(purchases) + 3, "Final assertions")

    by_label = {entry["label"]: entry for entry in purchase_log}

    accepted = [
        "Purchase A — Ethereum",
        "Purchase B — Solana",
        "Purchase C — Canton",
    ]
    for label in accepted:
        e = by_label[label]
        assert e["settled"], f"{label} unexpectedly failed: {e}"
        assert e["zk_commitment"] is not None, f"{label} produced no commitment"
        assert len(bytes.fromhex(e["zk_commitment"])) == 32, f"{label} commitment not 32 bytes"

    denied = by_label["Purchase D — Polygon (DENIAL EXPECTED)"]
    assert not denied["settled"], "Polygon purchase should have been denied"
    assert not denied["tdip_scope_ok"], "Polygon should fail the DelegationScope gate"
    assert CHAIN_NOT_ALLOWED in (denied["tdip_scope_reason"] or ""), (
        f"Polygon denial should cite ChainNotAllowed, got: {denied['tdip_scope_reason']!r}"
    )
    role_log("network", f"Denied as expected: {denied['tdip_scope_reason']}")

    # All commitments must be unique (each cart binds a different
    # transaction).
    assert len(registry) == 3, f"expected 3 commitments, got {len(registry)}"

    success("Multi-chain TDIP-rooted purchases settled with on-chain ZK anchoring")
    result_box(
        "Run Summary",
        {
            "agent_did": agent_did,
            "controller_did": user_did,
            "allowed_chains": allowed_chains,
            "purchases_attempted": len(purchases),
            "purchases_settled": sum(1 for p in purchase_log if p["settled"]),
            "purchases_denied": sum(1 for p in purchase_log if not p["settled"]),
            "denial_reason": denied["tdip_scope_reason"],
            "zk_commitments_recorded": len(registry),
            "spending_policy_used": (
                f"${machine.spending_policy.current_daily_spend/100:.2f} of "
                f"${machine.spending_policy.max_daily_spend/100:.2f}"
            ),
        },
    )

    for p in purchase_log:
        commit = p["zk_commitment"]
        commit_short = f"0x{commit[:16]}..." if commit else "—"
        status = "settled" if p["settled"] else f"denied ({p['tdip_scope_reason']})"
        role_log(
            "report",
            f"{p['label']}: {status}, cart_hash=0x{p['cart_hash'][:16]}..., commitment={commit_short}",
        )

    return True


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        error(f"Assertion failed: {exc}")
        raise
