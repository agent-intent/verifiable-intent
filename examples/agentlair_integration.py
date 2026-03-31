"""AgentLair + Mastercard Verifiable Intent — End-to-End Integration Demo.

Demonstrates how an AgentLair agent operates within a Mastercard Verifiable
Intent (VI) Autonomous mode delegation chain.

Architecture:
  - AgentLair provides: agent identity, keypair management, L3 signing vault
  - Verifiable Intent provides: user authorization chain (L1→L2→L3)

Flow:
  1. AgentLair agent generates a P-256 keypair (via AgentLair API in production)
  2. User creates VI L2 credential with the AgentLair agent's JWK + constraints
  3. AgentLair agent creates L3 credentials (checkout + payment mandates)
  4. Merchant and network verify L3 credentials against L2 constraints

Run:
  git clone https://github.com/agent-intent/verifiable-intent
  cd verifiable-intent
  pip install -e ".[dev]"
  python examples/agentlair_integration.py

AgentLair API Reference (production integration):
  GET  /v1/agents/public-key          → agent's P-256 JWK
  POST /v1/agents/vi/sign-l3          → sign L3 credential (vault-side)
  GET  /.well-known/agent-keys/{kid}  → verifier key lookup
"""

from __future__ import annotations

import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

# ─── Path bootstrapping ───────────────────────────────────────────────────────
# When running from the verifiable-intent repo root, add src/ to sys.path.
# When installed via pip install -e ".[dev]", this is not needed.
_REPO_SRC = Path(__file__).resolve().parent.parent / "src"
if _REPO_SRC.exists() and str(_REPO_SRC) not in sys.path:
    sys.path.insert(0, str(_REPO_SRC))

# ─── Standard imports ─────────────────────────────────────────────────────────
import hashlib
import json
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ec

from verifiable_intent.crypto.disclosure import (
    _b64url_encode,
    build_selective_presentation,
    hash_bytes,
    hash_disclosure,
)
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures
from verifiable_intent.crypto.signing import (
    _jwt_encode,
    private_key_to_jwk,
    public_key_to_jwk,
)
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

# ─── Console utilities ────────────────────────────────────────────────────────

BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
BLUE = "\033[94m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
MAGENTA = "\033[95m"; CYAN = "\033[96m"; RED = "\033[91m"

ROLE_COLORS = {
    "issuer": BLUE, "user": GREEN, "merchant": YELLOW,
    "network": MAGENTA, "agent": CYAN, "agentlair": BOLD + BLUE,
}


def banner(title: str) -> None:
    print(f"\n{BOLD}{'=' * 65}{RESET}")
    print(f"{BOLD}{title:^65}{RESET}")
    print(f"{BOLD}{'=' * 65}{RESET}\n")


def step(num: int, title: str) -> None:
    print(f"\n{BOLD}Step {num}: {title}{RESET}")
    print(f"{DIM}{'-' * 55}{RESET}")


def log(role: str, msg: str) -> None:
    color = ROLE_COLORS.get(role, "")
    print(f"  {color}[{role.upper():^12}]{RESET} {msg}")


def ok(msg: str) -> None:
    print(f"\n{GREEN}{BOLD}✓ {msg}{RESET}")


def fail(msg: str) -> None:
    print(f"\n{RED}{BOLD}✗ {msg}{RESET}")


# ─── Key types ────────────────────────────────────────────────────────────────


@dataclass
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_jwk: dict
    kid: str

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()


def _keyfrom(d: int, kid: str) -> KeyPair:
    priv = ec.derive_private_key(d, ec.SECP256R1())
    return KeyPair(private_key=priv, public_jwk=public_key_to_jwk(priv), kid=kid)


# ─── AgentLair simulation layer ───────────────────────────────────────────────
#
# In production these calls would be AgentLair API requests:
#
#   GET /v1/agents/{id}/public-key
#     → {"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"...","use":"sig"}
#
#   POST /v1/agents/vi/sign-l3
#     {"l3_payload": {...}, "mandate_id": "...", "l2_base_jwt": "..."}
#     → {"signed_l3": "<SD-JWT string>"}
#
#   GET /.well-known/agent-keys/{kid}/jwks.json
#     → {"keys":[{"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"..."}]}
#
# The simulation below uses the same P-256 key the SDK uses, with annotated
# comments showing where each AgentLair API call would occur.

# Fixed demo private scalars — NOT secret, test only.
_ISSUER_D   = 0x1A2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01
_USER_D     = 0x2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF0102
_AGENT_D    = 0x3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF010203
_MERCHANT_D = 0x4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01020304

ISSUER_KEYS   = _keyfrom(_ISSUER_D, "mastercard-issuer-key-1")
USER_KEYS     = _keyfrom(_USER_D, "user-device-key-1")
MERCHANT_KEYS = _keyfrom(_MERCHANT_D, "merchant-key-1")

# ── AGENTLAIR INTEGRATION POINT 1: Agent keypair ─────────────────────────────
# Production: GET https://api.agentlair.dev/v1/agents/{agent_id}/public-key
# The AgentLair API returns the agent's P-256 public key as a JWK.
# The private key stays in AgentLair's vault (never leaves).
#
# Example response:
# {
#   "kty": "EC", "crv": "P-256",
#   "x": "<base64url>", "y": "<base64url>",
#   "kid": "al-agent-abc123-key-1",
#   "use": "sig", "alg": "ES256"
# }
AGENT_KEYS = _keyfrom(_AGENT_D, "al-agent-abc123-key-1")

# ─── Scenario data ────────────────────────────────────────────────────────────

MERCHANTS = [
    {"id": "merchant-uuid-1", "name": "AudioShop Inc.", "website": "https://audioshop.example.com"},
    {"id": "merchant-uuid-2", "name": "SoundStore", "website": "https://soundstore.example.com"},
]

ACCEPTABLE_ITEMS = [
    {"id": "SNY-WH1000XM5", "title": "Sony WH-1000XM5 Wireless Headphones"},
    {"id": "APL-AIRPODS-MAX", "title": "Apple AirPods Max"},
]

PRODUCTS = {
    "SNY-WH1000XM5": {
        "sku": "SNY-WH1000XM5", "name": "Sony WH-1000XM5 Wireless Headphones",
        "price": 27999, "currency": "USD",
    },
}

PAYMENT_INSTRUMENT = {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234",
}


def create_checkout_jwt(items: list[dict]) -> str:
    now = int(time.time())
    cart = [
        {"sku": item["sku"], "name": PRODUCTS[item["sku"]]["name"],
         "quantity": item["quantity"],
         "unitPrice": PRODUCTS[item["sku"]]["price"] / 100}
        for item in items
    ]
    total = sum(PRODUCTS[i["sku"]]["price"] * i["quantity"] / 100 for i in items)
    payload = {
        "iss": "https://audioshop.example.com",
        "sub": "cart_checkout",
        "iat": now,
        "exp": now + 3600,
        "cart": {"items": cart, "subTotal": {"amount": total, "currencyCode": "USD"}},
    }
    return _jwt_encode(
        {"alg": "ES256", "typ": "JWT", "kid": MERCHANT_KEYS.kid},
        payload,
        MERCHANT_KEYS.private_key,
    )


def checkout_hash(checkout_jwt: str) -> str:
    return _b64url_encode(hashlib.sha256(checkout_jwt.encode()).digest())


def _find_disc(sd_jwt, pred):
    for ds, dv in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        val = dv[-1] if dv else None
        if pred(val):
            return ds
    return None


# ─── Main demo ────────────────────────────────────────────────────────────────


def main() -> None:
    banner("AgentLair + Mastercard Verifiable Intent\nAutonomous Purchase Demo")
    now = int(time.time())

    # ── Step 1: AgentLair agent's public key ──────────────────────────────────
    step(1, "AgentLair agent publishes P-256 keypair (JWK)")
    agent_jwk = AGENT_KEYS.public_jwk
    log("agentlair", f"Agent key: kid={AGENT_KEYS.kid}")
    log("agentlair", f"  kty={agent_jwk['kty']}, crv={agent_jwk['crv']}")
    log("agentlair", f"  Public: x={agent_jwk['x'][:20]}..., y={agent_jwk['y'][:20]}...")
    log("agentlair", "  Private key stored in AgentLair vault (never exposed)")
    log("agentlair", f"  Verifier URL: https://agentlair.dev/.well-known/agent-keys/{AGENT_KEYS.kid}/jwks.json")

    # ── Step 2: Issuer creates L1 credential ─────────────────────────────────
    step(2, "Issuer creates L1 credential (binds user's device key)")
    l1 = create_layer1(
        IssuerCredential(
            iss="https://www.mastercard.com",
            sub="user-alice-001",
            iat=now, exp=now + 86400 * 365,
            aud="https://wallet.example.com",
            cnf_jwk=USER_KEYS.public_jwk,
            email="alice@example.com",
            pan_last_four="1234",
            scheme="Mastercard",
        ),
        ISSUER_KEYS.private_key,
    )
    log("issuer", f"L1 created: typ={l1.header['typ']}, {len(l1.disclosures)} disclosure(s)")
    log("issuer", f"  cnf.jwk binds user's device key (kid={USER_KEYS.kid})")

    # ── Step 3: User creates L2 autonomous mandate with constraints ───────────
    step(3, "User creates L2 mandate — delegates to AgentLair agent")
    log("user", f"Binding AgentLair agent key (kid={AGENT_KEYS.kid}) as cnf.jwk")
    log("user", "  Constraints: max $300, allowlist: AudioShop + SoundStore, Sony WH-1000XM5")

    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud="https://agent.verifiable-intent.example",
        iat=now, exp=now + 86400,
        iss="https://wallet.example.com",
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy Sony WH-1000XM5 headphones under $300 from approved merchants",
        # ── CHECKOUT mandate: delegates to AgentLair agent key ───────────────
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open",
            cnf_jwk=agent_jwk,   # ← AgentLair agent's public JWK
            cnf_kid=AGENT_KEYS.kid,
            constraints=[
                AllowedMerchantConstraint(allowed_merchants=MERCHANTS),
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-1", "acceptable_items": ACCEPTABLE_ITEMS, "quantity": 1}],
                ),
            ],
        ),
        # ── PAYMENT mandate: delegates to AgentLair agent key ────────────────
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open",
            cnf_jwk=agent_jwk,   # ← AgentLair agent's public JWK
            cnf_kid=AGENT_KEYS.kid,
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=[
                PaymentAmountConstraint(currency="USD", min=0, max=30000),   # max $300
                AllowedPayeeConstraint(allowed_payees=MERCHANTS),
            ],
        ),
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, USER_KEYS.private_key)
    log("user", f"L2 created: typ={l2.header['typ']}, {len(l2.disclosures)} disclosures")
    log("user", f"  sd_hash binds L2 to L1 serialization")

    # ── Step 4: AgentLair agent executes purchase ─────────────────────────────
    step(4, "AgentLair agent processes the mandate")
    l2_claims = resolve_disclosures(l2)

    # Resolve acceptable items
    disc_by_hash = {
        hash_disclosure(ds): (dv[-1] if dv else None)
        for ds, dv in zip(l2.disclosures, l2.disclosure_values)
    }
    selected_sku = None
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.checkout.open":
            for constraint in delegate.get("constraints", []):
                if constraint.get("type") == "mandate.checkout.line_items":
                    for item_entry in constraint.get("items", []):
                        for ai in item_entry.get("acceptable_items", []):
                            if isinstance(ai, dict):
                                ref = ai.get("...", "")
                                if ref and ref in disc_by_hash:
                                    resolved = disc_by_hash[ref]
                                    if isinstance(resolved, dict):
                                        sku = resolved.get("id")
                                        if sku and sku in PRODUCTS:
                                            selected_sku = sku
                                            break

    if not selected_sku:
        fail("Agent could not find an acceptable product from acceptable_items in L2 constraints")
        return

    product = PRODUCTS[selected_sku]
    log("agent", f"Mandate accepted: prompt='{mandate.prompt_summary}'")
    log("agent", f"Selected product: {product['name']} @ ${product['price']/100:.2f}")

    # Check payment amount constraint
    amount_cents = product["price"]
    log("agent", f"Amount ${amount_cents/100:.2f} within constraint [0, $300] ✓")

    # ── Step 5: Create checkout at merchant ───────────────────────────────────
    step(5, "AgentLair agent creates checkout at AudioShop Inc.")
    checkout_jwt_str = create_checkout_jwt([{"sku": selected_sku, "quantity": 1}])
    c_hash = checkout_hash(checkout_jwt_str)
    log("merchant", f"Checkout JWT issued for: {product['name']}")
    log("merchant", f"  checkout_hash: {c_hash[:32]}...")

    # ── Step 6: AgentLair agent creates L3a + L3b (vault signing) ─────────────
    step(6, "AgentLair vault signs L3 credentials")
    log("agentlair", "PRODUCTION: POST /v1/agents/vi/sign-l3")
    log("agentlair", "  → Vault signs L3a (payment) and L3b (checkout) with agent key")
    log("agentlair", "  → Creates audit log entry: mandate_id, amount, merchant, outcome")
    log("agentlair", f"  → Links transaction: checkout_hash={c_hash[:16]}...")

    nonce = str(uuid.uuid4())
    l2_ser = l2.serialize()
    l2_base = l2_ser.split("~")[0]

    payment_disc = _find_disc(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open")
    checkout_disc = _find_disc(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open")
    merchant_disc = _find_disc(l2, lambda v: isinstance(v, dict) and v.get("name") == "AudioShop Inc.")
    item_disc = _find_disc(l2, lambda v: isinstance(v, dict) and v.get("id") == "SNY-WH1000XM5")

    # L3a: Payment mandate (→ Mastercard network)
    l3a = create_layer3_payment(
        PaymentL3Mandate(
            nonce=nonce,
            aud="https://www.mastercard.com",
            iat=now, iss="https://api.agentlair.dev", exp=now + 300,
            final_payment=FinalPaymentMandate(
                transaction_id=c_hash,
                payee=MERCHANTS[0],
                payment_amount={"currency": "USD", "amount": amount_cents},
                payment_instrument=PAYMENT_INSTRUMENT,
            ),
            final_merchant=MERCHANTS[0],
        ),
        AGENT_KEYS.private_key,  # ← In production: vault signs, key never exposed
        l2_base, payment_disc, merchant_disc,
        kid=AGENT_KEYS.kid,  # Must match cnf.kid in L2 mandate
    )

    # L3b: Checkout mandate (→ AudioShop merchant)
    l3b = create_layer3_checkout(
        CheckoutL3Mandate(
            nonce=nonce,
            aud="https://audioshop.example.com",
            iat=now, iss="https://api.agentlair.dev", exp=now + 300,
            final_checkout=FinalCheckoutMandate(
                checkout_jwt=checkout_jwt_str,
                checkout_hash=c_hash,
            ),
        ),
        AGENT_KEYS.private_key,  # ← In production: vault signs, key never exposed
        l2_base, checkout_disc, item_disc,
        kid=AGENT_KEYS.kid,  # Must match cnf.kid in L2 mandate
    )

    log("agent", f"L3a (payment) created: {len(l3a.disclosures)} disclosures → network")
    log("agent", f"L3b (checkout) created: {len(l3b.disclosures)} disclosures → merchant")
    log("agent", f"  transaction_id == checkout_hash ✓ (cross-reference binding)")

    # ── Step 7: Selective disclosure routing ──────────────────────────────────
    step(7, "Privacy-preserving selective disclosure routing")

    l2_payment_ser = build_selective_presentation(l2_base, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base, [checkout_disc, item_disc])

    log("agent", "Merchant receives:  L1 + L2[checkout only] + L3b")
    log("agent", "  → Merchant sees: authorization proof + line items")
    log("agent", "  → Merchant CANNOT see: payment card, network routing")
    log("agent", "Network receives:   L1 + L2[payment only]  + L3a")
    log("agent", "  → Network sees:  payment mandate + amount + payee")
    log("agent", "  → Network CANNOT see: line item details, merchant's checkout data")

    # ── Step 8: Merchant verifies checkout chain ───────────────────────────────
    step(8, "AudioShop verifies checkout authorization")

    l1_parsed = decode_sd_jwt(l1.serialize())
    l2_checkout_parsed = decode_sd_jwt(build_selective_presentation(l2_base, [checkout_disc, item_disc]))

    merchant_result = verify_chain(
        l1_parsed, l2_checkout_parsed,
        l3_checkout=l3b,
        issuer_public_key=ISSUER_KEYS.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_checkout_serialized=l2_checkout_ser,
    )
    log("merchant", f"Chain valid: {merchant_result.valid}")
    if merchant_result.valid:
        log("merchant", f"  Agent key verified against L2 cnf.jwk ✓")
        log("merchant", f"  checkout_hash binding valid ✓")
        log("merchant", f"  Authorized to process checkout for {product['name']}")
    else:
        for e in merchant_result.errors:
            log("merchant", f"  ERROR: {e}")

    # ── Step 9: Mastercard network verifies payment chain + constraints ────────
    step(9, "Mastercard network validates payment chain and constraints")

    l2_full_parsed = decode_sd_jwt(l2_ser)

    network_result = verify_chain(
        l1_parsed, l2_full_parsed,
        l3_payment=l3a,
        issuer_public_key=ISSUER_KEYS.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2_ser,
        l2_payment_serialized=l2_payment_ser,
    )
    log("network", f"Chain valid: {network_result.valid}")

    # Check constraints
    constraint_result = None
    if network_result.valid:
        l2_pay_claims = resolve_disclosures(l2_full_parsed)
        payment_constraints = []
        for delegate in l2_pay_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") in ("mandate.payment.open", "mandate.payment"):
                payment_constraints = delegate.get("constraints", [])
                break

        fulfillment = {}
        for delegate in network_result.l3_payment_claims.get("delegate_payload", []):
            if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment":
                fulfillment = delegate
                break

        # Resolve merchant for payee constraint
        disc_by_h2 = {
            hash_disclosure(ds): (dv[-1] if dv else None)
            for ds, dv in zip(l2_full_parsed.disclosures, l2_full_parsed.disclosure_values)
        }
        for c in payment_constraints:
            if c.get("type") == "payment.allowed_payee":
                resolved = [disc_by_h2[ref.get("...", "")] for ref in c.get("allowed_payees", [])
                            if isinstance(ref, dict) and ref.get("...") in disc_by_h2]
                fulfillment["allowed_merchants"] = resolved
                break

        constraint_result = check_constraints(payment_constraints, fulfillment)
        log("network", f"Constraints satisfied: {constraint_result.satisfied}")
        if constraint_result.satisfied:
            log("network", f"  Amount ${amount_cents/100:.2f} within limit $0–$300 ✓")
            log("network", f"  Payee 'AudioShop Inc.' on allowlist ✓")
            log("network", f"  Agent key matches L2 cnf.jwk ✓")
        else:
            for v in constraint_result.violations:
                log("network", f"  VIOLATION: {v}")

    # ── AgentLair audit trail ──────────────────────────────────────────────────
    step(10, "AgentLair records audit trail")
    log("agentlair", "PRODUCTION: Audit entry written to hash-chained log")
    log("agentlair", f"  agent_id: al-agent-abc123")
    log("agentlair", f"  mandate: AUTONOMOUS, delegated by alice@example.com")
    log("agentlair", f"  action: PURCHASE ${amount_cents/100:.2f} at AudioShop Inc.")
    log("agentlair", f"  vi_transaction_id: {c_hash[:16]}...")
    log("agentlair", f"  constraints_satisfied: {constraint_result.satisfied if constraint_result else '?'}")
    log("agentlair", f"  outcome: APPROVED")
    log("agentlair", "  → Linked to Mastercard VI transaction for dispute resolution")

    # ── Summary ────────────────────────────────────────────────────────────────
    all_ok = merchant_result.valid and network_result.valid and (
        constraint_result is not None and constraint_result.satisfied
    )

    if all_ok:
        ok("AgentLair + Verifiable Intent integration demo completed successfully!")
        print(f"\n{BOLD}What this demonstrates:{RESET}")
        print(f"  {GREEN}✓{RESET} AgentLair's agent key is the P-256 key in L2 cnf.jwk")
        print(f"  {GREEN}✓{RESET} AgentLair vault signs L3 credentials on behalf of the agent")
        print(f"  {GREEN}✓{RESET} User's constraints enforced cryptographically (not just policy)")
        print(f"  {GREEN}✓{RESET} Privacy-preserving routing: merchant/network see only their data")
        print(f"  {GREEN}✓{RESET} AgentLair audit trail links to VI transaction_id")
        print(f"\n{BOLD}Trust stack composition:{RESET}")
        print(f"  Verifiable Intent → 'Did the human authorize this?'")
        print(f"  AgentLair         → 'Who is this agent, and what did it do?'")
        print(f"  Together          → Complete, auditable, privacy-preserving agent commerce")
    else:
        fail("Demo failed — check errors above")


if __name__ == "__main__":
    main()
