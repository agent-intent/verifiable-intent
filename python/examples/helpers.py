"""Shared utilities for VI examples: keys, catalog, display, selective routing."""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure the in-repo SDK is importable even without an editable install.
# Running `python examples/foo.py` from the repo root sets cwd but not
# src/ on sys.path — this fixes that so examples work out of the box.
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import hashlib
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from verifiable_intent.crypto.disclosure import _b64url_encode
from verifiable_intent.crypto.sd_jwt import SdJwt
from verifiable_intent.crypto.signing import (
    _jwt_encode,
    private_key_to_jwk,
    public_key_to_jwk,
)

# ---------------------------------------------------------------------------
# Deterministic demo keys
# ---------------------------------------------------------------------------


@dataclass
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_jwk: dict
    private_jwk: dict
    kid: str

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()


def _key_from_d(d_int: int, kid: str) -> KeyPair:
    """Create a deterministic key pair from a known private value."""
    priv_key = ec.derive_private_key(d_int, ec.SECP256R1())
    return KeyPair(
        private_key=priv_key,
        public_jwk=public_key_to_jwk(priv_key),
        private_jwk=private_key_to_jwk(priv_key),
        kid=kid,
    )


# Fixed private key values — NOT secret, demo/test keys only.
_ISSUER_D = 0x1A2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01
_USER_D = 0x2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF0102
_AGENT_D = 0x3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF010203
_MERCHANT_D = 0x4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01020304

_issuer_keys: KeyPair | None = None
_user_keys: KeyPair | None = None
_agent_keys: KeyPair | None = None
_merchant_keys: KeyPair | None = None


def get_issuer_keys() -> KeyPair:
    global _issuer_keys
    if _issuer_keys is None:
        _issuer_keys = _key_from_d(_ISSUER_D, "mastercard-issuer-key-1")
    return _issuer_keys


def get_user_keys() -> KeyPair:
    global _user_keys
    if _user_keys is None:
        _user_keys = _key_from_d(_USER_D, "user-device-key-1")
    return _user_keys


def get_agent_keys() -> KeyPair:
    global _agent_keys
    if _agent_keys is None:
        _agent_keys = _key_from_d(_AGENT_D, "agent-key-1")
    return _agent_keys


def get_merchant_keys() -> KeyPair:
    global _merchant_keys
    if _merchant_keys is None:
        _merchant_keys = _key_from_d(_MERCHANT_D, "merchant-key-1")
    return _merchant_keys


# ---------------------------------------------------------------------------
# V2 Scenario: Tennis purchase
# Budget: $100-$400, 1 item (Babolat Pure Aero racket)
# ---------------------------------------------------------------------------

MERCHANTS = [
    {
        "id": "merchant-uuid-1",
        "name": "Tennis Warehouse",
        "website": "https://tennis-warehouse.com",
    },
    {
        "id": "merchant-uuid-2",
        "name": "Babolat",
        "website": "https://babolat.com",
    },
]

ACCEPTABLE_ITEMS = [
    {
        "id": "BAB86345",
        "title": "Babolat Pure Aero Tennis Racket",
    },
    {
        "id": "HEA23102",
        "title": "Head Graphene 360 Speed",
    },
]

PRODUCTS = [
    {
        "sku": "BAB86345",
        "name": "Babolat Pure Aero Tennis Racket",
        "price": 27999,  # cents
        "currency": "USD",
        "brand": "Babolat",
        "model": "Pure Aero",
        "color": "white",
        "size": 3,
        "size_label": "4 3/8",
        "category": "racket",
    },
    {
        "sku": "HEA23102",
        "name": "Head Graphene 360 Speed Tennis Racket",
        "price": 24999,  # cents
        "currency": "USD",
        "brand": "HEAD",
        "model": "Speed Pro",
        "color": "black",
        "size": 3,
        "size_label": "4 3/8",
        "category": "racket",
    },
]

PAYMENT_INSTRUMENT = {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234",
}


def get_catalog() -> list[dict]:
    return PRODUCTS


def find_product(sku: str) -> dict | None:
    for p in PRODUCTS:
        if p["sku"] == sku:
            return p
    return None


# ---------------------------------------------------------------------------
# Merchant checkout JWT creation (signed by merchant)
# ---------------------------------------------------------------------------


def create_checkout_jwt(items: list[dict], merchant_keys: KeyPair) -> str:
    """Create a merchant-signed checkout JWT from line items.

    Returns the signed JWT string (not a dict wrapper).
    """
    now = int(time.time())
    cart_items = []
    total_cents = 0

    for item in items:
        product = find_product(item["sku"])
        if not product:
            raise ValueError(f"Product {item['sku']} not found")
        qty = item.get("quantity", 1)
        unit_price_cents = int(product["price"])
        line_total_cents = unit_price_cents * qty
        total_cents += line_total_cents
        cart_items.append(
            {
                "sku": product["sku"],
                "name": product["name"],
                "size": product.get("size"),
                "size_label": product.get("size_label", ""),
                "color": product.get("color", ""),
                "quantity": qty,
                "unitPrice": unit_price_cents / 100,  # display price in dollars
            }
        )

    checkout_payload = {
        "iss": "https://tennis-warehouse.com",
        "sub": "cart_checkout",
        "iat": now,
        "exp": now + 3600,
        "cart": {
            "items": cart_items,
            "subTotal": {
                "amount": total_cents / 100,
                "currencyCode": "USD",
            },
        },
    }
    header = {"alg": "ES256", "typ": "JWT", "kid": merchant_keys.kid}
    return _jwt_encode(header, checkout_payload, merchant_keys.private_key)


def checkout_hash_from_jwt(checkout_jwt: str) -> str:
    """Compute SHA-256 hash of a checkout JWT string (base64url-encoded)."""
    return _b64url_encode(hashlib.sha256(checkout_jwt.encode("utf-8")).digest())


# ---------------------------------------------------------------------------
# Selective disclosure routing (L2 level)
# ---------------------------------------------------------------------------


def build_role_presentations(l2: SdJwt, fallback_serialized: str) -> tuple[str, str]:
    """Split L2 into role-specific presentations.

    Merchant gets checkout mandate + item disclosures.
    Network gets payment mandate + merchant disclosures.

    Returns (l2_checkout_only, l2_payment_only) as serialized strings.
    """
    checkout_indices: list[int] = []
    payment_indices: list[int] = []

    for idx, disc_val in enumerate(l2.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if not isinstance(value, dict):
            continue

        vct = value.get("vct")
        if vct == "mandate.checkout.open.1":
            checkout_indices.append(idx)
        elif vct == "mandate.payment.open.1":
            payment_indices.append(idx)
        elif "name" in value and "website" in value:
            # Merchant entry — network needs for payee validation
            payment_indices.append(idx)
        elif "id" in value and "title" in value:
            # Acceptable item — merchant needs for checkout validation
            checkout_indices.append(idx)

    if not checkout_indices:
        raise ValueError(
            "No checkout mandate disclosures found in L2 — cannot build merchant presentation. "
            "Refusing to fall back to full L2 (would leak payment data to merchant)."
        )
    if not payment_indices:
        raise ValueError(
            "No payment mandate disclosures found in L2 — cannot build network presentation. "
            "Refusing to fall back to full L2 (would leak checkout data to network)."
        )

    l2_checkout_only = l2.serialize(include_disclosures=checkout_indices)
    l2_payment_only = l2.serialize(include_disclosures=payment_indices)
    return l2_checkout_only, l2_payment_only


# ---------------------------------------------------------------------------
# Network-side validation pipeline
# ---------------------------------------------------------------------------


def validate_intent(
    l1_serialized: str,
    l2_serialized: str,
    l3_payment_serialized: str | None,
    issuer_public_key,
) -> dict:
    """Validate the full VI chain (network side, receives L3a payment).

    This is the network-side orchestration logic: chain verification,
    mode detection, constraint enforcement, and checkout/payment binding.

    Returns dict with valid, order_id, assurance_data, errors.
    """
    from verifiable_intent.crypto.disclosure import hash_disclosure
    from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
    from verifiable_intent.verification.chain import verify_chain
    from verifiable_intent.verification.constraint_checker import StrictnessMode, check_constraints

    l1 = decode_sd_jwt(l1_serialized)
    l2 = decode_sd_jwt(l2_serialized)
    l3_payment = decode_sd_jwt(l3_payment_serialized) if l3_payment_serialized else None

    result = verify_chain(
        l1,
        l2,
        l3_payment=l3_payment,
        issuer_public_key=issuer_public_key,
        l1_serialized=l1_serialized,
        l2_serialized=l2_serialized,
    )

    if not result.valid:
        return {"valid": False, "order_id": "", "assurance_data": {}, "errors": result.errors}

    l2_claims = result.l2_claims
    l3_claims = result.l3_payment_claims

    # Detect autonomous mode: mandates with cnf indicate agent delegation
    autonomous_mode = any(isinstance(d, dict) and d.get("cnf") for d in l2_claims.get("delegate_payload", []))

    if autonomous_mode and not l3_payment_serialized:
        return {
            "valid": False,
            "order_id": "",
            "assurance_data": {},
            "errors": ["Autonomous intent requires Layer 3 fulfillment"],
        }

    # Network requires L2 payment mandate disclosure
    if l3_payment_serialized and not result.l2_payment_disclosed:
        return {
            "valid": False,
            "order_id": "",
            "assurance_data": {},
            "errors": ["Network verification requires L2 payment mandate disclosure"],
        }

    # Extract payment constraints from L2 (v2 VCTs)
    payment_constraints = []
    for delegate in l2_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("vct") in (
            "mandate.payment.open.1",
            "mandate.payment.1",
        ):
            payment_constraints = delegate.get("constraints", [])
            break

    # Extract fulfillment from L3a payment claims
    fulfillment = {}
    for delegate in l3_claims.get("delegate_payload", []):
        if isinstance(delegate, dict) and delegate.get("vct") == "mandate.payment.1":
            fulfillment = delegate
            break

    if autonomous_mode and not payment_constraints:
        return {
            "valid": False,
            "order_id": "",
            "assurance_data": {},
            "errors": ["Missing disclosed Layer 2 payment mandate"],
        }

    if l3_payment_serialized and payment_constraints and not fulfillment:
        return {
            "valid": False,
            "order_id": "",
            "assurance_data": {},
            "errors": ["Missing disclosed Layer 3 payment mandate"],
        }

    # Resolve merchant disclosures for payee constraint
    if payment_constraints and fulfillment:
        disc_by_hash = {}
        for disc_str, disc_val in zip(l2.disclosures, l2.disclosure_values):
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

        # Payment networks SHOULD enforce STRICT mode — unknown constraints are violations, not skips
        constraint_result = check_constraints(payment_constraints, fulfillment, mode=StrictnessMode.STRICT)
        if not constraint_result.satisfied:
            return {"valid": False, "order_id": "", "assurance_data": {}, "errors": constraint_result.violations}

    order_id = f"VI-{uuid.uuid4().hex[:12].upper()}"
    return {
        "valid": True,
        "order_id": order_id,
        "assurance_data": {"chain_valid": True, "constraints_checked": True},
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Display utilities
# ---------------------------------------------------------------------------

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

ROLE_COLORS = {
    "issuer": BLUE,
    "user": GREEN,
    "merchant": YELLOW,
    "network": MAGENTA,
    "agent": CYAN,
}


def banner(title: str):
    width = 60
    print(f"\n{BOLD}{'=' * width}{RESET}")
    print(f"{BOLD}{title:^{width}}{RESET}")
    print(f"{BOLD}{'=' * width}{RESET}\n")


def step(num: int, description: str):
    print(f"\n{BOLD}Step {num}: {description}{RESET}")
    print(f"{DIM}{'-' * 50}{RESET}")


def role_log(role: str, message: str):
    color = ROLE_COLORS.get(role, "")
    label = f"[{role.upper():^10}]"
    print(f"  {color}{label}{RESET} {message}")


def visible(field: str, value: str = ""):
    print(f"    {GREEN}✓{RESET} {field}: {value}")


def redacted(field: str):
    print(f"    {RED}✗{RESET} {field}: {RED}[REDACTED]{RESET}")


def success(message: str):
    print(f"\n{GREEN}{BOLD}✓ {message}{RESET}")


def error(message: str):
    print(f"\n{RED}{BOLD}✗ {message}{RESET}")


def print_sd_jwt(role: str, label: str, serialized: str):
    """Print a serialized SD-JWT with component breakdown."""
    parts = serialized.split("~")
    # Format: <issuer-jwt>~<d1>~...~<dN>~<kb-jwt-or-empty>
    # Disclosures are the middle segments; last segment is KB-JWT (or empty string if trailing ~)
    disclosures = parts[1:-1]
    n_disc = len(disclosures)
    role_log(role, f"{label} ({n_disc} disclosures):")
    print(f"    {DIM}{serialized}{RESET}")


def result_box(label: str, data: dict):
    print(f"\n{BOLD}Result: {label}{RESET}")
    for k, v in data.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for k2, v2 in v.items():
                print(f"    {k2}: {v2}")
        elif isinstance(v, list):
            print(f"  {k}: [{len(v)} items]")
        else:
            print(f"  {k}: {v}")
