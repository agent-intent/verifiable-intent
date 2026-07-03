"""Layer 2: User mandate creation for both Immediate and Autonomous modes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.disclosure import (
    _b64url_encode,
    create_delegate_ref,
    create_disclosure,
    hash_disclosure,
)
from ..crypto.sd_jwt import SdJwt, create_sd_jwt
from ..models.constraints import ReferenceConstraint
from ..models.user_mandate import MandateMode, UserMandate


@dataclass
class ImmediateL2Result:
    """Result of Layer 2 creation in Immediate mode.

    In Immediate mode, the user signs final values directly — there is no
    KB-JWT (no agent delegation). This wrapper provides the SD-JWT and a
    serialize() convenience method.
    """

    sd_jwt: SdJwt

    def serialize(self) -> str:
        return self.sd_jwt.serialize()


def create_layer2_immediate(
    mandate: UserMandate,
    user_private_key: ec.EllipticCurvePrivateKey,
    kid: str = "user-device-key-1",
) -> ImmediateL2Result:
    """Create Layer 2 KB-SD-JWT for Immediate mode.

    Mandates contain final values, no agent delegation (no cnf in mandates).
    Selectively disclosable: final_checkout, final_payment.
    """
    if mandate.mode != MandateMode.IMMEDIATE:
        actual = mandate.mode.value if isinstance(mandate.mode, MandateMode) else str(mandate.mode)
        raise ValueError(f"create_layer2_immediate() requires mode=IMMEDIATE, got {actual}")

    disclosures = []

    # Auto-compute checkout_hash and transaction_id BEFORE disclosure serialization
    if mandate.checkout_mandate and mandate.checkout_mandate.checkout_jwt:
        jwt_bytes = mandate.checkout_mandate.checkout_jwt.encode("ascii")
        computed_hash = _b64url_encode(hashlib.sha256(jwt_bytes).digest())
        if not mandate.checkout_mandate.checkout_hash:
            mandate.checkout_mandate.checkout_hash = computed_hash
        if mandate.payment_mandate and not mandate.payment_mandate.transaction_id:
            mandate.payment_mandate.transaction_id = computed_hash

    # final_checkout mandate disclosure (after auto-compute so checkout_hash is included)
    checkout_disc = None
    if mandate.checkout_mandate:
        checkout_dict = mandate.checkout_mandate.to_dict()
        checkout_disc = create_disclosure(None, checkout_dict)
        disclosures.append(checkout_disc)

    if mandate.payment_mandate:
        d = create_disclosure(None, mandate.payment_mandate.to_dict())
        disclosures.append(d)

    # Build delegate_payload with references to mandate disclosures
    delegate_payload = []
    for disc in disclosures:
        delegate_payload.append(create_delegate_ref(hash_disclosure(disc)))

    payload = {
        "nonce": mandate.nonce,
        "aud": mandate.aud,
        "iat": mandate.iat,
        "sd_hash": mandate.sd_hash,
        "delegate_payload": delegate_payload,
        "_sd_alg": "sha-256",
    }
    if mandate.iss is not None:
        payload["iss"] = mandate.iss
    if mandate.exp is not None:
        payload["exp"] = mandate.exp

    # Add all disclosure hashes to _sd array
    sd_hashes = [hash_disclosure(d) for d in disclosures]
    if sd_hashes:
        payload["_sd"] = sd_hashes

    header = {
        "alg": "ES256",
        "typ": "kb-sd-jwt",
        "kid": kid,
    }

    sd_jwt = create_sd_jwt(header, payload, disclosures, user_private_key)

    return ImmediateL2Result(sd_jwt=sd_jwt)


def create_layer2_autonomous(
    mandate: UserMandate,
    user_private_key: ec.EllipticCurvePrivateKey,
    kid: str = "user-device-key-1",
) -> SdJwt:
    """Create Layer 2 KB-SD-JWT for Autonomous mode.

    V2 structure with nested selective disclosure:
    - Standalone merchant disclosures (referenced by hash in constraints)
    - Standalone acceptable item disclosures (referenced by hash in constraints)
    - open_checkout mandate disclosure (with constraint refs)
    - open_payment mandate disclosure (with constraint refs + payment_instrument)
    """
    if mandate.mode != MandateMode.AUTONOMOUS:
        actual = mandate.mode.value if isinstance(mandate.mode, MandateMode) else str(mandate.mode)
        raise ValueError(f"create_layer2_autonomous() requires mode=AUTONOMOUS, got {actual}")

    disclosures = []

    # 1. Create standalone merchant disclosures
    merchant_disc_hashes = []
    for merchant in mandate.merchants:
        d = create_disclosure(None, merchant)
        disclosures.append(d)
        merchant_disc_hashes.append(hash_disclosure(d))

    # 2. Create standalone acceptable item disclosures
    item_disc_hashes = []
    for item in mandate.acceptable_items:
        d = create_disclosure(None, item)
        disclosures.append(d)
        item_disc_hashes.append(hash_disclosure(d))

    # 3. Build open_checkout mandate disclosure
    checkout_disc = None
    if mandate.checkout_mandate:
        checkout_dict = mandate.checkout_mandate.to_dict()

        # Replace merchant/item refs in constraints — scoped to constraint's subset
        for c in checkout_dict.get("constraints", []):
            if c.get("type") == "mandate.checkout.allowed_merchants":
                original_merchants = c.get("allowed", [])
                c["allowed"] = _match_merchant_refs(original_merchants, mandate.merchants, merchant_disc_hashes)
            elif c.get("type") == "mandate.checkout.line_items":
                for item_entry in c.get("items", []):
                    original_items = item_entry.get("acceptable_items", [])
                    item_entry["acceptable_items"] = _match_item_refs(
                        original_items, mandate.acceptable_items, item_disc_hashes
                    )

        checkout_disc = create_disclosure(None, checkout_dict)
        disclosures.append(checkout_disc)

    # 4. Build open_payment mandate disclosure
    payment_disc = None
    if mandate.payment_mandate:
        payment_dict = mandate.payment_mandate.to_dict()

        # Replace payee refs in allowed_payees constraint — scoped to constraint's subset
        for c in payment_dict.get("constraints", []):
            if c.get("type") == "mandate.payment.allowed_payees":
                original_allowed = c.get("allowed", [])
                c["allowed"] = _match_merchant_refs(original_allowed, mandate.merchants, merchant_disc_hashes)

        # Inject mandate.payment.reference constraint binding checkout ↔ payment
        if checkout_disc is not None:
            checkout_disc_hash = hash_disclosure(checkout_disc)
            ref_constraint = ReferenceConstraint(
                conditional_transaction_id=checkout_disc_hash,
            )
            if "constraints" not in payment_dict:
                payment_dict["constraints"] = []
            payment_dict["constraints"].append(ref_constraint.to_dict())

        payment_disc = create_disclosure(None, payment_dict)
        disclosures.append(payment_disc)

    # 5. Build delegate_payload with references to mandate disclosures
    delegate_payload = []
    if checkout_disc:
        delegate_payload.append(create_delegate_ref(hash_disclosure(checkout_disc)))
    if payment_disc:
        delegate_payload.append(create_delegate_ref(hash_disclosure(payment_disc)))

    # Add all disclosure hashes to _sd array
    sd_hashes = [hash_disclosure(d) for d in disclosures]

    payload = {
        "nonce": mandate.nonce,
        "aud": mandate.aud,
        "iat": mandate.iat,
        "sd_hash": mandate.sd_hash,
        "delegate_payload": delegate_payload,
        "_sd_alg": "sha-256",
    }
    if sd_hashes:
        payload["_sd"] = sd_hashes
    if mandate.iss is not None:
        payload["iss"] = mandate.iss
    if mandate.exp is not None:
        payload["exp"] = mandate.exp

    header = {
        "alg": "ES256",
        "typ": "kb-sd-jwt+kb",
        "kid": kid,
    }

    return create_sd_jwt(header, payload, disclosures, user_private_key)


def _match_merchant_refs(
    original_merchants: list[dict],
    mandate_merchants: list[dict],
    disc_hashes: list[str],
) -> list[dict]:
    """Match constraint's merchant list against mandate merchants, return scoped SD refs.

    If original_merchants is empty, returns empty list (fail-closed at verification).
    Raises ValueError if a constraint merchant has no match in the mandate.
    """
    if not original_merchants:
        return []
    matched = []
    for orig in original_merchants:
        orig_id = orig.get("id")
        orig_name = orig.get("name")
        if not orig_id and not orig_name:
            raise ValueError(f"Constraint merchant missing both 'id' and 'name': {orig}")
        found = False
        for idx, m in enumerate(mandate_merchants):
            # Match by id if both have it, else by name
            m_id = m.get("id")
            if orig_id and m_id:
                match = m_id == orig_id
            else:
                match = m.get("name") == orig_name and bool(orig_name)
            if match:
                matched.append(create_delegate_ref(disc_hashes[idx]))
                found = True
                break
        if not found:
            raise ValueError(f"Constraint references unknown merchant: {orig_id or orig_name}")
    return matched


def _match_item_refs(
    original_items: list[dict],
    mandate_items: list[dict],
    disc_hashes: list[str],
) -> list[dict]:
    """Match constraint's item list against mandate items, return scoped SD refs.

    If original_items is empty, returns empty list (any SKU allowed per spec).
    Raises ValueError if a constraint item has no match in the mandate.
    """
    if not original_items:
        return []
    matched = []
    for orig in original_items:
        if not isinstance(orig, dict):
            raise ValueError(f"Constraint item must be an object: {orig!r}")
        orig_keys = {k for k in (orig.get("id"), orig.get("sku")) if k}
        found = False
        for idx, item in enumerate(mandate_items):
            if not isinstance(item, dict):
                continue
            item_keys = {k for k in (item.get("id"), item.get("sku")) if k}
            if orig_keys and orig_keys & item_keys:
                matched.append(create_delegate_ref(disc_hashes[idx]))
                found = True
                break
        if not found:
            raise ValueError(f"Constraint references unknown item: {orig.get('id') or orig.get('sku') or orig}")
    return matched
