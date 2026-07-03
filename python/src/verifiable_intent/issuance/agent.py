"""Layer 3: Agent mandate creation (autonomous mode only).

V2 splits L3 into two separate credentials:
  create_layer3_payment() → L3a for payment network
  create_layer3_checkout() → L3b for merchant
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.disclosure import (
    build_selective_presentation,
    create_delegate_ref,
    create_disclosure,
    hash_bytes,
    hash_disclosure,
)
from ..crypto.sd_jwt import SdJwt, create_sd_jwt
from ..models.agent_mandate import CheckoutL3Mandate, PaymentL3Mandate


def create_layer3_payment(
    mandate: PaymentL3Mandate,
    agent_private_key: ec.EllipticCurvePrivateKey,
    l2_base_jwt: str,
    payment_disclosure_b64: str,
    merchant_disclosure_b64: str,
    kid: str = "agent-key-1",
) -> SdJwt:
    """Create L3a: payment mandate for network.

    Contains final payment values. sd_hash binds to the L2 presentation
    as seen by the network (L2 base JWT + payment disclosure + merchant disclosure).
    """
    disclosures = []

    # final_merchant disclosure (standalone, selectively disclosable)
    merchant_disc = None
    if mandate.final_merchant:
        merchant_disc = create_disclosure(None, mandate.final_merchant)
        disclosures.append(merchant_disc)

    # final_payment disclosure
    payment_disc = None
    if mandate.final_payment:
        payment_disc = create_disclosure(None, mandate.final_payment.to_dict())
        disclosures.append(payment_disc)

    # Build delegate_payload references
    delegate_payload = []
    for d in disclosures:
        delegate_payload.append(create_delegate_ref(hash_disclosure(d)))

    # Compute selective sd_hash: L2 base JWT + payment + merchant disclosures
    selective_presentation = build_selective_presentation(
        l2_base_jwt, [payment_disclosure_b64, merchant_disclosure_b64]
    )
    sd_hash = hash_bytes(selective_presentation.encode("ascii"))

    payload = {
        "nonce": mandate.nonce,
        "aud": mandate.aud,
        "sd_hash": sd_hash,
        "iat": mandate.iat,
        "delegate_payload": delegate_payload,
        "_sd_alg": "sha-256",
    }
    if mandate.iss is not None:
        payload["iss"] = mandate.iss
    if mandate.exp is not None:
        payload["exp"] = mandate.exp

    header = {
        "alg": "ES256",
        "typ": "kb-sd-jwt",
        "kid": kid,
    }

    return create_sd_jwt(header, payload, disclosures, agent_private_key)


def create_layer3_checkout(
    mandate: CheckoutL3Mandate,
    agent_private_key: ec.EllipticCurvePrivateKey,
    l2_base_jwt: str,
    checkout_disclosure_b64: str,
    item_disclosure_b64: str,
    kid: str = "agent-key-1",
) -> SdJwt:
    """Create L3b: checkout mandate for merchant.

    Contains merchant-signed checkout JWT. sd_hash binds to the L2 presentation
    as seen by the merchant (L2 base JWT + checkout disclosure + item disclosure).
    """
    disclosures = []

    # final_checkout disclosure
    checkout_disc = None
    if mandate.final_checkout:
        checkout_disc = create_disclosure(None, mandate.final_checkout.to_dict())
        disclosures.append(checkout_disc)

    # Build delegate_payload references
    delegate_payload = []
    for d in disclosures:
        delegate_payload.append(create_delegate_ref(hash_disclosure(d)))

    # Compute selective sd_hash: L2 base JWT + checkout + item disclosures
    selective_presentation = build_selective_presentation(l2_base_jwt, [checkout_disclosure_b64, item_disclosure_b64])
    sd_hash = hash_bytes(selective_presentation.encode("ascii"))

    payload = {
        "nonce": mandate.nonce,
        "aud": mandate.aud,
        "sd_hash": sd_hash,
        "iat": mandate.iat,
        "delegate_payload": delegate_payload,
        "_sd_alg": "sha-256",
    }
    if mandate.iss is not None:
        payload["iss"] = mandate.iss
    if mandate.exp is not None:
        payload["exp"] = mandate.exp

    header = {
        "alg": "ES256",
        "typ": "kb-sd-jwt",
        "kid": kid,
    }

    return create_sd_jwt(header, payload, disclosures, agent_private_key)
