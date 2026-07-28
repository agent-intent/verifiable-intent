"""Layer 1: Issuer credential creation."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.disclosure import create_disclosure, create_sd_array
from ..crypto.sd_jwt import SdJwt, create_sd_jwt
from ..models.issuer_credential import IssuerCredential


def create_layer1(
    credential: IssuerCredential,
    issuer_private_key: ec.EllipticCurvePrivateKey,
    kid: str = "mastercard-issuer-key-1",
) -> SdJwt:
    """Create a Layer 1 Issuer SD-JWT.

    1 selectively disclosable claim (email only).
    Always visible: iss, sub, iat, exp, vct, cnf, pan_last_four, scheme.
    """
    disclosures = []

    # Create disclosure for email only (1 disclosure)
    if credential.email is not None:
        d = create_disclosure("email", credential.email)
        disclosures.append(d)

    payload = credential.to_payload()
    payload["_sd"] = create_sd_array(disclosures)
    payload["_sd_alg"] = "sha-256"

    header = {
        "alg": "ES256",
        "typ": "sd+jwt",
        "kid": kid,
    }

    return create_sd_jwt(header, payload, disclosures, issuer_private_key)
