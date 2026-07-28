"""Key-Bound SD-JWT (KB-SD-JWT) operations."""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from .disclosure import hash_bytes
from .sd_jwt import SdJwt
from .signing import _b64url_encode, _jwt_decode_parts, _jwt_encode, es256_verify


@dataclass
class KbSdJwt:
    """Key-Bound SD-JWT: the holder binding proof appended to an SD-JWT."""

    header: dict
    payload: dict
    signature: bytes

    @property
    def jwt(self) -> str:
        h = _b64url_encode(json.dumps(self.header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(self.payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{_b64url_encode(self.signature)}"


@dataclass
class SdJwtWithKb:
    """Complete SD-JWT presentation with key binding proof."""

    sd_jwt: SdJwt
    kb_jwt: KbSdJwt
    disclosed_indices: list[int] | None = None

    def serialize(self) -> str:
        """Serialize: <issuer-jwt>~<d1>~<d2>~...<kb-jwt>"""
        sd_part = self.sd_jwt.serialize(include_disclosures=self.disclosed_indices)
        return sd_part + self.kb_jwt.jwt


def create_kb_sd_jwt(
    sd_jwt: SdJwt,
    holder_header: dict,
    holder_payload: dict,
    holder_private_key: ec.EllipticCurvePrivateKey,
    disclosed_indices: list[int] | None = None,
) -> SdJwtWithKb:
    """Create a KB-SD-JWT by signing a key binding proof over the SD-JWT.

    holder_payload should include: nonce, aud, iat, sd_hash
    The sd_hash is computed from the SD-JWT's serialized form.
    """
    # Compute sd_hash if not provided
    if "sd_hash" not in holder_payload:
        sd_serialized = sd_jwt.serialize(include_disclosures=disclosed_indices)
        holder_payload["sd_hash"] = hash_bytes(sd_serialized.encode("ascii"))

    jwt_token = _jwt_encode(holder_header, holder_payload, holder_private_key)
    h, p, sig = _jwt_decode_parts(jwt_token)

    kb = KbSdJwt(header=h, payload=p, signature=sig)
    return SdJwtWithKb(sd_jwt=sd_jwt, kb_jwt=kb, disclosed_indices=disclosed_indices)


def verify_kb_jwt(kb_jwt: KbSdJwt, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verify the key binding JWT signature."""
    h = _b64url_encode(json.dumps(kb_jwt.header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(kb_jwt.payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    return es256_verify(signing_input, kb_jwt.signature, public_key)
