"""SD-JWT creation and parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec

from .disclosure import decode_disclosure, hash_disclosure
from .signing import _b64url_encode, _jwt_decode_parts, _jwt_encode, es256_verify


@dataclass
class SdJwt:
    """Represents a parsed SD-JWT with its disclosures."""

    header: dict
    payload: dict
    signature: bytes
    disclosures: list[str] = field(default_factory=list)
    disclosure_values: list[list] = field(default_factory=list)
    _raw_header_b64: str | None = field(default=None, repr=False)
    _raw_payload_b64: str | None = field(default=None, repr=False)

    @property
    def issuer_jwt(self) -> str:
        h = self._raw_header_b64 or _b64url_encode(json.dumps(self.header, separators=(",", ":")).encode())
        p = self._raw_payload_b64 or _b64url_encode(json.dumps(self.payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{_b64url_encode(self.signature)}"

    def serialize(self, include_disclosures: list[int] | None = None) -> str:
        """Serialize to SD-JWT format: <jwt>~<disclosure1>~<disclosure2>~

        If include_disclosures is provided, only include those indices.
        """
        parts = [self.issuer_jwt]
        if include_disclosures is not None:
            for i in include_disclosures:
                parts.append(self.disclosures[i])
        else:
            parts.extend(self.disclosures)
        return "~".join(parts) + "~"


def create_sd_jwt(
    header: dict,
    payload: dict,
    disclosures: list[str],
    private_key: ec.EllipticCurvePrivateKey,
) -> SdJwt:
    """Create an SD-JWT with the given payload and disclosures.

    The payload should already include _sd array and _sd_alg.
    Disclosures are pre-created disclosure strings.
    """
    jwt_token = _jwt_encode(header, payload, private_key)
    parts = jwt_token.split(".")
    raw_h_b64, raw_p_b64 = parts[0], parts[1]
    h, p, sig = _jwt_decode_parts(jwt_token)
    disclosure_values = [decode_disclosure(d) for d in disclosures]
    return SdJwt(
        header=h,
        payload=p,
        signature=sig,
        disclosures=disclosures,
        disclosure_values=disclosure_values,
        _raw_header_b64=raw_h_b64,
        _raw_payload_b64=raw_p_b64,
    )


def decode_sd_jwt(serialized: str) -> SdJwt:
    """Parse a serialized SD-JWT string.

    Raises ValueError for any malformed input (bad structure, invalid
    base64url, non-JSON payload, etc.).
    """
    try:
        # Format: <jwt>~<d1>~<d2>~...~
        # Trailing ~ means last element after split is empty
        parts = serialized.split("~")
        jwt_part = parts[0]
        disclosures = [p for p in parts[1:] if p]

        # Validate JWT structure first (raises ValueError for malformed input),
        # then capture raw base64url segments for round-trip stability.
        header, payload, signature = _jwt_decode_parts(jwt_part)
        jwt_segments = jwt_part.split(".")
        raw_h_b64, raw_p_b64 = jwt_segments[0], jwt_segments[1]
        disclosure_values = [decode_disclosure(d) for d in disclosures]

        return SdJwt(
            header=header,
            payload=payload,
            signature=signature,
            disclosures=disclosures,
            disclosure_values=disclosure_values,
            _raw_header_b64=raw_h_b64,
            _raw_payload_b64=raw_p_b64,
        )
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid SD-JWT: {e}") from e


def verify_sd_jwt_signature(sd_jwt: SdJwt, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verify the issuer's signature on the SD-JWT.

    Always re-encodes from current header/payload dicts (never uses cached
    _raw_* segments) so that in-memory mutations are caught by signature
    verification.  Raw segments are only used by issuer_jwt/serialize() for
    sd_hash round-trip stability.
    """
    try:
        h = _b64url_encode(json.dumps(sd_jwt.header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(sd_jwt.payload, separators=(",", ":")).encode())
    except (TypeError, ValueError):
        return False
    signing_input = f"{h}.{p}".encode("ascii")
    return es256_verify(signing_input, sd_jwt.signature, public_key)


def resolve_disclosures(sd_jwt: SdJwt) -> dict:
    """Resolve all disclosures into the payload, returning a full claim set."""
    result = dict(sd_jwt.payload)
    _sd_raw = result.get("_sd", [])
    if isinstance(_sd_raw, list):
        sd_hashes = {v for v in _sd_raw if isinstance(v, str)}
    else:
        sd_hashes = set()

    # Map disclosure hashes to their decoded values
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        disc_hash = hash_disclosure(disc_str)
        if disc_hash in sd_hashes:
            if len(disc_val) == 3:
                # Object property: [salt, name, value]
                result[disc_val[1]] = disc_val[2]
            elif len(disc_val) == 2:
                # Array element: [salt, value] — added to delegate_payload resolution
                pass

    # Resolve delegate_payload references
    delegate_payload = result.get("delegate_payload", [])
    if delegate_payload and isinstance(delegate_payload, list):
        resolved_delegates = []
        disc_by_hash = {}
        for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
            disc_by_hash[hash_disclosure(disc_str)] = disc_val

        for item in delegate_payload:
            if isinstance(item, dict) and "..." in item:
                ref_hash = item["..."]
                if ref_hash in disc_by_hash:
                    dv = disc_by_hash[ref_hash]
                    resolved_delegates.append(dv[-1])  # last element is the value
                else:
                    resolved_delegates.append(item)
            else:
                resolved_delegates.append(item)
        result["delegate_payload"] = resolved_delegates

    return result
