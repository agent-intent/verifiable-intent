"""SD-JWT selective disclosure utilities."""

from __future__ import annotations

import base64
import hashlib
import json
import os


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _generate_salt() -> str:
    return _b64url_encode(os.urandom(16))


def create_disclosure(claim_name: str | None, claim_value, salt: str | None = None) -> str:
    """Create an SD-JWT disclosure.

    For object property disclosures: [salt, claim_name, claim_value]
    For array element disclosures: [salt, claim_value]
    """
    if salt is None:
        salt = _generate_salt()
    if claim_name is not None:
        arr = [salt, claim_name, claim_value]
    else:
        arr = [salt, claim_value]
    encoded = json.dumps(arr, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(encoded)


def decode_disclosure(disclosure_b64: str) -> list:
    raw = _b64url_decode(disclosure_b64)
    return json.loads(raw)


def hash_disclosure(disclosure_b64: str) -> str:
    """SHA-256 hash of a disclosure, base64url-encoded.

    Per SD-JWT spec, hashes the ASCII base64url string (not decoded bytes).
    """
    digest = hashlib.sha256(disclosure_b64.encode("ascii")).digest()
    return _b64url_encode(digest)


def create_sd_array(disclosures: list[str]) -> list[str]:
    """Create the _sd array from a list of disclosure strings."""
    return [hash_disclosure(d) for d in disclosures]


def hash_bytes(data: bytes) -> str:
    """SHA-256 hash of raw bytes, base64url-encoded."""
    digest = hashlib.sha256(data).digest()
    return _b64url_encode(digest)


def hash_string(s: str) -> str:
    """SHA-256 hash of a UTF-8 string, base64url-encoded."""
    return hash_bytes(s.encode("utf-8"))


def create_delegate_ref(disclosure_hash: str) -> dict:
    """Create a delegate_payload reference: {"...": "<hash>"}."""
    return {"...": disclosure_hash}


def build_selective_presentation(base_jwt: str, disclosures: list[str]) -> str:
    """Build a selective SD-JWT presentation string with only specified disclosures.

    Returns the serialized form: <base_jwt>~<disc1>~<disc2>~...~
    Used to compute sd_hash for split L3 where each recipient sees
    a different subset of L2 disclosures.
    """
    parts = [base_jwt] + disclosures
    return "~".join(parts) + "~"
