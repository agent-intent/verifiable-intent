"""ES256 signing and key management utilities."""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def generate_es256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _int_to_b64url(n: int, length: int = 32) -> str:
    return _b64url_encode(n.to_bytes(length, "big"))


def _b64url_to_int(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def private_key_to_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    numbers = key.private_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(numbers.public_numbers.x),
        "y": _int_to_b64url(numbers.public_numbers.y),
        "d": _int_to_b64url(numbers.private_value),
    }


def public_key_to_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        pub = key.public_key()
    else:
        pub = key
    numbers = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(numbers.x),
        "y": _int_to_b64url(numbers.y),
    }


def jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = _b64url_to_int(jwk["x"])
    y = _b64url_to_int(jwk["y"])
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()


def jwk_to_private_key(jwk: dict) -> ec.EllipticCurvePrivateKey:
    x = _b64url_to_int(jwk["x"])
    y = _b64url_to_int(jwk["y"])
    d = _b64url_to_int(jwk["d"])
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    priv_numbers = ec.EllipticCurvePrivateNumbers(d, pub_numbers)
    return priv_numbers.private_key()


def es256_sign(payload: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    der_sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es256_verify(payload: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_sig = encode_dss_signature(r, s)
    try:
        public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _jwt_encode(header: dict, payload: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = es256_sign(signing_input, private_key)
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _jwt_decode_parts(token: str) -> tuple[dict, dict, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    return header, payload, signature
