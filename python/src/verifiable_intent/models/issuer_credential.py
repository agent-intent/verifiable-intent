"""Layer 1: Issuer SD-JWT credential model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IssuerCredential:
    """Layer 1 Issuer SD-JWT: binds user identity to public key."""

    iss: str  # Issuer URL, e.g., "https://www.mastercard.com"
    sub: str  # Subject identifier
    iat: int  # Issued-at timestamp
    exp: int  # Expiration timestamp
    vct: str = "https://credentials.mastercard.com/card"
    aud: str | None = None  # Intended recipient (wallet URL), OPTIONAL
    cnf_jwk: dict = field(default_factory=dict)  # User's public key (JWK)

    # Always-visible claims
    pan_last_four: str = ""  # Last 4 digits of PAN
    scheme: str = ""  # Card scheme (e.g., "Mastercard")
    card_id: str | None = None  # Links to payment_instrument.id in L2/L3

    # Selectively disclosable claims (email only)
    email: str | None = None

    def to_payload(self) -> dict:
        """Return the non-SD claims for the JWT payload.
        _sd array and disclosures are added during issuance."""
        d = {
            "iss": self.iss,
            "sub": self.sub,
            "iat": self.iat,
            "exp": self.exp,
            "vct": self.vct,
            "cnf": {"jwk": self.cnf_jwk},
        }
        if self.aud:
            d["aud"] = self.aud
        d["pan_last_four"] = self.pan_last_four
        d["scheme"] = self.scheme
        if self.card_id is not None:
            d["card_id"] = self.card_id
        return d
