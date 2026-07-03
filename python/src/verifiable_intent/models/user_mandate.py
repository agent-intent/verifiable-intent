"""Layer 2: User KB-SD-JWT mandate models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .constraints import Constraint


class MandateMode(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    AUTONOMOUS = "AUTONOMOUS"


@dataclass
class CheckoutMandate:
    """Checkout mandate — either open (L2 autonomous) or final (L2 immediate).

    Autonomous: cnf_jwk + constraints, vct = mandate.checkout.open.1
    Immediate: checkout_jwt + checkout_hash with final values, vct = mandate.checkout.1
    """

    vct: str = "mandate.checkout.open.1"
    # Autonomous mode: constraints + cnf for agent delegation
    cnf_jwk: dict | None = None
    cnf_kid: str | None = None  # Key identifier for agent key (autonomous mode)
    constraints: list[Constraint] = field(default_factory=list)
    # Immediate mode: final checkout JWT and its hash
    checkout_jwt: str | None = None
    checkout_hash: str | None = None  # SHA-256 of checkout_jwt

    def __post_init__(self):
        if self.cnf_jwk and self.checkout_jwt is not None:
            raise ValueError("CheckoutMandate cannot have both cnf_jwk (autonomous) and checkout_jwt (immediate)")

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"vct": self.vct}
        if self.cnf_jwk:
            jwk = dict(self.cnf_jwk)
            if self.cnf_kid:
                jwk["kid"] = self.cnf_kid
            d["cnf"] = {"jwk": jwk}
        if self.constraints:
            d["constraints"] = [c.to_dict() for c in self.constraints]
        if self.checkout_jwt is not None:
            d["checkout_jwt"] = self.checkout_jwt
        if self.checkout_hash is not None:
            d["checkout_hash"] = self.checkout_hash
        return d


@dataclass
class PaymentMandate:
    """Payment mandate — either open (L2 autonomous) or final (L2 immediate).

    Autonomous: cnf_jwk + constraints + payment_instrument + risk_data, vct = mandate.payment.open.1
    Immediate: currency + amount + payee + payment_instrument + transaction_id, vct = mandate.payment.1
    """

    vct: str = "mandate.payment.open.1"
    # Autonomous mode
    cnf_jwk: dict | None = None
    cnf_kid: str | None = None  # Key identifier for agent key (autonomous mode)
    constraints: list[Constraint] = field(default_factory=list)
    # Both modes
    payment_instrument: dict | None = None  # {type, id, description} — required
    # Autonomous only
    risk_data: dict | None = None  # {device_id, ip_address} — optional, L2 only
    # Immediate mode: final payment values
    payee: dict | None = None  # {id, name, website}
    currency: str | None = None  # e.g. "USD"
    amount: int | None = None  # Integer minor units (cents)
    transaction_id: str | None = None  # SHA-256 of checkout_jwt (cross-ref to checkout_hash)

    def __post_init__(self):
        has_immediate = self.amount is not None
        has_autonomous = self.cnf_jwk is not None
        if has_immediate and has_autonomous:
            raise ValueError("PaymentMandate cannot have both cnf_jwk (autonomous) and amount (immediate)")

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"vct": self.vct}
        if self.cnf_jwk:
            jwk = dict(self.cnf_jwk)
            if self.cnf_kid:
                jwk["kid"] = self.cnf_kid
            d["cnf"] = {"jwk": jwk}
        if self.constraints:
            d["constraints"] = [c.to_dict() for c in self.constraints]
        if self.payment_instrument is not None:
            d["payment_instrument"] = self.payment_instrument
        if self.risk_data is not None:
            d["risk_data"] = self.risk_data
        # Immediate mode fields
        if self.payee is not None:
            d["payee"] = self.payee
        if self.currency is not None and self.amount is not None:
            d["payment_amount"] = {"currency": self.currency, "amount": self.amount}
        if self.transaction_id is not None:
            d["transaction_id"] = self.transaction_id
        return d


@dataclass
class UserMandate:
    """Layer 2 KB-SD-JWT: user's consent with mandates."""

    nonce: str
    aud: str  # Agent URL
    iat: int
    mode: MandateMode
    iss: str | None = None  # Issuer/signer URL
    exp: int | None = None  # Expiration timestamp
    sd_hash: str = ""  # Hash of Layer 1 SD-JWT
    prompt_summary: str | None = None
    checkout_mandate: CheckoutMandate | None = None
    payment_mandate: PaymentMandate | None = None
    # Autonomous: merchant entries (selectively disclosable)
    merchants: list[dict] = field(default_factory=list)
    # Autonomous: acceptable items (selectively disclosable within checkout constraints)
    acceptable_items: list[dict] = field(default_factory=list)
