"""Layer 3: Agent KB-SD-JWT mandate models (autonomous mode only).

V2 splits L3 into two separate credentials:
  L3a (PaymentL3Mandate) → payment network, contains final payment values
  L3b (CheckoutL3Mandate) → merchant, contains final checkout JWT
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FinalCheckoutMandate:
    """L3b final checkout mandate for merchant."""

    vct: str = "mandate.checkout.1"
    checkout_jwt: str = ""  # Merchant-signed JWT with cart items
    checkout_hash: str = ""  # SHA-256 of checkout_jwt (cross-ref to L3a transaction_id)

    def to_dict(self) -> dict:
        return {
            "vct": self.vct,
            "checkout_jwt": self.checkout_jwt,
            "checkout_hash": self.checkout_hash,
        }


@dataclass
class FinalPaymentMandate:
    """L3a final payment mandate for network."""

    vct: str = "mandate.payment.1"
    transaction_id: str = ""  # = checkout_hash (cross-ref to L3b)
    payee: dict = field(default_factory=dict)  # {id, name, website}
    payment_amount: dict = field(default_factory=dict)  # {currency: str, amount: int}
    payment_instrument: dict = field(default_factory=dict)  # {type, id, description}

    def to_dict(self) -> dict:
        return {
            "vct": self.vct,
            "transaction_id": self.transaction_id,
            "payee": self.payee,
            "payment_amount": self.payment_amount,
            "payment_instrument": self.payment_instrument,
        }


@dataclass
class PaymentL3Mandate:
    """L3a KB-SD-JWT: agent's payment fulfillment for network."""

    nonce: str
    aud: str  # Payment network URL
    iat: int
    iss: str | None = None  # Issuer/signer URL
    exp: int | None = None  # Expiration timestamp
    sd_hash: str = ""  # Hash of L2 base JWT + payment disclosure + merchant disclosure
    final_payment: FinalPaymentMandate | None = None
    final_merchant: dict | None = None  # Selected merchant (standalone disclosure)


@dataclass
class CheckoutL3Mandate:
    """L3b KB-SD-JWT: agent's checkout fulfillment for merchant."""

    nonce: str
    aud: str  # Merchant URL
    iat: int
    iss: str | None = None  # Issuer/signer URL
    exp: int | None = None  # Expiration timestamp
    sd_hash: str = ""  # Hash of L2 base JWT + checkout disclosure + item disclosure
    final_checkout: FinalCheckoutMandate | None = None
