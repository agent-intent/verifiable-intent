"""Cart structures for merchant-signed cart JWTs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CartItem:
    sku: str
    name: str
    quantity: int
    price: str
    currency: str = "USD"
    brand: str | None = None
    model: str | None = None
    color: str | None = None
    size: int | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "sku": self.sku,
            "name": self.name,
            "quantity": self.quantity,
            "price": self.price,
            "currency": self.currency,
        }
        if self.brand:
            d["brand"] = self.brand
        if self.model:
            d["model"] = self.model
        if self.color:
            d["color"] = self.color
        if self.size is not None:
            d["size"] = self.size
        return d


@dataclass
class Cart:
    merchant_name: str
    merchant_url: str
    items: list[CartItem] = field(default_factory=list)
    total: str = "0"
    currency: str = "USD"

    def to_dict(self) -> dict:
        return {
            "merchant": {
                "name": self.merchant_name,
                "url": self.merchant_url,
            },
            "items": [item.to_dict() for item in self.items],
            "total": self.total,
            "currency": self.currency,
        }
