"""Constraint type definitions for autonomous mode mandates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Constraint:
    """Base constraint type. Unknown constraint types are preserved as-is."""

    type: str = ""
    extra_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"type": self.type}
        d.update(self.extra_fields)
        return d


@dataclass
class AllowedMerchantConstraint(Constraint):
    """Merchant allowlist in checkout mandate. allowed contains SD disclosure refs."""

    allowed: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self.type = "mandate.checkout.allowed_merchants"

    def to_dict(self) -> dict:
        d = {"type": self.type, "allowed": self.allowed}
        d.update(self.extra_fields)
        return d


@dataclass
class CheckoutLineItemsConstraint(Constraint):
    """Line items in checkout mandate. Each item has id, acceptable_items (SD refs), and quantity.

    match_mode controls how fulfillment line items are compared to the
    constraint's item allowlist:
      - "minimum" (default): fulfillment items must be within the constraint
        (subset of allowed_ids and under per-item quantity caps).
      - "exact": additionally requires every line-item requirement to be
        fulfilled by at least one acceptable item with quantity > 0.
    """

    items: list[dict] = field(default_factory=list)  # [{id, acceptable_items, quantity}, ...]
    match_mode: str = "minimum"

    def __post_init__(self):
        self.type = "mandate.checkout.line_items"

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"type": self.type, "items": self.items, "match_mode": self.match_mode}
        d.update(self.extra_fields)
        return d


@dataclass
class AllowedPayeeConstraint(Constraint):
    """Payee allowlist in payment mandate. allowed contains SD disclosure refs."""

    allowed: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self.type = "mandate.payment.allowed_payees"

    def to_dict(self) -> dict:
        d = {"type": self.type, "allowed": self.allowed}
        d.update(self.extra_fields)
        return d


@dataclass
class PaymentAmountConstraint(Constraint):
    """Per-transaction budget bounds. min/max in integer minor units (cents)."""

    currency: str = "USD"
    min: int | None = None
    max: int | None = None

    def __post_init__(self):
        self.type = "mandate.payment.amount_range"

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"type": self.type, "currency": self.currency}
        if self.min is not None:
            d["min"] = self.min
        if self.max is not None:
            d["max"] = self.max
        d.update(self.extra_fields)
        return d


@dataclass
class ReferenceConstraint(Constraint):
    """Cross-reference to checkout mandate via hash of checkout disclosure."""

    conditional_transaction_id: str = ""

    def __post_init__(self):
        self.type = "mandate.payment.reference"

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "conditional_transaction_id": self.conditional_transaction_id,
        }
        d.update(self.extra_fields)
        return d


@dataclass
class PaymentBudgetConstraint(Constraint):
    """Cumulative spend cap across all L3s for a mandate pair. Network-enforced."""

    currency: str = "USD"
    max: int = 0  # Cumulative cap in integer minor units
    min: int | None = None  # Optional per-transaction floor in integer minor units

    def __post_init__(self):
        self.type = "mandate.payment.budget"
        if self.max <= 0:
            raise ValueError("PaymentBudgetConstraint.max must be a positive integer")
        if self.min is not None and self.min <= 0:
            raise ValueError("PaymentBudgetConstraint.min must be a positive integer")

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"type": self.type, "currency": self.currency, "max": self.max}
        if self.min is not None:
            d["min"] = self.min
        d.update(self.extra_fields)
        return d


@dataclass
class PaymentRecurrenceConstraint(Constraint):
    """Subscription setup terms for merchant-initiated recurring. Network-enforced."""

    frequency: str = (
        ""  # ISO 20022: "INDA", "DAIL", "WEEK", "TOWK", "TWMN", "MNTH", "TOMN", "QUTR", "FOMN", "SEMI", "YEAR", "TYEA"
    )
    start_date: str = ""  # ISO 8601
    end_date: str | None = None  # ISO 8601, optional
    number: int | None = None  # Max occurrences, optional

    def __post_init__(self):
        self.type = "mandate.payment.recurrence"

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "type": self.type,
            "frequency": self.frequency,
            "start_date": self.start_date,
        }
        if self.end_date is not None:
            d["end_date"] = self.end_date
        if self.number is not None:
            d["number"] = self.number
        d.update(self.extra_fields)
        return d


@dataclass
class AgentRecurrenceConstraint(Constraint):
    """Agent-managed recurring transaction terms. Network-enforced."""

    frequency: str = (
        ""  # ISO 20022: "INDA", "DAIL", "WEEK", "TOWK", "TWMN", "MNTH", "TOMN", "QUTR", "FOMN", "SEMI", "YEAR", "TYEA"
    )
    start_date: str = ""  # ISO 8601
    end_date: str = ""  # ISO 8601, required
    max_occurrences: int | None = None  # Optional cap

    def __post_init__(self):
        self.type = "mandate.payment.agent_recurrence"

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "type": self.type,
            "frequency": self.frequency,
            "start_date": self.start_date,
            "end_date": self.end_date,
        }
        if self.max_occurrences is not None:
            d["max_occurrences"] = self.max_occurrences
        d.update(self.extra_fields)
        return d


_REGISTRY: dict[str, type[Constraint]] = {
    "mandate.checkout.allowed_merchants": AllowedMerchantConstraint,
    "mandate.checkout.line_items": CheckoutLineItemsConstraint,
    "mandate.payment.allowed_payees": AllowedPayeeConstraint,
    "mandate.payment.amount_range": PaymentAmountConstraint,
    "mandate.payment.reference": ReferenceConstraint,
    "mandate.payment.budget": PaymentBudgetConstraint,
    "mandate.payment.recurrence": PaymentRecurrenceConstraint,
    "mandate.payment.agent_recurrence": AgentRecurrenceConstraint,
}


def parse_constraint(data: dict) -> Constraint:
    """Parse a constraint dict into the appropriate typed constraint."""
    if not isinstance(data, dict):
        return Constraint(type="unknown")
    ctype = data.get("type", "")
    cls = _REGISTRY.get(ctype)
    if cls is None:
        return Constraint(type=ctype, extra_fields={k: v for k, v in data.items() if k != "type"})

    known_fields = {f.name for f in cls.__dataclass_fields__.values()} - {"type", "extra_fields"}
    kwargs = {}
    extra = {}
    for k, v in data.items():
        if k == "type":
            continue
        if k in known_fields:
            kwargs[k] = v
        else:
            extra[k] = v
    obj = cls(type=ctype, **kwargs)
    obj.extra_fields = extra
    return obj
