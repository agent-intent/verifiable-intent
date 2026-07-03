"""Tests for new constraint types: payment.budget, payment.recurrence, payment.agent_recurrence."""

import pytest

from verifiable_intent.models.constraints import (
    AgentRecurrenceConstraint,
    PaymentBudgetConstraint,
    PaymentRecurrenceConstraint,
    parse_constraint,
)
from verifiable_intent.verification.constraint_checker import (
    StrictnessMode,
    check_constraints,
)


class TestPaymentBudgetConstraint:
    def test_round_trip(self):
        c = PaymentBudgetConstraint(currency="USD", min=1000, max=100000)
        d = c.to_dict()
        assert d == {"type": "mandate.payment.budget", "currency": "USD", "min": 1000, "max": 100000}

    def test_parse(self):
        c = parse_constraint({"type": "mandate.payment.budget", "currency": "EUR", "min": 500, "max": 50000})
        assert isinstance(c, PaymentBudgetConstraint)
        assert c.currency == "EUR"
        assert c.min == 500
        assert c.max == 50000

    def test_round_trip_without_min(self):
        c = PaymentBudgetConstraint(currency="USD", max=100000)
        d = c.to_dict()
        assert d == {"type": "mandate.payment.budget", "currency": "USD", "max": 100000}

    def test_recognized_permissive(self):
        """payment.budget is recognized (checked, not skipped) in PERMISSIVE mode."""
        result = check_constraints(
            [{"type": "mandate.payment.budget", "currency": "USD", "max": 100000}],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
            mode=StrictnessMode.PERMISSIVE,
        )
        assert result.satisfied
        assert "mandate.payment.budget" in result.checked
        assert "mandate.payment.budget" not in result.skipped


class TestPaymentRecurrenceConstraint:
    def test_round_trip(self):
        c = PaymentRecurrenceConstraint(frequency="MNTH", start_date="2026-01-01", end_date="2028-01-01", number=24)
        d = c.to_dict()
        assert d == {
            "type": "mandate.payment.recurrence",
            "frequency": "MNTH",
            "start_date": "2026-01-01",
            "end_date": "2028-01-01",
            "number": 24,
        }

    def test_round_trip_minimal(self):
        c = PaymentRecurrenceConstraint(frequency="YEAR", start_date="2026-06-01")
        d = c.to_dict()
        assert d == {"type": "mandate.payment.recurrence", "frequency": "YEAR", "start_date": "2026-06-01"}
        assert "end_date" not in d
        assert "number" not in d

    def test_parse(self):
        c = parse_constraint(
            {"type": "mandate.payment.recurrence", "frequency": "MNTH", "start_date": "2026-01-01", "number": 12}
        )
        assert isinstance(c, PaymentRecurrenceConstraint)
        assert c.frequency == "MNTH"
        assert c.number == 12

    def test_recognized_permissive(self):
        result = check_constraints(
            [{"type": "mandate.payment.recurrence", "frequency": "MNTH", "start_date": "2026-01-01"}],
            {},
            mode=StrictnessMode.PERMISSIVE,
        )
        assert result.satisfied
        assert "mandate.payment.recurrence" in result.checked


class TestAgentRecurrenceConstraint:
    def test_round_trip(self):
        c = AgentRecurrenceConstraint(
            frequency="WEEK", start_date="2026-03-01", end_date="2026-06-01", max_occurrences=12
        )
        d = c.to_dict()
        assert d == {
            "type": "mandate.payment.agent_recurrence",
            "frequency": "WEEK",
            "start_date": "2026-03-01",
            "end_date": "2026-06-01",
            "max_occurrences": 12,
        }

    def test_round_trip_no_max(self):
        c = AgentRecurrenceConstraint(frequency="MNTH", start_date="2026-01-01", end_date="2027-01-01")
        d = c.to_dict()
        assert "max_occurrences" not in d

    def test_parse(self):
        c = parse_constraint(
            {
                "type": "mandate.payment.agent_recurrence",
                "frequency": "WEEK",
                "start_date": "2026-03-01",
                "end_date": "2026-06-01",
            }
        )
        assert isinstance(c, AgentRecurrenceConstraint)
        assert c.frequency == "WEEK"
        assert c.max_occurrences is None

    def test_recognized_permissive(self):
        result = check_constraints(
            [
                {
                    "type": "mandate.payment.agent_recurrence",
                    "frequency": "WEEK",
                    "start_date": "2026-03-01",
                    "end_date": "2026-06-01",
                }
            ],
            {},
            mode=StrictnessMode.PERMISSIVE,
        )
        assert result.satisfied
        assert "mandate.payment.agent_recurrence" in result.checked


class TestNewConstraintsWithOtherConstraints:
    def test_mixed_constraints_all_checked(self):
        """New network-enforced constraints work alongside existing local constraints."""
        result = check_constraints(
            [
                {"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000},
                {"type": "mandate.payment.budget", "currency": "USD", "max": 100000},
                {"type": "mandate.payment.recurrence", "frequency": "MNTH", "start_date": "2026-01-01"},
            ],
            {"payment_amount": {"amount": 27999, "currency": "USD"}},
            mode=StrictnessMode.STRICT,
        )
        assert result.satisfied
        assert "mandate.payment.amount_range" in result.checked
        assert "mandate.payment.budget" in result.checked
        assert "mandate.payment.recurrence" in result.checked


class TestPaymentBudgetConstraintValidation:
    """7F: PaymentBudgetConstraint rejects non-positive min/max values."""

    def test_budget_zero_max_raises(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            PaymentBudgetConstraint(currency="USD", max=0)

    def test_budget_negative_max_raises(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            PaymentBudgetConstraint(currency="USD", max=-100)

    def test_budget_zero_min_raises(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            PaymentBudgetConstraint(currency="USD", min=0, max=100)

    def test_budget_negative_min_raises(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            PaymentBudgetConstraint(currency="USD", min=-1, max=100)


class TestL2SdArrayContainsMandateHashes:
    """7E: L2 _sd array must contain hashes of ALL disclosures (not just prompt_summary)."""

    def test_immediate_l2_sd_contains_mandate_hashes(self):
        import time

        from helpers import (
            PAYMENT_INSTRUMENT,
            checkout_hash_from_jwt,
            create_checkout_jwt,
            get_issuer_keys,
            get_merchant_keys,
            get_user_keys,
        )
        from verifiable_intent import (
            FinalCheckoutMandate,
            FinalPaymentMandate,
            IssuerCredential,
            MandateMode,
            UserMandate,
            create_layer1,
            create_layer2_immediate,
        )
        from verifiable_intent.crypto.disclosure import hash_bytes

        issuer = get_issuer_keys()
        user = get_user_keys()
        merchant = get_merchant_keys()
        now = int(time.time())

        l1 = create_layer1(
            IssuerCredential(
                iss="https://issuer.example.com",
                sub="user1",
                iat=now,
                exp=now + 86400,
                aud="https://wallet.example.com",
                email="test@example.com",
                pan_last_four="1234",
                scheme="Mastercard",
                cnf_jwk=user.public_jwk,
            ),
            issuer.private_key,
        )

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        mandate = UserMandate(
            nonce="n-test",
            aud="https://wallet.example.com",
            iat=now,
            exp=now + 900,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1.serialize().encode("ascii")),
            checkout_mandate=FinalCheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=c_hash),
            payment_mandate=FinalPaymentMandate(
                transaction_id=c_hash,
                payee={"name": "Tennis Warehouse", "website": "https://tw.com"},
                payment_amount={"currency": "USD", "amount": 27999},
                payment_instrument=PAYMENT_INSTRUMENT,
            ),
        )
        result = create_layer2_immediate(mandate, user.private_key)
        sd_jwt = result.sd_jwt

        # _sd should contain hashes for ALL disclosures (checkout + payment)
        sd_array = sd_jwt.payload.get("_sd", [])
        assert len(sd_array) == len(sd_jwt.disclosures), (
            f"_sd should have {len(sd_jwt.disclosures)} entries (one per disclosure), got {len(sd_array)}"
        )

    def test_autonomous_l2_sd_contains_all_disclosure_hashes(self):
        import time

        from helpers import ACCEPTABLE_ITEMS, MERCHANTS, PAYMENT_INSTRUMENT, get_issuer_keys, get_user_keys
        from verifiable_intent import (
            AllowedMerchantConstraint,
            CheckoutLineItemsConstraint,
            CheckoutMandate,
            IssuerCredential,
            MandateMode,
            PaymentAmountConstraint,
            PaymentMandate,
            UserMandate,
            create_layer1,
            create_layer2_autonomous,
        )
        from verifiable_intent.crypto.disclosure import hash_bytes

        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        l1 = create_layer1(
            IssuerCredential(
                iss="https://issuer.example.com",
                sub="user1",
                iat=now,
                exp=now + 86400,
                aud="https://wallet.example.com",
                email="test@example.com",
                pan_last_four="1234",
                scheme="Mastercard",
                cnf_jwk=user.public_jwk,
            ),
            issuer.private_key,
        )

        from helpers import get_agent_keys

        agent = get_agent_keys()

        mandate = UserMandate(
            nonce="n-test",
            aud="https://agent.example.com",
            iat=now,
            exp=now + 86400,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1.serialize().encode("ascii")),
            checkout_mandate=CheckoutMandate(
                vct="mandate.checkout.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                constraints=[
                    AllowedMerchantConstraint(allowed=MERCHANTS),
                    CheckoutLineItemsConstraint(
                        items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
                    ),
                ],
            ),
            payment_mandate=PaymentMandate(
                vct="mandate.payment.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                payment_instrument=PAYMENT_INSTRUMENT,
                constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
            ),
            merchants=MERCHANTS,
            acceptable_items=ACCEPTABLE_ITEMS,
        )
        l2 = create_layer2_autonomous(mandate, user.private_key)

        # _sd should contain hashes for ALL disclosures
        sd_array = l2.payload.get("_sd", [])
        assert len(sd_array) == len(l2.disclosures), (
            f"_sd should have {len(l2.disclosures)} entries, got {len(sd_array)}"
        )
