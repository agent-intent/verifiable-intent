"""Characterize why L3 presentation hashes cannot identify a shared budget.

These are signed-fixture tests, not an implementation of network accounting.
See security-model.md section 4.2. No new wire identifier is defined here.
"""

import time

import pytest

from helpers import MERCHANTS, PAYMENT_INSTRUMENT, get_agent_keys, get_issuer_keys, get_user_keys, validate_intent
from verifiable_intent import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    FinalPaymentMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentL3Mandate,
    PaymentMandate,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes
from verifiable_intent.crypto.sd_jwt import resolve_disclosures
from verifiable_intent.models.constraints import AgentRecurrenceConstraint, PaymentBudgetConstraint


@pytest.fixture
def shared_budget():
    issuer, user, agent = get_issuer_keys(), get_user_keys(), get_agent_keys()
    now = int(time.time())
    l1 = create_layer1(
        IssuerCredential(
            iss="https://issuer.example.com",
            sub="test-user",
            iat=now,
            exp=now + 3600,
            aud="https://wallet.example.com",
            cnf_jwk=user.public_jwk,
            pan_last_four="0000",
            scheme="test",
        ),
        issuer.private_key,
    )
    item = {"id": "test-item", "title": "Test item"}
    l2 = create_layer2_autonomous(
        UserMandate(
            nonce="test-approval",
            aud="https://agent.example.com",
            iat=now,
            iss="https://wallet.example.com",
            exp=now + 3600,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1.serialize().encode("ascii")),
            checkout_mandate=CheckoutMandate(
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                constraints=[
                    AllowedMerchantConstraint(allowed=MERCHANTS),
                    CheckoutLineItemsConstraint(items=[{"id": "line-1", "acceptable_items": [item], "quantity": 1}]),
                ],
            ),
            payment_mandate=PaymentMandate(
                cnf_jwk=agent.public_jwk,
                cnf_kid="agent-key-1",
                payment_instrument=PAYMENT_INSTRUMENT,
                constraints=[
                    PaymentAmountConstraint(currency="USD", min=1, max=10000),
                    AllowedPayeeConstraint(allowed=MERCHANTS),
                    PaymentBudgetConstraint(currency="USD", max=10000),
                    AgentRecurrenceConstraint(
                        frequency="ON_DEMAND",
                        start_date="2026-01-01",
                        end_date="2099-01-01",
                        max_occurrences=10,
                    ),
                ],
            ),
            merchants=MERCHANTS,
            acceptable_items=[item],
        ),
        user.private_key,
    )
    disclosures = list(zip(l2.disclosures, l2.disclosure_values))
    payment = next(
        e for e, d in disclosures if isinstance(d[-1], dict) and d[-1].get("vct") == "mandate.payment.open.1"
    )
    base = l2.serialize().split("~")[0]
    presentations, proofs = [], []
    for index, merchant in enumerate(MERCHANTS):
        selected = next(e for e, d in disclosures if isinstance(d[-1], dict) and d[-1].get("id") == merchant["id"])
        presentation = build_selective_presentation(base, [payment, selected])
        proof = create_layer3_payment(
            PaymentL3Mandate(
                nonce=f"purchase-{index}",
                aud="https://network.example.com",
                iat=now,
                exp=now + 300,
                final_payment=FinalPaymentMandate(
                    # Synthetic checkout reference; merchant-side execution is outside this fixture.
                    transaction_id=hash_bytes(f"test-checkout-{index}".encode("ascii")),
                    payee=merchant,
                    payment_amount={"currency": "USD", "amount": 6000},
                    payment_instrument=PAYMENT_INSTRUMENT,
                ),
                final_merchant=merchant,
            ),
            agent.private_key,
            base,
            payment,
            selected,
        )
        presentations.append(presentation)
        proofs.append(proof)
    return l1, l2, issuer, payment, presentations, proofs


def test_same_budget_has_different_valid_presentation_hashes(shared_budget):
    l1, l2, issuer, payment, presentations, proofs = shared_budget
    assert len(proofs) == 2
    assert proofs[0].payload["sd_hash"] != proofs[1].payload["sd_hash"]
    mandate = next(
        value
        for value in resolve_disclosures(l2)["delegate_payload"]
        if isinstance(value, dict) and value.get("vct") == "mandate.payment.open.1"
    )
    budget = next(c for c in mandate["constraints"] if c["type"] == "mandate.payment.budget")
    amounts = [
        next(
            value["payment_amount"]["amount"]
            for value in resolve_disclosures(proof)["delegate_payload"]
            if isinstance(value, dict) and value.get("vct") == "mandate.payment.1"
        )
        for proof in proofs
    ]
    assert amounts == [6000, 6000]
    assert budget["currency"] == "USD" and budget["max"] == 10000
    assert sum(amounts) > budget["max"]
    for presentation, proof in zip(presentations, proofs):
        assert presentation.split("~")[0] == l2.serialize().split("~")[0]
        assert payment in presentation.split("~")
        result = validate_intent(l1.serialize(), presentation, proof.serialize(), issuer.public_key)
        assert result["valid"], result["errors"]
    # Both proofs belong to one issued mandate pair. A map keyed only by sd_hash
    # would create two allowance records. A network must resolve them to one.
    assert len({proof.payload["sd_hash"] for proof in proofs}) == 2


@pytest.mark.parametrize("index", [0, 1])
def test_accounting_identity_does_not_replace_presentation_binding(shared_budget, index):
    l1, l2, issuer, _, presentations, proofs = shared_budget
    result = verify_chain(
        l1,
        l2,
        l3_payment=proofs[index],
        issuer_public_key=issuer.public_key,
        l1_serialized=l1.serialize(),
        l2_serialized=l2.serialize(),
        l2_payment_serialized=presentations[1 - index],
    )
    assert not result.valid
    assert any("sd_hash" in error for error in result.errors)
