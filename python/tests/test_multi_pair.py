"""Tests for multi-mandate-pair L2 verification (issue #37)."""

from __future__ import annotations

import copy
import time

from helpers import (
    ACCEPTABLE_ITEMS,
    MERCHANTS,
    PAYMENT_INSTRUMENT,
    checkout_hash_from_jwt,
    create_checkout_jwt,
    get_agent_keys,
    get_issuer_keys,
    get_merchant_keys,
    get_user_keys,
)
from verifiable_intent import (
    AllowedMerchantConstraint,
    CheckoutL3Mandate,
    CheckoutLineItemsConstraint,
    CheckoutMandate,
    FinalCheckoutMandate,
    FinalPaymentMandate,
    IssuerCredential,
    MandateMode,
    PaymentAmountConstraint,
    PaymentL3Mandate,
    PaymentMandate,
    SplitL3,
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer2_immediate,
    create_layer3_checkout,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes, hash_disclosure
from verifiable_intent.crypto.sd_jwt import SdJwt, create_sd_jwt

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Second merchant for multi-pair scenarios
MERCHANTS_2 = [
    {
        "id": "merchant-uuid-3",
        "name": "Sports Direct",
        "website": "https://sportsdirect.com",
    },
    {
        "id": "merchant-uuid-4",
        "name": "Decathlon",
        "website": "https://decathlon.com",
    },
]

ACCEPTABLE_ITEMS_2 = [
    {
        "id": "NIK90210",
        "title": "Nike Air Zoom Vapor Pro 2",
    },
    {
        "id": "ADI55123",
        "title": "Adidas Barricade Tennis Shoe",
    },
]


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _make_l1(now=None):
    issuer = get_issuer_keys()
    user = get_user_keys()
    now = now or int(time.time())
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        pan_last_four="8842",
        scheme="mastercard",
        email="alice@example.com",
        iat=now,
        exp=now + 86400,
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_single_pair_l2(now, l1_ser, checkout_items, merchants, acceptable_items, payment_instrument):
    """Create a single-pair autonomous L2 with SDK, returning (l2, checkout_jwt, c_hash)."""
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()

    checkout_jwt = create_checkout_jwt(checkout_items, merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        constraints=[
            AllowedMerchantConstraint(allowed=merchants),
            CheckoutLineItemsConstraint(
                items=[{"id": "li-1", "acceptable_items": acceptable_items[:1], "quantity": 1}]
            ),
        ],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent.public_jwk,
        cnf_kid="agent-key-1",
        payment_instrument=payment_instrument,
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    user_mandate = UserMandate(
        nonce="test-n",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
        merchants=merchants,
        acceptable_items=acceptable_items,
    )
    l2 = create_layer2_autonomous(user_mandate, user.private_key)
    return l2, checkout_jwt, c_hash


def _merge_l2s(l2_a, l2_b, user_private_key):
    """Merge two single-pair L2s into a multi-pair L2.

    Combines delegate_payload refs and disclosures from both L2s,
    then re-signs with the user's key.
    """
    new_payload = copy.deepcopy(l2_a.payload)
    # Append l2_b's delegate_payload refs
    for ref in l2_b.payload.get("delegate_payload", []):
        new_payload["delegate_payload"].append(ref)

    # Combine disclosures
    combined_disclosures = list(l2_a.disclosures) + list(l2_b.disclosures)

    return create_sd_jwt(l2_a.header, new_payload, combined_disclosures, user_private_key)


def _make_split_l3(l2, l2_base_jwt, checkout_jwt, c_hash, merchants, now):
    """Create L3a + L3b for a single mandate pair."""
    agent = get_agent_keys()

    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == merchants[0]["name"])
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    # L3a
    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=merchants[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce="n-l3a",
        aud="https://www.mastercard.com",
        iat=now,
        final_payment=final_payment,
        final_merchant=merchants[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    # L3b
    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce="n-l3b",
        aud="https://tennis-warehouse.com",
        iat=now,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

    return l3a, l3b, l2_payment_ser, l2_checkout_ser


def _make_immediate_pair(now, l1_ser, checkout_items):
    """Create a single-pair immediate L2, returning (l2, checkout_jwt, c_hash)."""
    user = get_user_keys()
    merchant = get_merchant_keys()

    checkout_jwt = create_checkout_jwt(checkout_items, merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        transaction_id=c_hash,
        payment_instrument=PAYMENT_INSTRUMENT,
        currency="USD",
        amount=27999,
        payee=MERCHANTS[0],
    )
    user_mandate = UserMandate(
        nonce="test-imm",
        aud="https://www.agent.com",
        iat=now,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    l2_result = create_layer2_immediate(user_mandate, user.private_key)
    return l2_result.sd_jwt, checkout_jwt, c_hash


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSinglePairBackwardCompat:
    """Existing single-pair flows remain unchanged, pair_results populated."""

    def test_single_pair_autonomous_populates_pair_results(self):
        """Single-pair autonomous chain sets pair_results and mandate_pair_count."""
        issuer = get_issuer_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2, checkout_jwt, c_hash = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )
        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        l3a, l3b, l2_payment_ser, l2_checkout_ser = _make_split_l3(
            l2, l2_base_jwt, checkout_jwt, c_hash, MERCHANTS, now
        )

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            l3_checkout=l3b,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            l2_payment_serialized=l2_payment_ser,
            l2_checkout_serialized=l2_checkout_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert result.mandate_pair_count == 1
        assert len(result.pair_results) == 1
        assert result.pair_results[0].pair_index == 0
        assert result.pair_results[0].checkout_mandate.get("vct") == "mandate.checkout.open.1"
        assert result.pair_results[0].payment_mandate.get("vct") == "mandate.payment.open.1"
        # Legacy fields populated from first pair
        assert result.l3_payment_claims
        assert result.l3_checkout_claims

    def test_single_pair_immediate_populates_pair_results(self):
        """Single-pair immediate chain sets pair_results."""
        issuer = get_issuer_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])

        result = verify_chain(
            l1,
            l2,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert result.mandate_pair_count == 1
        assert len(result.pair_results) == 1
        assert result.pair_results[0].checkout_mandate.get("vct") == "mandate.checkout.1"
        assert result.pair_results[0].payment_mandate.get("vct") == "mandate.payment.1"


class TestTwoPairImmediate:
    """Two-pair immediate mode L2 verification."""

    def test_two_pair_immediate_valid(self):
        """2-pair immediate L2 both pairs verify."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        # Build two single-pair immediate L2s
        l2_a, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])
        l2_b, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "HEA23102", "quantity": 1}])

        # Merge into multi-pair L2
        l2_merged = _merge_l2s(l2_a, l2_b, user.private_key)

        result = verify_chain(
            l1,
            l2_merged,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert result.mandate_pair_count == 2
        assert len(result.pair_results) == 2


class TestTwoPairAutonomous:
    """Two-pair autonomous mode L2 verification."""

    def test_two_pair_autonomous_valid(self):
        """2-pair autonomous L2 + 2 split L3s, all verify."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        # Build two single-pair L2s
        l2_a, checkout_jwt_a, c_hash_a = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )
        l2_b, checkout_jwt_b, c_hash_b = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "HEA23102", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )

        # Merge into multi-pair L2
        l2_merged = _merge_l2s(l2_a, l2_b, user.private_key)
        l2_ser = l2_merged.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        # Find disclosures for pair A (from merged L2)
        payment_disc_a = _find_disclosure(
            l2_merged, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1"
        )
        merchant_disc_a = _find_disclosure(
            l2_merged, lambda v: isinstance(v, dict) and v.get("name") == MERCHANTS[0]["name"]
        )
        checkout_disc_a = _find_disclosure(
            l2_merged, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1"
        )
        item_disc_a = _find_disclosure(l2_merged, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

        # Find disclosures for pair B — need to find the second set
        # Since _find_disclosure returns the first match, we need a different approach
        # for the second pair's mandates. Use disclosure_values to distinguish them.
        all_payment_discs = []
        all_checkout_discs = []
        for ds, dv in zip(l2_merged.disclosures, l2_merged.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict):
                if val.get("vct") == "mandate.payment.open.1":
                    all_payment_discs.append(ds)
                elif val.get("vct") == "mandate.checkout.open.1":
                    all_checkout_discs.append(ds)

        assert len(all_payment_discs) >= 2, "Need 2 payment mandate disclosures"
        assert len(all_checkout_discs) >= 2, "Need 2 checkout mandate disclosures"

        payment_disc_b = all_payment_discs[1]
        checkout_disc_b = all_checkout_discs[1]

        # Find second merchant and item disclosures (they may be duplicates)
        all_merchant_discs = []
        all_item_discs = []
        for ds, dv in zip(l2_merged.disclosures, l2_merged.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and val.get("name") == MERCHANTS[0]["name"]:
                all_merchant_discs.append(ds)
            if isinstance(val, dict) and (val.get("id") in ("BAB86345", "HEA23102")):
                all_item_discs.append(ds)

        merchant_disc_b = all_merchant_discs[1] if len(all_merchant_discs) > 1 else all_merchant_discs[0]
        # For item disc B, find the HEA23102 item
        item_disc_b = _find_disclosure(l2_merged, lambda v: isinstance(v, dict) and v.get("id") == "HEA23102")
        if item_disc_b is None:
            item_disc_b = all_item_discs[1] if len(all_item_discs) > 1 else all_item_discs[0]

        # Build split L3 A
        final_payment_a = FinalPaymentMandate(
            transaction_id=c_hash_a,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_a = create_layer3_payment(
            PaymentL3Mandate(
                nonce="n-l3a-a",
                aud="https://www.mastercard.com",
                iat=now,
                final_payment=final_payment_a,
                final_merchant=MERCHANTS[0],
            ),
            agent.private_key,
            l2_base_jwt,
            payment_disc_a,
            merchant_disc_a,
        )
        l3b_a = create_layer3_checkout(
            CheckoutL3Mandate(
                nonce="n-l3b-a",
                aud="https://tennis-warehouse.com",
                iat=now,
                final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt_a, checkout_hash=c_hash_a),
            ),
            agent.private_key,
            l2_base_jwt,
            checkout_disc_a,
            item_disc_a,
        )

        # Build split L3 B
        final_payment_b = FinalPaymentMandate(
            transaction_id=c_hash_b,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 24999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_b = create_layer3_payment(
            PaymentL3Mandate(
                nonce="n-l3a-b",
                aud="https://www.mastercard.com",
                iat=now,
                final_payment=final_payment_b,
                final_merchant=MERCHANTS[0],
            ),
            agent.private_key,
            l2_base_jwt,
            payment_disc_b,
            merchant_disc_b,
        )
        l3b_b = create_layer3_checkout(
            CheckoutL3Mandate(
                nonce="n-l3b-b",
                aud="https://tennis-warehouse.com",
                iat=now,
                final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt_b, checkout_hash=c_hash_b),
            ),
            agent.private_key,
            l2_base_jwt,
            checkout_disc_b,
            item_disc_b,
        )

        l2_payment_ser_a = build_selective_presentation(l2_base_jwt, [payment_disc_a, merchant_disc_a])
        l2_checkout_ser_a = build_selective_presentation(l2_base_jwt, [checkout_disc_a, item_disc_a])
        l2_payment_ser_b = build_selective_presentation(l2_base_jwt, [payment_disc_b, merchant_disc_b])
        l2_checkout_ser_b = build_selective_presentation(l2_base_jwt, [checkout_disc_b, item_disc_b])

        result = verify_chain(
            l1,
            l2_merged,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            split_l3s=[
                SplitL3(
                    l3_payment=l3a_a,
                    l3_checkout=l3b_a,
                    l2_payment_serialized=l2_payment_ser_a,
                    l2_checkout_serialized=l2_checkout_ser_a,
                ),
                SplitL3(
                    l3_payment=l3a_b,
                    l3_checkout=l3b_b,
                    l2_payment_serialized=l2_payment_ser_b,
                    l2_checkout_serialized=l2_checkout_ser_b,
                ),
            ],
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert result.mandate_pair_count == 2
        assert len(result.pair_results) == 2
        # Legacy fields from first pair
        assert result.l3_payment_claims
        assert result.l3_checkout_claims


class TestSplitL3SwapRejected:
    """Swapping split L3s must fail identity binding."""

    def test_swapped_split_l3s_rejected(self):
        """Swapping split_l3s[0] and split_l3s[1] must fail identity binding."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2_a, checkout_jwt_a, c_hash_a = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )
        l2_b, checkout_jwt_b, c_hash_b = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "HEA23102", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )

        l2_merged = _merge_l2s(l2_a, l2_b, user.private_key)
        l2_ser = l2_merged.serialize()
        l2_base_jwt = l2_ser.split("~")[0]

        # Find disclosures for both pairs
        all_payment_discs = []
        all_checkout_discs = []
        all_merchant_discs = []
        for ds, dv in zip(l2_merged.disclosures, l2_merged.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict):
                if val.get("vct") == "mandate.payment.open.1":
                    all_payment_discs.append(ds)
                elif val.get("vct") == "mandate.checkout.open.1":
                    all_checkout_discs.append(ds)
                elif val.get("name") == MERCHANTS[0]["name"]:
                    all_merchant_discs.append(ds)

        item_disc_a = _find_disclosure(l2_merged, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")
        item_disc_b = _find_disclosure(l2_merged, lambda v: isinstance(v, dict) and v.get("id") == "HEA23102")

        # Build split L3 A
        l3a_a = create_layer3_payment(
            PaymentL3Mandate(
                nonce="n-l3a-a",
                aud="https://www.mastercard.com",
                iat=now,
                final_payment=FinalPaymentMandate(
                    transaction_id=c_hash_a,
                    payee=MERCHANTS[0],
                    payment_amount={"currency": "USD", "amount": 27999},
                    payment_instrument=PAYMENT_INSTRUMENT,
                ),
                final_merchant=MERCHANTS[0],
            ),
            agent.private_key,
            l2_base_jwt,
            all_payment_discs[0],
            all_merchant_discs[0],
        )
        l3b_a = create_layer3_checkout(
            CheckoutL3Mandate(
                nonce="n-l3b-a",
                aud="https://tennis-warehouse.com",
                iat=now,
                final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt_a, checkout_hash=c_hash_a),
            ),
            agent.private_key,
            l2_base_jwt,
            all_checkout_discs[0],
            item_disc_a,
        )

        # Build split L3 B
        merchant_disc_b = all_merchant_discs[1] if len(all_merchant_discs) > 1 else all_merchant_discs[0]
        l3a_b = create_layer3_payment(
            PaymentL3Mandate(
                nonce="n-l3a-b",
                aud="https://www.mastercard.com",
                iat=now,
                final_payment=FinalPaymentMandate(
                    transaction_id=c_hash_b,
                    payee=MERCHANTS[0],
                    payment_amount={"currency": "USD", "amount": 24999},
                    payment_instrument=PAYMENT_INSTRUMENT,
                ),
                final_merchant=MERCHANTS[0],
            ),
            agent.private_key,
            l2_base_jwt,
            all_payment_discs[1],
            merchant_disc_b,
        )
        l3b_b = create_layer3_checkout(
            CheckoutL3Mandate(
                nonce="n-l3b-b",
                aud="https://tennis-warehouse.com",
                iat=now,
                final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt_b, checkout_hash=c_hash_b),
            ),
            agent.private_key,
            l2_base_jwt,
            all_checkout_discs[1],
            item_disc_b,
        )

        l2_payment_ser_a = build_selective_presentation(l2_base_jwt, [all_payment_discs[0], all_merchant_discs[0]])
        l2_checkout_ser_a = build_selective_presentation(l2_base_jwt, [all_checkout_discs[0], item_disc_a])
        l2_payment_ser_b = build_selective_presentation(l2_base_jwt, [all_payment_discs[1], merchant_disc_b])
        l2_checkout_ser_b = build_selective_presentation(l2_base_jwt, [all_checkout_discs[1], item_disc_b])

        pair_a = SplitL3(
            l3_payment=l3a_a,
            l3_checkout=l3b_a,
            l2_payment_serialized=l2_payment_ser_a,
            l2_checkout_serialized=l2_checkout_ser_a,
        )
        pair_b = SplitL3(
            l3_payment=l3a_b,
            l3_checkout=l3b_b,
            l2_payment_serialized=l2_payment_ser_b,
            l2_checkout_serialized=l2_checkout_ser_b,
        )

        # Correct order works
        result_ok = verify_chain(
            l1,
            l2_merged,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            split_l3s=[pair_a, pair_b],
        )
        assert result_ok.valid, f"Correct order failed: {result_ok.errors}"

        # SWAPPED order must fail
        result_swapped = verify_chain(
            l1,
            l2_merged,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            split_l3s=[pair_b, pair_a],
        )
        assert not result_swapped.valid
        assert any("identity mismatch" in e.lower() for e in result_swapped.errors)


class TestSmuggling:
    """Mandate smuggling detection in multi-pair context."""

    def test_duplicate_checkout_hash_rejected(self):
        """Two checkout mandates with same checkout_hash → pairing key collision."""
        from verifiable_intent.crypto.disclosure import create_disclosure

        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        # Build one immediate pair
        l2, checkout_jwt, c_hash = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])

        # Create a second checkout mandate disclosure with the SAME checkout_hash
        smuggled_checkout = {
            "vct": "mandate.checkout.1",
            "checkout_jwt": checkout_jwt,
            "checkout_hash": c_hash,
        }
        new_disc = create_disclosure(None, smuggled_checkout)
        new_ref_hash = hash_disclosure(new_disc)

        # Inject into delegate_payload with its own ref
        new_payload = copy.deepcopy(l2.payload)
        new_payload["delegate_payload"].append({"...": new_ref_hash})
        combined_disclosures = list(l2.disclosures) + [new_disc]
        l2_tampered = create_sd_jwt(l2.header, new_payload, combined_disclosures, user.private_key)

        result = verify_chain(l1, l2_tampered, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("pairing key" in e.lower() or "duplicate" in e.lower() for e in result.errors)

    def test_duplicate_ref_hash_rejected(self):
        """Two delegate_payload entries → same disclosure → smuggling."""
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2, _, _ = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )

        # Find the checkout mandate ref hash
        checkout_ref_hash = None
        for ds, dv in zip(l2.disclosures, l2.disclosure_values):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and val.get("vct") == "mandate.checkout.open.1":
                checkout_ref_hash = hash_disclosure(ds)
                break
        assert checkout_ref_hash is not None

        # Inject duplicate ref
        new_payload = copy.deepcopy(l2.payload)
        new_payload["delegate_payload"].append({"...": checkout_ref_hash})
        l2_tampered = create_sd_jwt(l2.header, new_payload, l2.disclosures, user.private_key)

        dummy_l3 = SdJwt(header={}, payload={}, signature=b"\x00" * 64)
        result = verify_chain(l1, l2_tampered, l3_payment=dummy_l3, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("duplicate disclosure reference" in e.lower() for e in result.errors)


class TestOrphans:
    """Orphaned mandate detection."""

    def test_orphaned_checkout_rejected(self):
        """2 checkouts, 1 payment → orphan error in immediate mode."""
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2_a, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])
        l2_b, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "HEA23102", "quantity": 1}])

        # Take only the checkout from l2_b and payment from l2_a
        # This creates an orphan checkout
        new_payload = copy.deepcopy(l2_a.payload)
        # Add checkout ref from l2_b but NOT its payment ref
        checkout_refs_b = []
        for ref, (ds, dv) in zip(
            l2_b.payload.get("delegate_payload", []),
            zip(l2_b.disclosures, l2_b.disclosure_values),
        ):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and "checkout" in val.get("vct", ""):
                checkout_refs_b.append(ref)

        for ref in checkout_refs_b:
            new_payload["delegate_payload"].append(ref)

        combined_disclosures = list(l2_a.disclosures) + list(l2_b.disclosures)
        l2_merged = create_sd_jwt(l2_a.header, new_payload, combined_disclosures, user.private_key)

        result = verify_chain(l1, l2_merged, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("orphan" in e.lower() for e in result.errors)

    def test_orphaned_payment_rejected(self):
        """1 checkout, 2 payments → orphan error in immediate mode."""
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2_a, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])
        l2_b, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "HEA23102", "quantity": 1}])

        # Take only the payment from l2_b
        new_payload = copy.deepcopy(l2_a.payload)
        payment_refs_b = []
        for ref, (ds, dv) in zip(
            l2_b.payload.get("delegate_payload", []),
            zip(l2_b.disclosures, l2_b.disclosure_values),
        ):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and "payment" in val.get("vct", ""):
                payment_refs_b.append(ref)

        for ref in payment_refs_b:
            new_payload["delegate_payload"].append(ref)

        combined_disclosures = list(l2_a.disclosures) + list(l2_b.disclosures)
        l2_merged = create_sd_jwt(l2_a.header, new_payload, combined_disclosures, user.private_key)

        result = verify_chain(l1, l2_merged, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("orphan" in e.lower() for e in result.errors)


class TestMismatchedKeys:
    """Mismatched pairing keys."""

    def test_mismatched_checkout_hash_transaction_id(self):
        """checkout_hash != transaction_id → orphan/no-match."""
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2_a, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])
        l2_b, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "HEA23102", "quantity": 1}])

        # Take checkout from l2_a and payment from l2_b — they won't match
        new_payload = copy.deepcopy(l2_a.payload)

        # Remove payment from l2_a, add payment from l2_b
        # First, figure out which refs are checkout vs payment
        checkout_refs_a = []
        payment_refs_b = []
        for ref, (ds, dv) in zip(
            l2_a.payload.get("delegate_payload", []),
            zip(l2_a.disclosures, l2_a.disclosure_values),
        ):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and "checkout" in val.get("vct", ""):
                checkout_refs_a.append(ref)

        for ref, (ds, dv) in zip(
            l2_b.payload.get("delegate_payload", []),
            zip(l2_b.disclosures, l2_b.disclosure_values),
        ):
            val = dv[-1] if dv else None
            if isinstance(val, dict) and "payment" in val.get("vct", ""):
                payment_refs_b.append(ref)

        new_payload["delegate_payload"] = checkout_refs_a + payment_refs_b
        combined_disclosures = list(l2_a.disclosures) + list(l2_b.disclosures)
        l2_mixed = create_sd_jwt(l2_a.header, new_payload, combined_disclosures, user.private_key)

        result = verify_chain(l1, l2_mixed, l1_serialized=l1_ser, skip_issuer_verification=True)
        assert not result.valid
        assert any("orphan" in e.lower() for e in result.errors)


class TestSplitL3sExclusivity:
    """Mutual exclusion between split_l3s and l3_payment/l3_checkout."""

    def test_split_l3s_and_l3_payment_exclusive(self):
        """Both split_l3s and l3_payment provided → error."""
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()
        l2, _, _ = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )

        dummy_l3 = SdJwt(header={}, payload={}, signature=b"\x00" * 64)
        result = verify_chain(
            l1,
            l2,
            l3_payment=dummy_l3,
            split_l3s=[SplitL3(l3_payment=dummy_l3)],
            l1_serialized=l1_ser,
            skip_issuer_verification=True,
        )
        assert not result.valid
        assert any("cannot provide both" in e.lower() for e in result.errors)


class TestSplitL3CountMismatch:
    """split L3 count must match mandate pair count."""

    def test_split_l3_count_mismatch(self):
        """len(split_l3s) != len(mandate_pairs) → error."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        # Build two-pair L2
        l2_a, _, _ = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "BAB86345", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )
        l2_b, _, _ = _make_single_pair_l2(
            now,
            l1_ser,
            [{"sku": "HEA23102", "quantity": 1}],
            MERCHANTS,
            ACCEPTABLE_ITEMS,
            PAYMENT_INSTRUMENT,
        )
        l2_merged = _merge_l2s(l2_a, l2_b, user.private_key)

        # Provide only 1 split L3 for 2 mandate pairs
        dummy_l3 = SdJwt(header={}, payload={}, signature=b"\x00" * 64)
        result = verify_chain(
            l1,
            l2_merged,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
            split_l3s=[SplitL3(l3_payment=dummy_l3)],
        )
        assert not result.valid
        assert any("pair count" in e.lower() for e in result.errors)


class TestThreePairImmediate:
    """Three-pair L2 validates correctly."""

    def test_three_pair_immediate(self):
        """3-pair immediate L2 validates correctly."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(now)
        l1_ser = l1.serialize()

        l2_a, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 1}])
        l2_b, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "HEA23102", "quantity": 1}])
        # Third pair: same product, different quantity to get a different checkout_hash
        l2_c, _, _ = _make_immediate_pair(now, l1_ser, [{"sku": "BAB86345", "quantity": 2}])

        # Merge all three
        l2_ab = _merge_l2s(l2_a, l2_b, user.private_key)
        l2_abc = _merge_l2s(l2_ab, l2_c, user.private_key)

        result = verify_chain(
            l1,
            l2_abc,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1_ser,
        )
        assert result.valid, f"Chain verification failed: {result.errors}"
        assert result.mandate_pair_count == 3
        assert len(result.pair_results) == 3
