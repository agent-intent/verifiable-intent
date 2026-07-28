"""Tests for verification hardening (v2).

1. vct validation on L1
2. checkout_hash integrity check wired into verify_chain
3. Dual-mandate cnf.jwk cross-check
4. _sd_alg validation at each layer
5. Model-level mode enforcement (__post_init__ guards)
6. Algorithm confusion rejection (alg: "none", alg: "HS256")
7. Signature byte mutation detection
8. exp=0 treated as expired, not silently skipped
9. typ header validation (confused deputy prevention)
"""

from __future__ import annotations

import time

import pytest

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
    UserMandate,
    create_layer1,
    create_layer2_autonomous,
    create_layer3_checkout,
    create_layer3_payment,
    verify_chain,
)
from verifiable_intent.crypto.disclosure import build_selective_presentation, create_disclosure, hash_bytes
from verifiable_intent.crypto.sd_jwt import SdJwt, decode_sd_jwt
from verifiable_intent.crypto.signing import generate_es256_key, public_key_to_jwk


def _find_disclosure(sd_jwt, predicate):
    """Find a disclosure string in an SdJwt where value matches predicate."""
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


def _make_l1(issuer, user, now):
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=now,
        exp=now + 86400,
        aud="https://wallet.example.com",
        email="test@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_l1_custom(issuer, user, now, iat=None, exp=None):
    cred = IssuerCredential(
        iss="https://www.mastercard.com",
        sub="userCredentialId",
        iat=iat if iat is not None else now,
        exp=exp if exp is not None else now + 86400,
        aud="https://wallet.example.com",
        email="test@example.com",
        pan_last_four="1234",
        scheme="Mastercard",
        cnf_jwk=user.public_jwk,
    )
    return create_layer1(cred, issuer.private_key)


def _make_immediate_l2(user, l1, now):
    """Build an immediate L2 with final values for testing."""
    from verifiable_intent.issuance.user import create_layer2_immediate

    merchant = get_merchant_keys()
    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.1",
        checkout_jwt=checkout_jwt,
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.1",
        currency="USD",
        amount=27999,
        payee=MERCHANTS[0],
        payment_instrument=PAYMENT_INSTRUMENT,
        transaction_id=c_hash,
    )
    user_mandate = UserMandate(
        nonce="n-imm",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 900,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
    )
    return create_layer2_immediate(user_mandate, user.private_key).sd_jwt


def _make_autonomous_chain(
    now=None,
    l1_iat=None,
    l1_exp=None,
    include_checkout_cnf: bool = True,
    include_payment_cnf: bool = True,
):
    """Build a valid v2 3-layer autonomous chain. Returns (l1, l2, l3a, l3b, keys)."""
    issuer = get_issuer_keys()
    user = get_user_keys()
    agent = get_agent_keys()
    merchant = get_merchant_keys()
    if now is None:
        now = int(time.time())

    l1 = _make_l1_custom(issuer, user, now, iat=l1_iat, exp=l1_exp)
    l1_ser = l1.serialize()

    checkout_mandate = CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=agent.public_jwk if include_checkout_cnf else None,
        cnf_kid="agent-key-1" if include_checkout_cnf else None,
        constraints=[
            AllowedMerchantConstraint(allowed=MERCHANTS),
            CheckoutLineItemsConstraint(
                items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
            ),
        ],
    )
    payment_mandate = PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=agent.public_jwk if include_payment_cnf else None,
        cnf_kid="agent-key-1" if include_payment_cnf else None,
        payment_instrument=PAYMENT_INSTRUMENT,
        constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000)],
    )
    user_mandate = UserMandate(
        nonce="n-auto",
        aud="https://www.agent.com",
        iat=now,
        iss="https://wallet.example.com",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1_ser.encode("ascii")),
        checkout_mandate=checkout_mandate,
        payment_mandate=payment_mandate,
        merchants=MERCHANTS,
        acceptable_items=ACCEPTABLE_ITEMS,
    )
    l2 = create_layer2_autonomous(user_mandate, user.private_key)
    l2_ser = l2.serialize()
    l2_base_jwt = l2_ser.split("~")[0]

    payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")

    checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
    c_hash = checkout_hash_from_jwt(checkout_jwt)

    final_payment = FinalPaymentMandate(
        transaction_id=c_hash,
        payee=MERCHANTS[0],
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PAYMENT_INSTRUMENT,
    )
    l3a_mandate = PaymentL3Mandate(
        nonce="n-l3a",
        aud="https://www.mastercard.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_payment=final_payment,
        final_merchant=MERCHANTS[0],
    )
    l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

    final_checkout = FinalCheckoutMandate(
        checkout_jwt=checkout_jwt,
        checkout_hash=c_hash,
    )
    l3b_mandate = CheckoutL3Mandate(
        nonce="n-l3b",
        aud="https://tennis-warehouse.com",
        iat=now,
        iss="https://agent.example.com",
        exp=now + 300,
        final_checkout=final_checkout,
    )
    l3b = create_layer3_checkout(l3b_mandate, agent.private_key, l2_base_jwt, checkout_disc, item_disc)

    l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])
    l2_checkout_ser = build_selective_presentation(l2_base_jwt, [checkout_disc, item_disc])

    return {
        "l1": l1,
        "l2": l2,
        "l3a": l3a,
        "l3b": l3b,
        "l1_ser": l1_ser,
        "l2_ser": l2_ser,
        "l2_payment_ser": l2_payment_ser,
        "l2_checkout_ser": l2_checkout_ser,
        "issuer": issuer,
        "user": user,
        "agent": agent,
    }


# --- Fix #1: vct validation ---


class TestVctValidation:
    def test_wrong_vct_rejected(self):
        """L1 with wrong vct must be rejected."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(issuer, user, now)

        # Tamper with vct
        l1_tampered = SdJwt(
            header=l1.header,
            payload={**l1.payload, "vct": "wrong_type"},
            signature=l1.signature,
            disclosures=l1.disclosures,
            disclosure_values=l1.disclosure_values,
        )

        l2 = _make_immediate_l2(user, l1, now)

        # Skip issuer sig check to isolate vct check
        result = verify_chain(l1_tampered, l2, skip_issuer_verification=True)
        assert not result.valid
        assert any("vct" in e for e in result.errors)


# --- Fix #3: Dual-mandate cnf.jwk cross-check ---


class TestDualMandateCnfCrossCheck:
    def test_mismatched_cnf_keys_rejected(self):
        """Checkout and payment mandates with different cnf.jwk must fail."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        agent = get_agent_keys()
        other_key = generate_es256_key()
        now = int(time.time())
        l1 = _make_l1(issuer, user, now)

        checkout_mandate = CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent.public_jwk,
            cnf_kid="agent-key-1",
            constraints=[
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-item-1", "acceptable_items": ACCEPTABLE_ITEMS[:1], "quantity": 1}],
                ),
            ],
        )
        payment_mandate = PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=public_key_to_jwk(other_key),  # Different key!
            cnf_kid="agent-key-1",
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l2 = create_layer2_autonomous(
            UserMandate(
                nonce="n2",
                aud="https://www.agent.com",
                iat=now,
                iss="https://wallet.example.com",
                exp=now + 86400,
                mode=MandateMode.AUTONOMOUS,
                sd_hash=hash_bytes(l1.serialize().encode("ascii")),
                checkout_mandate=checkout_mandate,
                payment_mandate=payment_mandate,
                merchants=MERCHANTS,
                acceptable_items=ACCEPTABLE_ITEMS,
            ),
            user.private_key,
        )

        l2_ser = l2.serialize()
        l2_base_jwt = l2_ser.split("~")[0]
        merchant = get_merchant_keys()

        payment_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
        merchant_disc = _find_disclosure(l2, lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")

        checkout_jwt = create_checkout_jwt([{"sku": "BAB86345", "quantity": 1}], merchant)
        c_hash = checkout_hash_from_jwt(checkout_jwt)

        final_payment = FinalPaymentMandate(
            transaction_id=c_hash,
            payee=MERCHANTS[0],
            payment_amount={"currency": "USD", "amount": 27999},
            payment_instrument=PAYMENT_INSTRUMENT,
        )
        l3a_mandate = PaymentL3Mandate(
            nonce="n3",
            aud="https://www.mastercard.com",
            iat=now,
            iss="https://agent.example.com",
            exp=now + 300,
            final_payment=final_payment,
            final_merchant=MERCHANTS[0],
        )
        l3a = create_layer3_payment(l3a_mandate, agent.private_key, l2_base_jwt, payment_disc, merchant_disc)

        l2_payment_ser = build_selective_presentation(l2_base_jwt, [payment_disc, merchant_disc])

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3a,
            issuer_public_key=issuer.public_key,
            l1_serialized=l1.serialize(),
            l2_serialized=l2_ser,
            l2_payment_serialized=l2_payment_ser,
        )
        assert not result.valid
        assert any("identical" in e or "differ" in e for e in result.errors)

    @staticmethod
    def _with_extra_disclosure(l2, disclosure: str):
        serialized = l2.serialize()
        with_extra = f"{serialized[:-1]}~{disclosure}~"
        return decode_sd_jwt(with_extra)

    def test_missing_cnf_on_disclosed_open_mandate_rejected(self):
        """If both open mandates are disclosed, each must carry cnf.jwk."""
        chain = _make_autonomous_chain(include_payment_cnf=False)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("payment open mandate missing cnf.jwk" in e.lower() for e in result.errors), result.errors

    def test_cnf_in_unreferenced_mandate_disclosure_rejected(self):
        """cnf.jwk in an unreferenced disclosure must not satisfy extraction."""
        chain = _make_autonomous_chain(include_checkout_cnf=False, include_payment_cnf=False)
        fake_mandate_disc = create_disclosure(
            None,
            {
                "vct": "mandate.checkout.open.1",
                "cnf": {"jwk": chain["agent"].public_jwk},
            },
        )
        tampered_l2 = self._with_extra_disclosure(chain["l2"], fake_mandate_disc)

        result = verify_chain(
            chain["l1"],
            tampered_l2,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("missing cnf.jwk" in e.lower() for e in result.errors), result.errors

    def test_cnf_in_non_mandate_disclosure_rejected(self):
        """cnf.jwk in merchant/item disclosures must not be used for delegation."""
        chain = _make_autonomous_chain(include_checkout_cnf=False, include_payment_cnf=False)
        fake_merchant_disc = create_disclosure(
            None,
            {
                "id": "merchant-injected",
                "name": "Injected Merchant",
                "website": "https://example.invalid",
                "cnf": {"jwk": chain["agent"].public_jwk},
            },
        )
        tampered_l2 = self._with_extra_disclosure(chain["l2"], fake_merchant_disc)

        result = verify_chain(
            chain["l1"],
            tampered_l2,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("missing cnf.jwk" in e.lower() for e in result.errors), result.errors


# --- Fix #4: _sd_alg validation ---


class TestSdAlgValidation:
    def test_wrong_sd_alg_l1_rejected(self):
        """L1 with _sd_alg != sha-256 must be rejected."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(issuer, user, now)

        l1_tampered = SdJwt(
            header=l1.header,
            payload={**l1.payload, "_sd_alg": "sha-512"},
            signature=l1.signature,
            disclosures=l1.disclosures,
            disclosure_values=l1.disclosure_values,
        )

        l2 = _make_immediate_l2(user, l1, now)

        result = verify_chain(l1_tampered, l2, skip_issuer_verification=True)
        assert not result.valid
        assert any("_sd_alg" in e and "sha-512" in e for e in result.errors)


# --- Fix #5: Model-level mode enforcement ---


class TestMandateModeEnforcement:
    def test_checkout_mandate_hybrid_rejected(self):
        """CheckoutMandate with both cnf_jwk and checkout_jwt raises ValueError."""
        with pytest.raises(ValueError, match="cannot have both"):
            CheckoutMandate(cnf_jwk={"x": "a"}, checkout_jwt="some-jwt-string")

    def test_payment_mandate_hybrid_rejected(self):
        """PaymentMandate with both cnf_jwk and amount raises ValueError."""
        with pytest.raises(ValueError, match="cannot have both"):
            PaymentMandate(cnf_jwk={"x": "a"}, amount=100)


# --- D1: Algorithm confusion rejection ---


class TestAlgValidation:
    def test_alg_none_rejected(self):
        """alg: 'none' on L1 must be rejected."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header={**chain["l1"].header, "alg": "none"},
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("alg" in e for e in result.errors)

    def test_alg_hs256_rejected(self):
        """alg: 'HS256' on L1 must be rejected."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header={**chain["l1"].header, "alg": "HS256"},
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("alg" in e for e in result.errors)


# --- D2: Signature byte mutation ---


class TestSignatureMutation:
    def test_l1_signature_mutation_detected(self):
        """Flipping a bit in L1 signature must fail verification."""
        chain = _make_autonomous_chain()
        mutated_sig = bytearray(chain["l1"].signature)
        mutated_sig[0] ^= 0x01
        l1_mutated = SdJwt(
            header=chain["l1"].header,
            payload=chain["l1"].payload,
            signature=bytes(mutated_sig),
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(
            l1_mutated,
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("L1 signature" in e for e in result.errors)

    def test_l2_signature_mutation_detected(self):
        """Flipping a bit in L2 signature must fail verification."""
        chain = _make_autonomous_chain()
        mutated_sig = bytearray(chain["l2"].signature)
        mutated_sig[0] ^= 0x01
        l2_mutated = SdJwt(
            header=chain["l2"].header,
            payload=chain["l2"].payload,
            signature=bytes(mutated_sig),
            disclosures=chain["l2"].disclosures,
            disclosure_values=chain["l2"].disclosure_values,
        )
        result = verify_chain(
            chain["l1"],
            l2_mutated,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("L2 signature" in e for e in result.errors)

    def test_l3_signature_mutation_detected(self):
        """Flipping a bit in L3a signature must fail verification."""
        chain = _make_autonomous_chain()
        mutated_sig = bytearray(chain["l3a"].signature)
        mutated_sig[0] ^= 0x01
        l3_mutated = SdJwt(
            header=chain["l3a"].header,
            payload=chain["l3a"].payload,
            signature=bytes(mutated_sig),
            disclosures=chain["l3a"].disclosures,
            disclosure_values=chain["l3a"].disclosure_values,
        )
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=l3_mutated,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("signature" in e.lower() for e in result.errors)


# --- D3: exp=0 handling ---


class TestExpZero:
    def test_l1_exp_zero_treated_as_expired(self):
        """exp=0 on L1 must be treated as expired (epoch), not skipped."""
        chain = _make_autonomous_chain(l1_exp=0)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("expired" in e.lower() or "exp" in e.lower() for e in result.errors)


# --- D4: typ header validation (confused deputy prevention) ---


class TestTypValidation:
    def test_wrong_l1_typ_rejected(self):
        """L1 with wrong typ must be rejected."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header={**chain["l1"].header, "typ": "jwt"},
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("typ" in e for e in result.errors)

    def test_wrong_l3_typ_rejected(self):
        """L3 with wrong typ must be rejected (re-signed to isolate typ check)."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        chain = _make_autonomous_chain()
        bad_header = {**chain["l3a"].header, "typ": "sd+jwt"}
        l3_bad_typ = create_sd_jwt(
            bad_header, chain["l3a"].payload, chain["l3a"].disclosures, chain["agent"].private_key
        )
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=l3_bad_typ,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("typ" in e for e in result.errors)


# --- D5: Type confusion defenses ---


class TestTypeConfusion:
    def test_non_string_alg_rejected(self):
        """Non-string alg (e.g. list) must be rejected, not crash."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header={**chain["l1"].header, "alg": ["ES256"]},
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("alg" in e for e in result.errors)

    def test_non_string_typ_rejected(self):
        """Non-string typ (e.g. int) must be rejected, not crash."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header={**chain["l1"].header, "typ": 42},
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("typ" in e for e in result.errors)

    def test_non_numeric_exp_rejected(self):
        """Non-numeric exp (e.g. string) must be rejected, not crash."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "exp": "never"},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("expired" in e.lower() or "exp" in e.lower() for e in result.errors)

    def test_dict_exp_rejected(self):
        """Dict exp must be rejected, not crash with TypeError."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "exp": {"value": 9999999999}},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("expired" in e.lower() or "exp" in e.lower() for e in result.errors)

    def test_nan_exp_rejected(self):
        """NaN exp must be rejected, not crash with ValueError on int()."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "exp": float("nan")},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("expired" in e.lower() or "exp" in e.lower() for e in result.errors)

    def test_non_dict_header_rejected(self):
        """Non-dict header (e.g. list) must be rejected, not crash with AttributeError."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=["ES256", "sd+jwt"],  # type: ignore[arg-type]
            payload=chain["l1"].payload,
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("header" in e.lower() for e in result.errors)


# --- Fix: in-memory mutation must not bypass signature verification ---


class TestMutationDetection:
    def test_payload_mutation_fails_signature(self):
        """Mutating payload after decode must cause signature verification to fail."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())
        l1 = _make_l1(issuer, user, now)

        from verifiable_intent.crypto.sd_jwt import verify_sd_jwt_signature

        assert verify_sd_jwt_signature(l1, issuer.public_key)

        attacker_key = generate_es256_key()
        l1.payload["cnf"] = {"jwk": public_key_to_jwk(attacker_key)}

        assert not verify_sd_jwt_signature(l1, issuer.public_key)

    def test_mutated_cnf_rejected_by_chain(self):
        """Full chain verification must reject L1 with mutated cnf."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        attacker_key = generate_es256_key()
        now = int(time.time())
        l1 = _make_l1(issuer, user, now)

        l1.payload["cnf"] = {"jwk": public_key_to_jwk(attacker_key)}

        l2 = _make_immediate_l2(user, l1, now)

        result = verify_chain(l1, l2, issuer_public_key=issuer.public_key)
        assert not result.valid
        assert any("L1 signature" in e for e in result.errors)


# --- Fix: decode_sd_jwt must raise ValueError on malformed JWT ---


class TestMalformedJwtParsing:
    def test_decode_sd_jwt_malformed_raises_valueerror(self):
        """Malformed JWT with too few parts must raise ValueError, not IndexError."""
        with pytest.raises(ValueError):
            decode_sd_jwt("bad~")

    def test_decode_sd_jwt_single_segment_raises_valueerror(self):
        """JWT with no dots must raise ValueError."""
        with pytest.raises(ValueError):
            decode_sd_jwt("nodots~disc1~")

    def test_decode_sd_jwt_bad_base64_raises_valueerror(self):
        """Malformed base64 payload must raise ValueError, not binascii.Error."""
        with pytest.raises(ValueError):
            decode_sd_jwt("a.b.c~")


# --- iat lower-bound validation ---


class TestIatFutureDated:
    def test_l1_iat_future_rejected(self):
        """L1 with iat far in the future must be rejected."""
        now = int(time.time())
        chain = _make_autonomous_chain(now=now, l1_iat=now + 3600)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("future" in e.lower() and "iat" in e.lower() for e in result.errors)

    def test_l1_iat_at_skew_boundary_accepted(self):
        """L1 with iat exactly at now + clock_skew should be accepted."""
        now = int(time.time())
        skew = 300
        chain = _make_autonomous_chain(now=now, l1_iat=now + skew)
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            clock_skew_seconds=skew,
        )
        assert result.valid

    def test_l1_iat_string_rejected(self):
        """Non-numeric iat (string) must be rejected."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "iat": "tomorrow"},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("future" in e.lower() and "iat" in e.lower() for e in result.errors)

    def test_l1_iat_nan_rejected(self):
        """NaN iat must be rejected."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "iat": float("nan")},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("future" in e.lower() and "iat" in e.lower() for e in result.errors)

    def test_l1_iat_bool_rejected(self):
        """Boolean iat must be rejected (bool is subclass of int in Python)."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "iat": True},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("iat" in e.lower() for e in result.errors)

    def test_l1_exp_bool_rejected(self):
        """Boolean exp must be rejected (bool is subclass of int in Python)."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "exp": True},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("expired" in e.lower() or "exp" in e.lower() for e in result.errors)

    def test_l1_iat_fractional_past_skew_rejected(self):
        """iat fractionally past skew boundary must be rejected, not truncated."""
        now = int(time.time())
        skew = 300
        chain = _make_autonomous_chain(now=now)
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "iat": now + skew + 0.9},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], clock_skew_seconds=skew, skip_issuer_verification=True)
        assert not result.valid
        assert any("future" in e.lower() and "iat" in e.lower() for e in result.errors)

    def test_l1_iat_huge_integer_rejected_without_overflow(self):
        """Huge integer iat should reject cleanly, not raise OverflowError."""
        chain = _make_autonomous_chain()
        l1_tampered = SdJwt(
            header=chain["l1"].header,
            payload={**chain["l1"].payload, "iat": 10**400},
            signature=chain["l1"].signature,
            disclosures=chain["l1"].disclosures,
            disclosure_values=chain["l1"].disclosure_values,
        )
        result = verify_chain(l1_tampered, chain["l2"], skip_issuer_verification=True)
        assert not result.valid
        assert any("future" in e.lower() and "iat" in e.lower() for e in result.errors)

    def test_l2_top_level_iat_future_rejected(self):
        """Future-dated top-level L2 iat must be rejected (re-signed to isolate iat check)."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        chain = _make_autonomous_chain(now=now)
        bad_payload = {**chain["l2"].payload, "iat": now + 7200}
        l2_tampered = create_sd_jwt(chain["l2"].header, bad_payload, chain["l2"].disclosures, chain["user"].private_key)
        result = verify_chain(
            chain["l1"],
            l2_tampered,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("l2" in e.lower() and "iat" in e.lower() and "future" in e.lower() for e in result.errors)

    def test_l2_top_level_iat_at_skew_boundary_accepted(self):
        """L2 with top-level iat exactly at now + clock_skew should be accepted."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        skew = 300
        chain = _make_autonomous_chain(now=now)
        boundary_payload = {**chain["l2"].payload, "iat": now + skew}
        l2_at_boundary = create_sd_jwt(
            chain["l2"].header, boundary_payload, chain["l2"].disclosures, chain["user"].private_key
        )
        result = verify_chain(
            chain["l1"],
            l2_at_boundary,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            clock_skew_seconds=skew,
        )
        assert not any("l2" in e.lower() and "iat" in e.lower() and "future" in e.lower() for e in result.errors)

    def test_l3_top_level_iat_future_rejected(self):
        """Future-dated top-level L3 iat must be rejected (re-signed to isolate iat check)."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        chain = _make_autonomous_chain(now=now)
        bad_payload = {**chain["l3a"].payload, "iat": now + 7200}
        l3_tampered = create_sd_jwt(
            chain["l3a"].header, bad_payload, chain["l3a"].disclosures, chain["agent"].private_key
        )
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=l3_tampered,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("l3" in e.lower() and "iat" in e.lower() and "future" in e.lower() for e in result.errors)

    def test_l3_top_level_iat_at_skew_boundary_accepted(self):
        """L3 with top-level iat exactly at now + clock_skew should be accepted."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        skew = 300
        chain = _make_autonomous_chain(now=now)
        boundary_payload = {**chain["l3a"].payload, "iat": now + skew}
        l3_at_boundary = create_sd_jwt(
            chain["l3a"].header, boundary_payload, chain["l3a"].disclosures, chain["agent"].private_key
        )
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=l3_at_boundary,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
            clock_skew_seconds=skew,
        )
        assert not any("l3" in e.lower() and "iat" in e.lower() and "future" in e.lower() for e in result.errors)


# --- L2/L3 expiration tests ---


class TestL2L3Expiration:
    def test_l2_expired_fails(self):
        """L2 with exp in the past must be rejected."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        chain = _make_autonomous_chain(now=now)
        # Re-sign L2 with exp in the past
        bad_payload = {**chain["l2"].payload, "exp": now - 3600}
        l2_expired = create_sd_jwt(chain["l2"].header, bad_payload, chain["l2"].disclosures, chain["user"].private_key)
        result = verify_chain(
            chain["l1"],
            l2_expired,
            l3_payment=chain["l3a"],
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("l2" in e.lower() and "expired" in e.lower() for e in result.errors)

    def test_l3_expired_fails(self):
        """L3 with exp in the past must be rejected."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        chain = _make_autonomous_chain(now=now)
        # Re-sign L3 with exp in the past
        bad_payload = {**chain["l3a"].payload, "exp": now - 3600}
        l3_expired = create_sd_jwt(
            chain["l3a"].header, bad_payload, chain["l3a"].disclosures, chain["agent"].private_key
        )
        result = verify_chain(
            chain["l1"],
            chain["l2"],
            l3_payment=l3_expired,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert not result.valid
        assert any("l3" in e.lower() and "expired" in e.lower() for e in result.errors)

    def test_l2_l3_exp_absent_passes(self):
        """L2 and L3 with no exp field should not fail on expiration (backward compat)."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        now = int(time.time())
        chain = _make_autonomous_chain(now=now)
        # Re-sign L2 without exp
        l2_payload_no_exp = {k: v for k, v in chain["l2"].payload.items() if k != "exp"}
        l2_no_exp = create_sd_jwt(
            chain["l2"].header, l2_payload_no_exp, chain["l2"].disclosures, chain["user"].private_key
        )
        # Re-sign L3 without exp
        l3_payload_no_exp = {k: v for k, v in chain["l3a"].payload.items() if k != "exp"}
        l3_no_exp = create_sd_jwt(
            chain["l3a"].header, l3_payload_no_exp, chain["l3a"].disclosures, chain["agent"].private_key
        )
        result = verify_chain(
            chain["l1"],
            l2_no_exp,
            l3_payment=l3_no_exp,
            issuer_public_key=chain["issuer"].public_key,
            l1_serialized=chain["l1_ser"],
            l2_serialized=chain["l2_ser"],
            l2_payment_serialized=chain["l2_payment_ser"],
        )
        assert result.valid, f"Chain should pass without L2/L3 exp: {result.errors}"
        assert not any("expired" in e.lower() for e in result.errors)


# --- Quality Review Round 2: WS2 hardening tests ---


class TestEmptyMandateSet:
    """P1-C2: Empty mandate set must be rejected in both modes."""

    def test_immediate_empty_delegates_rejected(self):
        """Immediate mode L2 with no mandate disclosures returns error."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        l1 = _make_l1(issuer, user, now)

        # Build an L2 with no mandates (empty delegate_payload)
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        l2_payload = {
            "nonce": "n-empty",
            "aud": "https://www.agent.com",
            "iat": now,
            "sd_hash": hash_bytes(l1.serialize().encode("ascii")),
            "mode": "immediate",
            "delegate_payload": [],
        }
        l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
        l2 = create_sd_jwt(l2_header, l2_payload, [], user.private_key)

        result = verify_chain(l1, l2, issuer_public_key=issuer.public_key)
        assert not result.valid
        assert any("zero mandate" in e.lower() for e in result.errors)

    def test_autonomous_empty_delegates_rejected(self):
        """L2 with no mandate disclosures returns 'zero mandate' error.
        Mode is inferred from VCTs; with empty delegate_payload (no open or final VCTs),
        is_autonomous defaults to False and a typ=kb-sd-jwt header is expected.
        The empty-mandate error fires at the pairing stage."""
        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        l1 = _make_l1(issuer, user, now)

        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        l2_payload = {
            "nonce": "n-empty",
            "aud": "https://www.agent.com",
            "iat": now,
            "sd_hash": hash_bytes(l1.serialize().encode("ascii")),
            "delegate_payload": [],
        }
        # No open or final VCTs → mode inferred as immediate → expect kb-sd-jwt typ
        l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
        l2 = create_sd_jwt(l2_header, l2_payload, [], user.private_key)

        result = verify_chain(l1, l2, issuer_public_key=issuer.public_key)
        assert not result.valid
        assert any("zero mandate" in e.lower() for e in result.errors)


class TestMalformedJwk:
    """P1-C3: Malformed cnf.jwk must return clean error, not crash."""

    def test_l1_cnf_jwk_missing_x(self):
        """L1 with cnf.jwk missing 'x' returns error, not KeyError."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        # Build L1 with malformed cnf.jwk (missing x coordinate)
        l1_payload = {
            "iss": "https://www.mastercard.com",
            "sub": "test",
            "iat": now,
            "exp": now + 86400,
            "vct": "https://credentials.mastercard.com/card",
            "pan_last_four": "1234",
            "scheme": "Mastercard",
            "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "y": user.public_jwk["y"]}},
        }
        l1_header = {"alg": "ES256", "typ": "sd+jwt"}
        l1 = create_sd_jwt(l1_header, l1_payload, [], issuer.private_key)

        # Build a minimal L2
        l2_payload = {
            "nonce": "n-test",
            "aud": "test",
            "iat": now,
            "sd_hash": hash_bytes(l1.serialize().encode("ascii")),
            "delegate_payload": [],
        }
        l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
        l2 = create_sd_jwt(l2_header, l2_payload, [], user.private_key)

        result = verify_chain(l1, l2, skip_issuer_verification=True)
        assert not result.valid
        assert any("malformed" in e.lower() for e in result.errors)

    def test_l1_cnf_jwk_bad_base64(self):
        """L1 with cnf.jwk containing invalid base64 returns error, not crash."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        l1_payload = {
            "iss": "https://www.mastercard.com",
            "sub": "test",
            "iat": now,
            "exp": now + 86400,
            "vct": "https://credentials.mastercard.com/card",
            "pan_last_four": "1234",
            "scheme": "Mastercard",
            "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "!!!invalid!!!", "y": "!!!bad!!!"}},
        }
        l1_header = {"alg": "ES256", "typ": "sd+jwt"}
        l1 = create_sd_jwt(l1_header, l1_payload, [], issuer.private_key)

        l2_payload = {
            "nonce": "n-test",
            "aud": "test",
            "iat": now,
            "sd_hash": hash_bytes(l1.serialize().encode("ascii")),
            "delegate_payload": [],
        }
        l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
        l2 = create_sd_jwt(l2_header, l2_payload, [], user.private_key)

        result = verify_chain(l1, l2, skip_issuer_verification=True)
        assert not result.valid
        assert any("malformed" in e.lower() for e in result.errors)


class TestUnrecognizedVct:
    """P1-C1: Unrecognized VCTs in delegate_payload tracked in checks_skipped."""

    def test_unrecognized_vct_tracked(self):
        """Mandate with unknown VCT is reported in checks_skipped."""
        from verifiable_intent.crypto.disclosure import create_disclosure
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        issuer = get_issuer_keys()
        user = get_user_keys()
        now = int(time.time())

        l1 = _make_l1(issuer, user, now)
        l1_ser = l1.serialize()

        # Create a disclosure with an unrecognized VCT
        unknown_mandate = {"vct": "mandate.checkout.open.99", "data": "test"}
        disc_str = create_disclosure("unknown_mandate", unknown_mandate)
        from verifiable_intent.crypto.disclosure import hash_disclosure

        disc_hash = hash_disclosure(disc_str)

        l2_payload = {
            "nonce": "n-test",
            "aud": "test",
            "iat": now,
            "sd_hash": hash_bytes(l1_ser.encode("ascii")),
            "delegate_payload": [{"...": disc_hash}],
        }
        l2_header = {"alg": "ES256", "typ": "kb-sd-jwt"}
        l2 = create_sd_jwt(l2_header, l2_payload, [disc_str], user.private_key)

        result = verify_chain(l1, l2, issuer_public_key=issuer.public_key)
        assert not result.valid  # Will fail because zero recognized mandates
        assert any("unrecognized_vct" in s for s in result.checks_skipped)


# --- Fix #10: L3 cnf rejection ---


class TestL3CnfRejection:
    """L3 payloads MUST NOT contain cnf (terminal delegation, no further key binding)."""

    def test_l3_payment_with_cnf_rejected(self):
        """L3a with cnf claim must be rejected."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        chain = _make_autonomous_chain()
        agent = chain["agent"]

        # Inject cnf into L3a payload
        bad_payload = {**chain["l3a"].payload, "cnf": {"jwk": agent.public_jwk}}
        l3a_tampered = create_sd_jwt(chain["l3a"].header, bad_payload, chain["l3a"].disclosures, agent.private_key)

        from verifiable_intent import SplitL3

        result = verify_chain(
            chain["l1"],
            chain["l2"],
            split_l3s=[SplitL3(l3_payment=l3a_tampered, l3_checkout=chain["l3b"])],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            issuer_public_key=chain["issuer"].public_key,
        )
        assert not result.valid
        assert any("MUST NOT contain cnf" in e for e in result.errors)

    def test_l3_checkout_with_cnf_rejected(self):
        """L3b with cnf claim must be rejected."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        chain = _make_autonomous_chain()
        agent = chain["agent"]

        # Inject cnf into L3b payload
        bad_payload = {**chain["l3b"].payload, "cnf": {"jwk": agent.public_jwk}}
        l3b_tampered = create_sd_jwt(chain["l3b"].header, bad_payload, chain["l3b"].disclosures, agent.private_key)

        from verifiable_intent import SplitL3

        result = verify_chain(
            chain["l1"],
            chain["l2"],
            split_l3s=[SplitL3(l3_payment=chain["l3a"], l3_checkout=l3b_tampered)],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            issuer_public_key=chain["issuer"].public_key,
        )
        assert not result.valid
        assert any("MUST NOT contain cnf" in e for e in result.errors)


# --- Fix #11: L3 exp 1-hour cap ---


class TestL3ExpOneHourCap:
    """L3 exp MUST NOT exceed 1 hour from iat."""

    def test_l3_exp_exceeds_one_hour_rejected(self):
        """L3a with exp - iat = 7200 (2 hours) must be rejected."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        chain = _make_autonomous_chain()
        now = int(time.time())

        # Set exp to 2 hours from iat
        bad_payload = {**chain["l3a"].payload, "iat": now, "exp": now + 7200}
        l3a_tampered = create_sd_jwt(
            chain["l3a"].header, bad_payload, chain["l3a"].disclosures, chain["agent"].private_key
        )

        from verifiable_intent import SplitL3

        result = verify_chain(
            chain["l1"],
            chain["l2"],
            split_l3s=[SplitL3(l3_payment=l3a_tampered, l3_checkout=chain["l3b"])],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            issuer_public_key=chain["issuer"].public_key,
        )
        assert not result.valid
        assert any("exp MUST NOT exceed 1 hour" in e for e in result.errors)

    def test_l3_exp_exactly_one_hour_passes(self):
        """L3a with exp - iat = 3600 (exactly 1 hour) should pass the duration check."""
        from verifiable_intent.crypto.sd_jwt import create_sd_jwt

        chain = _make_autonomous_chain()
        now = int(time.time())

        # Set exp to exactly 1 hour from iat — boundary should pass
        boundary_payload = {**chain["l3a"].payload, "iat": now, "exp": now + 3600}
        l3a_boundary = create_sd_jwt(
            chain["l3a"].header, boundary_payload, chain["l3a"].disclosures, chain["agent"].private_key
        )

        from verifiable_intent import SplitL3

        result = verify_chain(
            chain["l1"],
            chain["l2"],
            split_l3s=[SplitL3(l3_payment=l3a_boundary, l3_checkout=chain["l3b"])],
            l2_payment_serialized=chain["l2_payment_ser"],
            l2_checkout_serialized=chain["l2_checkout_ser"],
            issuer_public_key=chain["issuer"].public_key,
        )
        # Should not fail on the 1-hour check (may fail on sd_hash since payload changed)
        assert not any("exp MUST NOT exceed 1 hour" in e for e in result.errors)
