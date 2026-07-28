"""Generate golden conformance vectors from the Python reference implementation.

Snapshots one Immediate and one Autonomous flow with deterministic demo keys
and fixed timestamps/nonces. ECDSA P-256 signatures are randomized, so full
credentials are NOT reproducible by re-signing; instead we record every
*deterministic* artifact (disclosure encodings, hashes, payload JSON,
delegate_payload, _sd arrays, sd_hash inputs/outputs) plus the exact salts
consumed, so the TypeScript port can replay them byte-for-byte and the suite
can compare without depending on signature bytes.

Run from the python/ dir:
    uv run --no-project --with "cryptography>=42" python scripts/generate_vectors.py

Output: <repo-root>/test-vectors/vectors.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PY_ROOT = Path(__file__).resolve().parent.parent  # python/
REPO_ROOT = PY_ROOT.parent  # repo root
sys.path.insert(0, str(PY_ROOT / "src"))
sys.path.insert(0, str(PY_ROOT / "examples"))

import helpers  # noqa: E402

import verifiable_intent as vi  # noqa: E402
from verifiable_intent.crypto.disclosure import (  # noqa: E402
    _b64url_encode,
    build_selective_presentation,
    create_disclosure,
    hash_bytes,
    hash_disclosure,
)
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt  # noqa: E402
from verifiable_intent.crypto.signing import _jwt_encode  # noqa: E402
from verifiable_intent.verification.chain import SplitL3  # noqa: E402

# ---------------------------------------------------------------------------
# Deterministic scenario constants
# ---------------------------------------------------------------------------

ISSUER = helpers.get_issuer_keys()
USER = helpers.get_user_keys()
AGENT = helpers.get_agent_keys()
MERCHANT = helpers.get_merchant_keys()

PI = helpers.PAYMENT_INSTRUMENT
M1 = {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"}
M2 = {"id": "merchant-uuid-2", "name": "Babolat", "website": "https://babolat.com"}
ITEM1 = {"id": "BAB86345", "title": "Babolat Pure Aero Tennis Racket"}
ITEM2 = {"id": "HEA23102", "title": "Head Graphene 360 Speed"}

L1_IAT = 1_750_000_000
L1_EXP = L1_IAT + 31_536_000  # ~1 year
CHK_IAT = 1_750_000_050
L2_IAT = 1_750_000_100
L3_IAT = 1_750_000_200


def sd_jwt_record(sj) -> dict:
    """Capture every deterministic artifact of an SdJwt (signature excluded)."""
    return {
        "header": sj.header,
        "payload": sj.payload,
        "header_b64": sj._raw_header_b64,
        "payload_b64": sj._raw_payload_b64,
        "issuer_jwt": sj.issuer_jwt,
        "serialized": sj.serialize(),
        "disclosures": sj.disclosures,
        "salts": [dv[0] for dv in sj.disclosure_values],
        "values": [dv[-1] for dv in sj.disclosure_values],
        "sd_hashes_of_disclosures": [hash_disclosure(d) for d in sj.disclosures],
    }


def find_disclosure(sj, predicate) -> str:
    for s, dv in zip(sj.disclosures, sj.disclosure_values):
        if predicate(dv[-1]):
            return s
    raise ValueError("disclosure not found")


# ---------------------------------------------------------------------------
# Layer 1 (shared by both flows)
# ---------------------------------------------------------------------------

l1_cred = vi.IssuerCredential(
    iss="https://issuer.mastercard.com",
    sub="user-subject-12345",
    iat=L1_IAT,
    exp=L1_EXP,
    cnf_jwk=USER.public_jwk,
    pan_last_four="1234",
    scheme="mastercard",
    card_id=PI["id"],
    email="user@example.com",
)
l1 = vi.create_layer1(l1_cred, ISSUER.private_key, kid=ISSUER.kid)
l1_serialized = l1.serialize()
l1_sd_hash = hash_bytes(l1_serialized.encode("ascii"))

# ---------------------------------------------------------------------------
# Merchant checkout JWT (fixed timestamps; signature still random)
# ---------------------------------------------------------------------------

checkout_payload = {
    "iss": "https://tennis-warehouse.com",
    "sub": "cart_checkout",
    "iat": CHK_IAT,
    "exp": CHK_IAT + 3600,
    "cart": {
        "items": [
            {
                "sku": "BAB86345",
                "name": "Babolat Pure Aero Tennis Racket",
                "size": 3,
                "size_label": "4 3/8",
                "color": "white",
                "quantity": 1,
                "unitPrice": 279.99,
            }
        ],
        "subTotal": {"amount": 279.99, "currencyCode": "USD"},
    },
}
checkout_jwt = _jwt_encode(
    {"alg": "ES256", "typ": "JWT", "kid": MERCHANT.kid},
    checkout_payload,
    MERCHANT.private_key,
)
checkout_hash = _b64url_encode(hashlib.sha256(checkout_jwt.encode("ascii")).digest())

# ---------------------------------------------------------------------------
# Immediate flow: L2 with final values
# ---------------------------------------------------------------------------

imm_mandate = vi.UserMandate(
    nonce="immediate-nonce-0001",
    aud="https://agent.example.com",
    iat=L2_IAT,
    mode=vi.MandateMode.IMMEDIATE,
    iss="https://wallet.example.com",
    exp=L2_IAT + 900,
    sd_hash=l1_sd_hash,
    checkout_mandate=vi.CheckoutMandate(vct="mandate.checkout.1", checkout_jwt=checkout_jwt),
    payment_mandate=vi.PaymentMandate(
        vct="mandate.payment.1",
        payment_instrument=PI,
        payee=M1,
        currency="USD",
        amount=27999,
    ),
)
l2_imm = vi.create_layer2_immediate(imm_mandate, USER.private_key, kid=USER.kid).sd_jwt

# ---------------------------------------------------------------------------
# Autonomous flow: L2 open mandates with constraints + nested disclosures
# ---------------------------------------------------------------------------

auto_mandate = vi.UserMandate(
    nonce="autonomous-nonce-0001",
    aud="https://agent.example.com",
    iat=L2_IAT,
    mode=vi.MandateMode.AUTONOMOUS,
    iss="https://wallet.example.com",
    exp=L2_IAT + 86_400,
    sd_hash=l1_sd_hash,
    merchants=[M1, M2],
    acceptable_items=[ITEM1, ITEM2],
    checkout_mandate=vi.CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=AGENT.public_jwk,
        cnf_kid=AGENT.kid,
        constraints=[
            vi.AllowedMerchantConstraint(allowed=[dict(M1), dict(M2)]),
            vi.CheckoutLineItemsConstraint(
                items=[{"id": "line-1", "acceptable_items": [dict(ITEM1), dict(ITEM2)], "quantity": 1}]
            ),
        ],
    ),
    payment_mandate=vi.PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=AGENT.public_jwk,
        cnf_kid=AGENT.kid,
        constraints=[
            vi.AllowedPayeeConstraint(allowed=[dict(M1)]),
            vi.PaymentAmountConstraint(currency="USD", min=10000, max=40000),
        ],
        payment_instrument=PI,
    ),
)
l2_auto = vi.create_layer2_autonomous(auto_mandate, USER.private_key, kid=USER.kid)

# Locate the L2 disclosures each L3 binds to.
payment_disc = find_disclosure(l2_auto, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
checkout_disc = find_disclosure(l2_auto, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
merchant_disc = find_disclosure(l2_auto, lambda v: isinstance(v, dict) and v.get("id") == "merchant-uuid-1" and "website" in v)
item_disc = find_disclosure(l2_auto, lambda v: isinstance(v, dict) and v.get("id") == "BAB86345" and "title" in v)

# ---------------------------------------------------------------------------
# Split-agent attack fixture: an autonomous L2 whose payment mandate is bound to
# a DIFFERENT agent key than its checkout mandate. The chain MUST be rejected
# (cnf.jwk must be identical across the mandate pair). Mirrors the Python
# reference test (tests/test_verification_hardening.py
# TestDualMandateCnfCrossCheck) so the TypeScript port inherits the same
# fail-closed coverage via the autonomous_split_agent chain scenario below.
split_agent_mandate = vi.UserMandate(
    nonce="autonomous-split-agent-0001",
    aud="https://agent.example.com",
    iat=L2_IAT,
    mode=vi.MandateMode.AUTONOMOUS,
    iss="https://wallet.example.com",
    exp=L2_IAT + 86_400,
    sd_hash=l1_sd_hash,
    merchants=[M1, M2],
    acceptable_items=[ITEM1, ITEM2],
    checkout_mandate=vi.CheckoutMandate(
        vct="mandate.checkout.open.1",
        cnf_jwk=AGENT.public_jwk,
        cnf_kid=AGENT.kid,
        constraints=[
            vi.AllowedMerchantConstraint(allowed=[dict(M1), dict(M2)]),
            vi.CheckoutLineItemsConstraint(
                items=[{"id": "line-1", "acceptable_items": [dict(ITEM1), dict(ITEM2)], "quantity": 1}]
            ),
        ],
    ),
    payment_mandate=vi.PaymentMandate(
        vct="mandate.payment.open.1",
        cnf_jwk=MERCHANT.public_jwk,  # different key than the checkout mandate's cnf
        cnf_kid=AGENT.kid,
        constraints=[
            vi.AllowedPayeeConstraint(allowed=[dict(M1)]),
            vi.PaymentAmountConstraint(currency="USD", min=10000, max=40000),
        ],
        payment_instrument=PI,
    ),
)
l2_split_agent = vi.create_layer2_autonomous(split_agent_mandate, USER.private_key, kid=USER.kid)

# ---------------------------------------------------------------------------
# Autonomous flow: L3a (payment -> network) and L3b (checkout -> merchant)
# ---------------------------------------------------------------------------

l3a_mandate = vi.PaymentL3Mandate(
    nonce="l3a-nonce-0001",
    aud="https://network.mastercard.com",
    iat=L3_IAT,
    iss="https://agent.example.com",
    exp=L3_IAT + 300,
    final_payment=vi.FinalPaymentMandate(
        transaction_id=checkout_hash,
        payee=dict(M1),
        payment_amount={"currency": "USD", "amount": 27999},
        payment_instrument=PI,
    ),
    final_merchant=dict(M1),
)
l3a = vi.create_layer3_payment(l3a_mandate, AGENT.private_key, l2_auto.issuer_jwt, payment_disc, merchant_disc, kid=AGENT.kid)

l3b_mandate = vi.CheckoutL3Mandate(
    nonce="l3b-nonce-0001",
    aud="https://tennis-warehouse.com",
    iat=L3_IAT,
    iss="https://agent.example.com",
    exp=L3_IAT + 300,
    final_checkout=vi.FinalCheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash),
)
l3b = vi.create_layer3_checkout(l3b_mandate, AGENT.private_key, l2_auto.issuer_jwt, checkout_disc, item_disc, kid=AGENT.kid)

l3a_presentation = build_selective_presentation(l2_auto.issuer_jwt, [payment_disc, merchant_disc])
l3b_presentation = build_selective_presentation(l2_auto.issuer_jwt, [checkout_disc, item_disc])

# ---------------------------------------------------------------------------
# Self-verify (sanity; ensures emitted vectors are a known-good chain)
#
# Timestamps are pinned to a fixed instant so the deterministic snapshot is
# stable. verify_chain reads the wall clock internally, so we pin time.time()
# to a moment inside every layer's validity window for the duration of the
# self-check only (the reference implementation itself is left untouched).
# ---------------------------------------------------------------------------

import time as _time  # noqa: E402

VERIFY_NOW = L3_IAT + 60  # valid for L1, both L2 variants, and L3 (exp-iat<=3600)
_orig_time = _time.time
_time.time = lambda: VERIFY_NOW

verification = {"verify_now": VERIFY_NOW}

imm_result = vi.verify_chain(
    l1,
    l2_imm,
    issuer_public_key=ISSUER.public_key,
    l1_serialized=l1_serialized,
    l2_serialized=l2_imm.serialize(),
    expected_l2_aud="https://agent.example.com",
    expected_l2_nonce="immediate-nonce-0001",
)
verification["immediate_valid"] = imm_result.valid
verification["immediate_errors"] = imm_result.errors

try:
    auto_result = vi.verify_chain(
        l1,
        l2_auto,
        issuer_public_key=ISSUER.public_key,
        l1_serialized=l1_serialized,
        l2_serialized=l2_auto.serialize(),
        split_l3s=[
            SplitL3(
                l3_payment=l3a,
                l3_checkout=l3b,
                l2_payment_serialized=l3a_presentation,
                l2_checkout_serialized=l3b_presentation,
            )
        ],
        expected_l2_aud="https://agent.example.com",
        expected_l2_nonce="autonomous-nonce-0001",
        expected_l3_payment_aud="https://network.mastercard.com",
        expected_l3_payment_nonce="l3a-nonce-0001",
        expected_l3_checkout_aud="https://tennis-warehouse.com",
        expected_l3_checkout_nonce="l3b-nonce-0001",
    )
    verification["autonomous_valid"] = auto_result.valid
    verification["autonomous_errors"] = auto_result.errors
except Exception as e:  # pragma: no cover - diagnostic only
    verification["autonomous_valid"] = False
    verification["autonomous_errors"] = [f"{type(e).__name__}: {e}"]
finally:
    _time.time = _orig_time

# ---------------------------------------------------------------------------
# Verification conformance scenarios (chain / constraints / integrity)
# Each scenario records the exact result of the Python verifier so the
# TypeScript port can be asserted against it (clock pinned to current_time).
# ---------------------------------------------------------------------------


def tamper_signature(serialized: str) -> str:
    """Flip one character of the issuer JWT signature (breaks the signature)."""
    jwt, sep, rest = serialized.partition("~")
    h, p, sig = jwt.split(".")
    flipped = ("B" if sig[0] != "B" else "C") + sig[1:]
    return f"{h}.{p}.{flipped}{sep}{rest}"


L2_IMM_SER = l2_imm.serialize()
L2_AUTO_SER = l2_auto.serialize()
L2_SPLIT_AGENT_SER = l2_split_agent.serialize()
L3A_SER = l3a.serialize()
L3B_SER = l3b.serialize()

_chain_scenarios = []


def chain_scenario(name, *, l1s=l1_serialized, l2s, l3p=None, l3c=None, l2p=None, l2c=None,
                   issuer_pub=ISSUER.public_jwk, skip_issuer=False, current=VERIFY_NOW, **params):
    _time.time = lambda: current
    try:
        kwargs = dict(
            issuer_public_key=(ISSUER.public_key if issuer_pub is not None else None),
            skip_issuer_verification=skip_issuer,
            l1_serialized=l1s,
            l2_serialized=l2s,
        )
        kwargs.update(params)
        if l3p is not None or l3c is not None:
            kwargs["split_l3s"] = [
                SplitL3(
                    l3_payment=decode_sd_jwt(l3p) if l3p else None,
                    l3_checkout=decode_sd_jwt(l3c) if l3c else None,
                    l2_payment_serialized=l2p,
                    l2_checkout_serialized=l2c,
                )
            ]
        res = vi.verify_chain(decode_sd_jwt(l1s), decode_sd_jwt(l2s), **kwargs)
    finally:
        _time.time = _orig_time
    _chain_scenarios.append({
        "name": name,
        "current_time": current,
        "issuer_public": issuer_pub,
        "skip_issuer_verification": skip_issuer,
        "l1": l1s,
        "l2": l2s,
        "l3_payment": l3p,
        "l3_checkout": l3c,
        "l2_payment_serialized": l2p,
        "l2_checkout_serialized": l2c,
        "expected_l2_aud": params.get("expected_l2_aud"),
        "expected_l2_nonce": params.get("expected_l2_nonce"),
        "expected_l3_payment_aud": params.get("expected_l3_payment_aud"),
        "expected_l3_payment_nonce": params.get("expected_l3_payment_nonce"),
        "expected_l3_checkout_aud": params.get("expected_l3_checkout_aud"),
        "expected_l3_checkout_nonce": params.get("expected_l3_checkout_nonce"),
        "expected_valid": res.valid,
        "expected_errors": res.errors,
    })


# Immediate
chain_scenario("immediate_valid", l2s=L2_IMM_SER, expected_l2_aud="https://agent.example.com", expected_l2_nonce="immediate-nonce-0001")
chain_scenario("immediate_wrong_aud", l2s=L2_IMM_SER, expected_l2_aud="https://attacker.example.com")
chain_scenario("immediate_wrong_nonce", l2s=L2_IMM_SER, expected_l2_nonce="wrong-nonce")
chain_scenario("immediate_expired", l2s=L2_IMM_SER, current=VERIFY_NOW + 1_000_000)
chain_scenario("immediate_iat_future", l2s=L2_IMM_SER, current=L1_IAT - 1_000_000)
chain_scenario("immediate_tampered_l1", l1s=tamper_signature(l1_serialized), l2s=L2_IMM_SER)
chain_scenario("immediate_missing_issuer_key", l2s=L2_IMM_SER, issuer_pub=None)

# RFC 9901 section 7.1: an L1 whose _sd carries a duplicated digest must be rejected.
_dup_l1_payload = dict(l1.payload)
_l1_sd = _dup_l1_payload.get("_sd")
if isinstance(_l1_sd, list) and _l1_sd:
    _dup_l1_payload["_sd"] = list(_l1_sd) + [_l1_sd[0]]
_dup_l1_jwt = _jwt_encode(l1.header, _dup_l1_payload, ISSUER.private_key)
_dup_l1_ser = "~".join([_dup_l1_jwt] + list(l1.disclosures)) + "~"
chain_scenario("immediate_duplicate_l1_sd", l1s=_dup_l1_ser, l2s=L2_IMM_SER)

# Autonomous
chain_scenario(
    "autonomous_valid", l2s=L2_AUTO_SER, l3p=L3A_SER, l3c=L3B_SER, l2p=l3a_presentation, l2c=l3b_presentation,
    expected_l2_aud="https://agent.example.com", expected_l2_nonce="autonomous-nonce-0001",
    expected_l3_payment_aud="https://network.mastercard.com", expected_l3_payment_nonce="l3a-nonce-0001",
    expected_l3_checkout_aud="https://tennis-warehouse.com", expected_l3_checkout_nonce="l3b-nonce-0001",
)
chain_scenario("autonomous_swapped_l3", l2s=L2_AUTO_SER, l3p=L3A_SER, l3c=L3B_SER, l2p=l3b_presentation, l2c=l3a_presentation)
chain_scenario(
    "autonomous_wrong_l3_aud", l2s=L2_AUTO_SER, l3p=L3A_SER, l3c=L3B_SER, l2p=l3a_presentation, l2c=l3b_presentation,
    expected_l3_payment_aud="https://attacker.example.com",
)
chain_scenario("autonomous_l3_expired", l2s=L2_AUTO_SER, l3p=L3A_SER, l3c=L3B_SER, l2p=l3a_presentation, l2c=l3b_presentation, current=VERIFY_NOW + 1_000_000)
chain_scenario("autonomous_skip_issuer_ok", l2s=L2_AUTO_SER, l3p=L3A_SER, l3c=L3B_SER, l2p=l3a_presentation, l2c=l3b_presentation, issuer_pub=None, skip_issuer=True)
# Split-agent attack: payment and checkout mandates bound to different agent keys → reject.
chain_scenario("autonomous_split_agent", l2s=L2_SPLIT_AGENT_SER)

_constraint_cases = []


def cc(name, constraints, fulfillment, mode, is_open=False):
    r = vi.check_constraints(constraints, fulfillment, mode=mode, is_open_mandate=is_open)
    _constraint_cases.append({
        "name": name,
        "constraints": constraints,
        "fulfillment": fulfillment,
        "mode": mode.value,
        "is_open_mandate": is_open,
        "expected": {
            "satisfied": r.satisfied,
            "violations": len(r.violations),
            "checked": len(r.checked),
            "skipped": len(r.skipped),
        },
    })


_AMT = vi.PaymentAmountConstraint(currency="USD", min=10000, max=40000).to_dict()
cc("amount_ok", [_AMT], {"payment_amount": {"currency": "USD", "amount": 27999}}, vi.StrictnessMode.PERMISSIVE)
cc("amount_over_max", [_AMT], {"payment_amount": {"currency": "USD", "amount": 50000}}, vi.StrictnessMode.PERMISSIVE)
cc("amount_under_min", [_AMT], {"payment_amount": {"currency": "USD", "amount": 5000}}, vi.StrictnessMode.PERMISSIVE)
cc("amount_wrong_currency", [_AMT], {"payment_amount": {"currency": "EUR", "amount": 27999}}, vi.StrictnessMode.PERMISSIVE)

_PAYEE = vi.AllowedPayeeConstraint(allowed=[dict(M1)]).to_dict()
cc("payee_ok", [_PAYEE], {"payee": dict(M1)}, vi.StrictnessMode.PERMISSIVE)
cc("payee_not_allowed", [_PAYEE], {"payee": dict(M2)}, vi.StrictnessMode.PERMISSIVE)

_LI = vi.CheckoutLineItemsConstraint(items=[{"id": "line-1", "acceptable_items": [dict(ITEM1)], "quantity": 2}]).to_dict()
cc("line_items_ok", [_LI], {"line_items": [{"id": "BAB86345", "quantity": 1}]}, vi.StrictnessMode.PERMISSIVE)
cc("line_items_over_qty", [_LI], {"line_items": [{"id": "BAB86345", "quantity": 5}]}, vi.StrictnessMode.PERMISSIVE)
cc("line_items_wrong_id", [_LI], {"line_items": [{"id": "ZZZ99999", "quantity": 1}]}, vi.StrictnessMode.PERMISSIVE)

_UNK = [{"type": "mandate.custom.foo", "bar": 1}]
cc("unknown_permissive", _UNK, {}, vi.StrictnessMode.PERMISSIVE)
cc("unknown_strict", _UNK, {}, vi.StrictnessMode.STRICT)
cc("unknown_open_rejected", _UNK, {}, vi.StrictnessMode.PERMISSIVE, is_open=True)

_integrity_cases = []
_chk = {"vct": "mandate.checkout.1", "checkout_jwt": checkout_jwt, "checkout_hash": checkout_hash}
_pay = {"vct": "mandate.payment.1", "transaction_id": checkout_hash}
_integrity_cases.append({"name": "checkout_hash_ok", "kind": "checkout_hash", "checkout_mandate": _chk, "payment_mandate": _pay, "expected_valid": vi.verify_checkout_hash_binding(_chk, _pay)[0]})
_bad_pay = {"vct": "mandate.payment.1", "transaction_id": "WRONGHASH"}
_integrity_cases.append({"name": "checkout_hash_mismatch", "kind": "checkout_hash", "checkout_mandate": _chk, "payment_mandate": _bad_pay, "expected_valid": vi.verify_checkout_hash_binding(_chk, _bad_pay)[0]})
_l3a_c = {"delegate_payload": [{"vct": "mandate.payment.1", "transaction_id": checkout_hash}]}
_l3b_c = {"delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": checkout_hash}]}
_integrity_cases.append({"name": "l3_xref_ok", "kind": "l3_xref", "l3_payment_claims": _l3a_c, "l3_checkout_claims": _l3b_c, "expected_valid": vi.verify_l3_cross_reference(_l3a_c, _l3b_c)[0]})
_l3b_bad = {"delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": "DIFFERENT"}]}
_integrity_cases.append({"name": "l3_xref_mismatch", "kind": "l3_xref", "l3_payment_claims": _l3a_c, "l3_checkout_claims": _l3b_bad, "expected_valid": vi.verify_l3_cross_reference(_l3a_c, _l3b_bad)[0]})
# L2 reference binding: conditional_transaction_id == hash of the checkout disclosure.
_l2ref_pay = {"vct": "mandate.payment.open.1", "constraints": [{"type": "mandate.payment.reference", "conditional_transaction_id": hash_disclosure(checkout_disc)}]}
_integrity_cases.append({"name": "l2_reference_ok", "kind": "l2_ref", "checkout_disclosure": checkout_disc, "payment_mandate": _l2ref_pay, "expected_valid": vi.verify_l2_reference_binding({}, _l2ref_pay, checkout_disc)[0]})
_l2ref_bad = {"vct": "mandate.payment.open.1", "constraints": [{"type": "mandate.payment.reference", "conditional_transaction_id": "WRONGREF"}]}
_integrity_cases.append({"name": "l2_reference_mismatch", "kind": "l2_ref", "checkout_disclosure": checkout_disc, "payment_mandate": _l2ref_bad, "expected_valid": vi.verify_l2_reference_binding({}, _l2ref_bad, checkout_disc)[0]})

verification_conformance = {
    "chain_scenarios": _chain_scenarios,
    "constraint_cases": _constraint_cases,
    "integrity_cases": _integrity_cases,
}

# ---------------------------------------------------------------------------
# Primitive vectors (independent of any flow)
# ---------------------------------------------------------------------------

prim_disclosures = []
for claim_name, value, salt in [
    ("email", "user@example.com", "AAAAAAAAAAAAAAAAAAAAAA"),
    (None, dict(M1), "BBBBBBBBBBBBBBBBBBBBBB"),
    (None, dict(ITEM1), "CCCCCCCCCCCCCCCCCCCCCC"),
    (None, {"vct": "mandate.payment.1", "payment_amount": {"currency": "USD", "amount": 27999}}, "DDDDDDDDDDDDDDDDDDDDDD"),
]:
    d = create_disclosure(claim_name, value, salt=salt)
    prim_disclosures.append(
        {"claim_name": claim_name, "value": value, "salt": salt, "disclosure": d, "hash": hash_disclosure(d)}
    )

prim_hashes = [
    {"input_ascii": s, "hash": hash_bytes(s.encode("ascii"))}
    for s in ["", "hello", "abc~def~", checkout_jwt, l1_serialized]
]

prim_b64url = [
    {"bytes_hex": bytes(b).hex(), "b64url": _b64url_encode(bytes(b))}
    for b in [b"", b"\x00", b"\x00\x01\x02\x03", b"hello world", bytes(range(20))]
]

# ---------------------------------------------------------------------------
# Model vectors (to_dict / to_payload JSON, byte-exact)
# ---------------------------------------------------------------------------


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


constraint_models = [
    ("AllowedMerchantConstraint", vi.AllowedMerchantConstraint(allowed=[dict(M1), dict(M2)]).to_dict()),
    (
        "CheckoutLineItemsConstraint",
        vi.CheckoutLineItemsConstraint(
            items=[{"id": "line-1", "acceptable_items": [dict(ITEM1)], "quantity": 2}], match_mode="exact"
        ).to_dict(),
    ),
    ("AllowedPayeeConstraint", vi.AllowedPayeeConstraint(allowed=[dict(M1)]).to_dict()),
    ("PaymentAmountConstraint", vi.PaymentAmountConstraint(currency="USD", min=10000, max=40000).to_dict()),
    ("PaymentAmountConstraint_max_only", vi.PaymentAmountConstraint(currency="EUR", max=5000).to_dict()),
    ("ReferenceConstraint", vi.ReferenceConstraint(conditional_transaction_id="deadbeef").to_dict()),
    ("PaymentBudgetConstraint", vi.PaymentBudgetConstraint(currency="USD", max=100000, min=500).to_dict()),
    (
        "PaymentRecurrenceConstraint",
        vi.PaymentRecurrenceConstraint(frequency="MNTH", start_date="2026-01-01", end_date="2026-12-31", number=12).to_dict(),
    ),
    (
        "AgentRecurrenceConstraint",
        vi.AgentRecurrenceConstraint(frequency="WEEK", start_date="2026-01-01", end_date="2026-06-30", max_occurrences=26).to_dict(),
    ),
]
model_constraints = [{"name": n, "dict": d, "json": jdump(d)} for n, d in constraint_models]

model_misc = {
    "issuer_credential_to_payload": {"dict": l1_cred.to_payload(), "json": jdump(l1_cred.to_payload())},
    "final_payment_mandate": {
        "dict": vi.FinalPaymentMandate(
            transaction_id=checkout_hash, payee=dict(M1), payment_amount={"currency": "USD", "amount": 27999}, payment_instrument=PI
        ).to_dict()
    },
    "final_checkout_mandate": {
        "dict": vi.FinalCheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash).to_dict()
    },
}

# ---------------------------------------------------------------------------
# Assemble & write
# ---------------------------------------------------------------------------

vectors = {
    "_meta": {
        "description": "Golden conformance vectors from the Python verifiable-intent reference implementation.",
        "note": "ECDSA signatures are randomized; compare deterministic artifacts (disclosures, hashes, payload JSON, delegate_payload, _sd, sd_hash) — never signature bytes.",
        "vi_version": vi.__version__,
        "timestamps": {"l1_iat": L1_IAT, "l1_exp": L1_EXP, "checkout_iat": CHK_IAT, "l2_iat": L2_IAT, "l3_iat": L3_IAT},
    },
    "keys": {
        "issuer": {"kid": ISSUER.kid, "public": ISSUER.public_jwk, "private": ISSUER.private_jwk},
        "user": {"kid": USER.kid, "public": USER.public_jwk, "private": USER.private_jwk},
        "agent": {"kid": AGENT.kid, "public": AGENT.public_jwk, "private": AGENT.private_jwk},
        "merchant": {"kid": MERCHANT.kid, "public": MERCHANT.public_jwk, "private": MERCHANT.private_jwk},
    },
    "primitives": {"b64url": prim_b64url, "disclosures": prim_disclosures, "hash_bytes": prim_hashes},
    "models": {"constraints": model_constraints, "misc": model_misc},
    "shared": {
        "checkout_jwt": checkout_jwt,
        "checkout_hash": checkout_hash,
        "l1_serialized": l1_serialized,
        "l1_sd_hash": l1_sd_hash,
        "l1": sd_jwt_record(l1),
        "l1_credential": {
            "iss": l1_cred.iss,
            "sub": l1_cred.sub,
            "iat": l1_cred.iat,
            "exp": l1_cred.exp,
            "vct": l1_cred.vct,
            "cnf_jwk": l1_cred.cnf_jwk,
            "pan_last_four": l1_cred.pan_last_four,
            "scheme": l1_cred.scheme,
            "card_id": l1_cred.card_id,
            "email": l1_cred.email,
        },
    },
    "immediate": {
        "inputs": {
            "nonce": "immediate-nonce-0001",
            "aud": "https://agent.example.com",
            "iat": L2_IAT,
            "iss": "https://wallet.example.com",
            "exp": L2_IAT + 900,
            "sd_hash": l1_sd_hash,
            "kid": USER.kid,
            "checkout_mandate": {"vct": "mandate.checkout.1", "checkout_jwt": checkout_jwt},
            "payment_mandate": {
                "vct": "mandate.payment.1",
                "payment_instrument": PI,
                "payee": M1,
                "currency": "USD",
                "amount": 27999,
            },
        },
        "checkout_mandate_dict": imm_mandate.checkout_mandate.to_dict(),
        "payment_mandate_dict": imm_mandate.payment_mandate.to_dict(),
        "l2": sd_jwt_record(l2_imm),
        "delegate_payload": l2_imm.payload["delegate_payload"],
    },
    "autonomous": {
        "inputs": {
            "nonce": "autonomous-nonce-0001",
            "aud": "https://agent.example.com",
            "iat": L2_IAT,
            "iss": "https://wallet.example.com",
            "exp": L2_IAT + 86_400,
            "sd_hash": l1_sd_hash,
            "kid": USER.kid,
            "agent_cnf_jwk": AGENT.public_jwk,
            "agent_cnf_kid": AGENT.kid,
            "merchants": [M1, M2],
            "acceptable_items": [ITEM1, ITEM2],
        },
        "l2": sd_jwt_record(l2_auto),
        "disclosure_refs": {
            "payment_disc": payment_disc,
            "checkout_disc": checkout_disc,
            "merchant_disc": merchant_disc,
            "item_disc": item_disc,
        },
        "l3a": {
            "inputs": {
                "nonce": "l3a-nonce-0001",
                "aud": "https://network.mastercard.com",
                "iat": L3_IAT,
                "iss": "https://agent.example.com",
                "exp": L3_IAT + 300,
                "kid": AGENT.kid,
                "l2_base_jwt": l2_auto.issuer_jwt,
                "payment_disclosure": payment_disc,
                "merchant_disclosure": merchant_disc,
                "final_payment": l3a_mandate.final_payment.to_dict(),
                "final_merchant": dict(M1),
            },
            "selective_presentation": l3a_presentation,
            "sd_hash": l3a.payload["sd_hash"],
            "credential": sd_jwt_record(l3a),
        },
        "l3b": {
            "inputs": {
                "nonce": "l3b-nonce-0001",
                "aud": "https://tennis-warehouse.com",
                "iat": L3_IAT,
                "iss": "https://agent.example.com",
                "exp": L3_IAT + 300,
                "kid": AGENT.kid,
                "l2_base_jwt": l2_auto.issuer_jwt,
                "checkout_disclosure": checkout_disc,
                "item_disclosure": item_disc,
                "final_checkout": l3b_mandate.final_checkout.to_dict(),
            },
            "selective_presentation": l3b_presentation,
            "sd_hash": l3b.payload["sd_hash"],
            "credential": sd_jwt_record(l3b),
        },
    },
    "verification": verification,
    "verification_conformance": verification_conformance,
}

out_dir = REPO_ROOT / "test-vectors"
out_dir.mkdir(exist_ok=True)
out_path = out_dir / "vectors.json"
out_path.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

print(f"Wrote {out_path.relative_to(REPO_ROOT)} ({out_path.stat().st_size} bytes)")
print(f"  immediate verify : valid={verification.get('immediate_valid')} errors={verification.get('immediate_errors')}")
print(f"  autonomous verify: valid={verification.get('autonomous_valid')} errors={verification.get('autonomous_errors')}")
