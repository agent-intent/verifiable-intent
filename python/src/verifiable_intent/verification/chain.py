"""Full chain verification (L1 → L2 → L3a/L3b)."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.disclosure import hash_bytes, hash_disclosure
from ..crypto.sd_jwt import SdJwt, resolve_disclosures, verify_sd_jwt_signature
from ..crypto.signing import jwk_to_public_key
from .integrity import verify_checkout_hash_binding, verify_l2_reference_binding, verify_l3_cross_reference

_ALLOWED_ALGS = {"ES256"}

# VCT constants
_L1_VCT = "https://credentials.mastercard.com/card"
_L2_CHECKOUT_VCT_OPEN = "mandate.checkout.open.1"
_L2_PAYMENT_VCT_OPEN = "mandate.payment.open.1"
_L2_CHECKOUT_VCT_FINAL = "mandate.checkout.1"
_L2_PAYMENT_VCT_FINAL = "mandate.payment.1"
_L3_PAYMENT_VCT = "mandate.payment.1"
_L3_CHECKOUT_VCT = "mandate.checkout.1"

_CHECKOUT_VCTS = {_L2_CHECKOUT_VCT_OPEN, _L2_CHECKOUT_VCT_FINAL}
_PAYMENT_VCTS = {_L2_PAYMENT_VCT_OPEN, _L2_PAYMENT_VCT_FINAL}


def _is_expired(exp_value, now: int, skew: int) -> bool | None:
    """Check if an exp claim is expired. Returns None if exp is absent."""
    if exp_value is None:
        return None
    if isinstance(exp_value, bool):
        return True  # bool is subclass of int; reject before numeric check
    if not isinstance(exp_value, (int, float)):
        return True  # Non-numeric exp is always treated as expired
    if isinstance(exp_value, float) and not math.isfinite(exp_value):
        return True  # NaN, Infinity, -Infinity are invalid
    # Avoid coercing large ints to float; that can raise OverflowError.
    return now > exp_value + skew


def _is_future_dated(iat_value, now: int, skew: int) -> bool | None:
    """Check if an iat claim is in the future. Returns None if iat is absent."""
    if iat_value is None:
        return None
    if isinstance(iat_value, bool):
        return True  # bool is subclass of int; reject before numeric check
    if not isinstance(iat_value, (int, float)):
        return True  # Non-numeric iat is always treated as invalid
    if isinstance(iat_value, float) and not math.isfinite(iat_value):
        return True  # NaN, Infinity, -Infinity are invalid
    # Avoid coercing large ints to float; that can raise OverflowError.
    return iat_value > now + skew


def _validate_header(header, layer: str, expected_typ: str) -> str | None:
    """Validate typ and alg JWT header fields. Returns error message or None."""
    if not isinstance(header, dict):
        return f"{layer} header must be a JSON object, got {type(header).__name__}"
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _ALLOWED_ALGS:
        return f"{layer} header alg must be one of {_ALLOWED_ALGS}, got {type(alg).__name__} '{alg!s:.64}'"
    typ = header.get("typ")
    if not isinstance(typ, str) or typ != expected_typ:
        return f"{layer} header typ must be '{expected_typ}', got {type(typ).__name__} '{typ!s:.64}'"
    return None


@dataclass
class SplitL3:
    """The split L3 (L3a + L3b) for one mandate pair."""

    l3_payment: SdJwt | None = None
    l3_checkout: SdJwt | None = None
    l2_payment_serialized: str | None = None
    l2_checkout_serialized: str | None = None


@dataclass
class MandatePairResult:
    """Per-pair verification result within a multi-pair L2."""

    pair_index: int = 0
    pairing_key: str = ""
    checkout_mandate: dict = field(default_factory=dict)
    payment_mandate: dict = field(default_factory=dict)
    l3_payment_claims: dict = field(default_factory=dict)
    l3_checkout_claims: dict = field(default_factory=dict)
    checks_performed: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class _MandateInfo:
    """Internal: discovered mandate from L2 delegate_payload."""

    resolved: dict
    ref_hash: str | None = None
    disc_b64: str | None = None


@dataclass
class ChainVerificationResult:
    valid: bool = False
    errors: list[str] = field(default_factory=list)
    l1_claims: dict = field(default_factory=dict)
    l2_claims: dict = field(default_factory=dict)
    l3_payment_claims: dict = field(default_factory=dict)
    l3_checkout_claims: dict = field(default_factory=dict)
    l2_checkout_disclosed: bool = False
    l2_payment_disclosed: bool = False
    checks_performed: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    pair_results: list[MandatePairResult] = field(default_factory=list)
    mandate_pair_count: int = 0


def verify_chain(
    l1: SdJwt,
    l2: SdJwt,
    l3_payment: SdJwt | None = None,
    l3_checkout: SdJwt | None = None,
    issuer_public_key: ec.EllipticCurvePublicKey | None = None,
    skip_issuer_verification: bool = False,
    clock_skew_seconds: int = 300,
    l1_serialized: str | None = None,
    l2_serialized: str | None = None,
    l2_payment_serialized: str | None = None,
    l2_checkout_serialized: str | None = None,
    split_l3s: list[SplitL3] | None = None,
    expected_l2_aud: str | None = None,
    expected_l2_nonce: str | None = None,
    expected_l3_payment_aud: str | None = None,
    expected_l3_payment_nonce: str | None = None,
    expected_l3_checkout_aud: str | None = None,
    expected_l3_checkout_nonce: str | None = None,
    expected_l1_vct: str = _L1_VCT,
) -> ChainVerificationResult:
    """Verify the full VI delegation chain (split L3).

    For Immediate mode: l1 + l2 (both l3 params are None)
    For Autonomous mode: l1 + l2 + l3_payment and/or l3_checkout

    For multi-pair L2: use split_l3s instead of l3_payment/l3_checkout.
    split_l3s[i] validates against mandate_pair[i] (positional matching).
    Mutually exclusive with l3_payment/l3_checkout.

    l2_payment_serialized / l2_checkout_serialized: the L2 presentation
    as seen by each L3 recipient (for selective sd_hash verification).
    Falls back to l2_serialized or l2.serialize() if not provided.

    issuer_public_key: the issuer's EC public key used to verify the L1
    signature.  This parameter is REQUIRED by default.  Omitting it
    (leaving it as None) causes verification to fail with an explicit
    error unless skip_issuer_verification=True is also passed.

    skip_issuer_verification: set to True ONLY in unit tests that
    deliberately omit the issuer key to isolate other checks.
    Integration code MUST always provide issuer_public_key.
    """
    result = ChainVerificationResult()
    now = int(time.time())

    # 0. Mutual exclusion: split_l3s vs individual l3 params
    if split_l3s is not None and (l3_payment is not None or l3_checkout is not None):
        result.errors.append("Cannot provide both split_l3s and individual l3_payment/l3_checkout parameters")
        return result

    has_l3_args = l3_payment is not None or l3_checkout is not None
    if split_l3s is not None:
        has_l3_args = has_l3_args or any(p.l3_payment is not None or p.l3_checkout is not None for p in split_l3s)

    # is_autonomous is determined from L2 mandate VCTs after resolve_disclosures (below).
    # We use a placeholder here so early-return paths that never need it work correctly.
    # All code that branches on is_autonomous runs after the mode inference block.
    is_autonomous: bool  # set after L2 disclosure resolution

    # 0. Validate payload/header types are objects (fail-closed on malformed JWTs)
    if not isinstance(l1.payload, dict):
        result.errors.append(f"L1 payload must be a JSON object, got {type(l1.payload).__name__}")
        return result
    if not isinstance(l2.payload, dict):
        result.errors.append(f"L2 payload must be a JSON object, got {type(l2.payload).__name__}")
        return result

    # 1. Verify L1 signature (fail-closed: require key unless explicitly skipped)
    if issuer_public_key:
        if not verify_sd_jwt_signature(l1, issuer_public_key):
            result.errors.append("L1 signature verification failed")
            return result
    elif not skip_issuer_verification:
        result.errors.append(
            "issuer_public_key is required for chain verification "
            "(pass skip_issuer_verification=True to bypass in tests)"
        )
        return result

    # 1a0. Validate L1 header
    l1_header_err = _validate_header(l1.header, "L1", "sd+jwt")
    if l1_header_err:
        result.errors.append(l1_header_err)
        return result

    # 1a. Validate L1 vct claim
    l1_vct = l1.payload.get("vct")
    if l1_vct != expected_l1_vct:
        result.errors.append(f"L1 vct must be '{expected_l1_vct}', got '{l1_vct}'")
        return result

    # 1b. Validate _sd_alg on L1
    l1_sd_alg = l1.payload.get("_sd_alg")
    if l1_sd_alg is not None and l1_sd_alg != "sha-256":
        result.errors.append(f"L1 _sd_alg must be 'sha-256', got '{l1_sd_alg}'")
        return result

    # 2. Check L1 expiration
    l1_exp = l1.payload.get("exp")
    if _is_expired(l1_exp, now, clock_skew_seconds):
        result.errors.append(f"L1 credential expired at {l1_exp}")
        return result

    # 2a. Check L1 iat not in the future
    l1_iat = l1.payload.get("iat")
    if _is_future_dated(l1_iat, now, clock_skew_seconds):
        result.errors.append(f"L1 credential iat is in the future: {l1_iat}")
        return result

    result.l1_claims = resolve_disclosures(l1)

    # 3. Extract user's public key from L1 cnf
    l1_cnf = l1.payload.get("cnf", {})
    if not isinstance(l1_cnf, dict):
        result.errors.append("L1 cnf must be a JSON object")
        return result
    user_jwk = l1_cnf.get("jwk", {})
    if not user_jwk:
        result.errors.append("L1 missing cnf.jwk (user public key)")
        return result

    try:
        user_pub_key = jwk_to_public_key(user_jwk)
    except (KeyError, ValueError, TypeError) as exc:
        result.errors.append(f"L1 cnf.jwk is malformed: {exc}")
        return result

    # 4. Verify L2 signature with user's key
    if not verify_sd_jwt_signature(l2, user_pub_key):
        result.errors.append("L2 signature verification failed (user key mismatch)")
        return result

    # 4a. Verify L2 sd_hash binds to the presented L1
    l1_ser = l1_serialized if l1_serialized is not None else l1.serialize()
    actual_hash = l2.payload.get("sd_hash", "")
    if not actual_hash:
        result.errors.append("L2 missing required sd_hash binding to L1")
        return result
    expected_hash = hash_bytes(l1_ser.encode("ascii"))
    if actual_hash != expected_hash:
        result.errors.append("L2 sd_hash does not match L1 serialized form")
        return result

    # 4a2. Validate _sd_alg on L2
    l2_sd_alg = l2.payload.get("_sd_alg")
    if l2_sd_alg is not None and l2_sd_alg != "sha-256":
        result.errors.append(f"L2 _sd_alg must be 'sha-256', got '{l2_sd_alg}'")
        return result

    # 4a3. Check L2 top-level iat not in the future
    l2_iat = l2.payload.get("iat")
    if _is_future_dated(l2_iat, now, clock_skew_seconds):
        result.errors.append(f"L2 iat is in the future: {l2_iat}")
        return result

    # 4a4. Check L2 top-level exp (if present)
    l2_exp = l2.payload.get("exp")
    if _is_expired(l2_exp, now, clock_skew_seconds):
        result.errors.append(f"L2 expired at {l2_exp}")
        return result

    # 4a5. Validate L2 aud and nonce
    l2_aud = l2.payload.get("aud")
    l2_nonce = l2.payload.get("nonce")
    if expected_l2_aud is not None:
        if l2_aud != expected_l2_aud:
            result.errors.append(f"L2 aud mismatch: expected '{expected_l2_aud}', got '{l2_aud}'")
            return result
        result.checks_performed.append("l2_aud")
    else:
        if isinstance(l2_aud, str) and l2_aud:
            result.checks_skipped.append("l2_aud (no expected value provided)")

    if expected_l2_nonce is not None:
        if l2_nonce != expected_l2_nonce:
            result.errors.append(f"L2 nonce mismatch: expected '{expected_l2_nonce}', got '{l2_nonce}'")
            return result
        result.checks_performed.append("l2_nonce")
    else:
        if isinstance(l2_nonce, str) and l2_nonce:
            result.checks_skipped.append("l2_nonce (no expected value provided)")

    result.l2_claims = resolve_disclosures(l2)

    # 4a-mode. Infer execution mode from L2 mandate VCTs (not from L3 argument presence).
    # Open VCTs (mandate.checkout.open, mandate.payment.open) → Autonomous.
    # Final VCTs (mandate.checkout, mandate.payment) → Immediate.
    # Mixed (both open and final) → error.
    _resolved_delegates_for_mode = result.l2_claims.get("delegate_payload", [])
    _has_open_mandate = False
    _has_final_mandate = False
    if isinstance(_resolved_delegates_for_mode, list):
        for _item in _resolved_delegates_for_mode:
            if isinstance(_item, dict):
                _vct = _item.get("vct", "")
                if _vct in {_L2_CHECKOUT_VCT_OPEN, _L2_PAYMENT_VCT_OPEN}:
                    _has_open_mandate = True
                elif _vct in {_L2_CHECKOUT_VCT_FINAL, _L2_PAYMENT_VCT_FINAL}:
                    _has_final_mandate = True
    # Note: non-list delegate_payload is caught later by the list type check in section 4b.

    if _has_open_mandate and _has_final_mandate:
        result.errors.append(
            "L2 contains both open (autonomous) and final (immediate) mandate VCTs — "
            "open mandates are not allowed in immediate mode"
        )
        return result

    # When no mandates resolve yet (e.g. partial/malformed L2), default to immediate;
    # subsequent mandate checks will produce a more specific error.
    is_autonomous = _has_open_mandate

    # 4a0. Validate L2 header typ now that we know the mode.
    expected_l2_typ = "kb-sd-jwt+kb" if is_autonomous else "kb-sd-jwt"
    l2_header_err = _validate_header(l2.header, "L2", expected_l2_typ)
    if l2_header_err:
        result.errors.append(l2_header_err)
        return result

    # 4a-cross. If L2 is immediate but L3 args were provided, that is a caller error.
    if not is_autonomous and has_l3_args:
        result.errors.append("L3 credentials provided but L2 contains only immediate-mode (final) mandates")
        return result

    # 4b. Extract and pair mandate disclosures
    disc_str_by_hash = {hash_disclosure(ds): ds for ds in l2.disclosures}

    raw_delegates = l2.payload.get("delegate_payload", [])
    if not isinstance(raw_delegates, list):
        result.errors.append(f"L2 delegate_payload must be a list, got {type(raw_delegates).__name__}")
        return result
    resolved_delegates = result.l2_claims.get("delegate_payload", [])

    # Track unrecognized VCTs in delegate_payload for observability (before pairing, which may fail)
    _ALL_KNOWN_VCTS = {
        _L2_CHECKOUT_VCT_OPEN,
        _L2_CHECKOUT_VCT_FINAL,
        _L2_PAYMENT_VCT_OPEN,
        _L2_PAYMENT_VCT_FINAL,
        _L3_PAYMENT_VCT,
        _L3_CHECKOUT_VCT,
    }
    for resolved_item in resolved_delegates:
        if isinstance(resolved_item, dict):
            item_vct = resolved_item.get("vct")
            if isinstance(item_vct, str) and item_vct and item_vct not in _ALL_KNOWN_VCTS:
                result.checks_skipped.append(f"unrecognized_vct_in_delegate_payload: {item_vct}")

    mandate_pairs, pair_errors = _extract_mandate_pairs(
        raw_delegates, resolved_delegates, disc_str_by_hash, is_autonomous
    )
    if pair_errors:
        result.errors.extend(pair_errors)
        return result

    result.mandate_pair_count = len(mandate_pairs)

    any_checkout = any(p[0] is not None for p in mandate_pairs)
    any_payment = any(p[1] is not None for p in mandate_pairs)
    result.l2_checkout_disclosed = any_checkout
    result.l2_payment_disclosed = any_payment

    if not mandate_pairs:
        result.errors.append("L2 delegate_payload resolved zero mandate disclosures")
        return result

    # 4c. Per-pair mandate validation
    for pair_idx, (checkout_info, payment_info) in enumerate(mandate_pairs):
        checkout_mandate = checkout_info.resolved if checkout_info else None
        payment_mandate = payment_info.resolved if payment_info else None
        checkout_disc_b64 = checkout_info.disc_b64 if checkout_info else None
        pairing_key = ""
        if checkout_info and checkout_info.ref_hash:
            pairing_key = checkout_info.ref_hash
        elif payment_info and payment_info.ref_hash:
            pairing_key = payment_info.ref_hash

        pair_result = MandatePairResult(
            pair_index=pair_idx,
            pairing_key=pairing_key,
            checkout_mandate=checkout_mandate or {},
            payment_mandate=payment_mandate or {},
        )

        mp_errors, mp_checks, mp_skipped = _verify_mandate_pair(
            checkout_mandate, payment_mandate, checkout_disc_b64, is_autonomous
        )
        pair_result.checks_performed.extend(mp_checks)
        pair_result.checks_skipped.extend(mp_skipped)
        result.checks_performed.extend(mp_checks)
        result.checks_skipped.extend(mp_skipped)

        if mp_errors:
            pair_result.errors.extend(mp_errors)
            result.errors.extend(mp_errors)
            result.pair_results.append(pair_result)
            return result

        result.pair_results.append(pair_result)

    # 4c-bis. Optional card_id cross-check (SHOULD-level)
    l1_card_id = l1.payload.get("card_id")
    if l1_card_id:
        for pair_result in result.pair_results:
            pm = pair_result.payment_mandate
            pi = pm.get("payment_instrument", {}) if isinstance(pm, dict) else {}
            pi_id = pi.get("id") if isinstance(pi, dict) else None
            if pi_id and pi_id != l1_card_id:
                result.checks_performed.append("l1_card_id_cross_check")
                pair_result.checks_performed.append("l1_card_id_cross_check")
                result.errors.append(f"L1 card_id ({l1_card_id}) does not match payment_instrument.id ({pi_id})")
                return result
            elif pi_id:
                result.checks_performed.append("l1_card_id_cross_check")
                pair_result.checks_performed.append("l1_card_id_cross_check")
            else:
                # card_id is set but payment_instrument.id is absent — cannot verify binding
                result.checks_performed.append("l1_card_id_cross_check")
                pair_result.checks_performed.append("l1_card_id_cross_check")
                result.errors.append(
                    f"L1 card_id ({l1_card_id}) present but payment_instrument.id is missing — cannot verify binding"
                )
                return result
    else:
        result.checks_skipped.append("l1_card_id_cross_check")

    # 4d. Autonomous mode: extract agent key and verify L3s
    if is_autonomous:
        if not any_checkout and not any_payment:
            result.errors.append(
                "Autonomous mode requires at least one L2 mandate disclosure "
                "to extract the agent delegation key (cnf.jwk)"
            )
            return result

        # Extract agent key and kid from all pairs' open mandates
        agent_jwk, agent_kid, cnf_error = _extract_agent_key_from_all_pairs(mandate_pairs)
        if cnf_error:
            result.errors.append(cnf_error)
            return result
        if not agent_jwk:
            result.errors.append("L2 mandates missing cnf.jwk for agent delegation")
            return result

        try:
            agent_pub_key = jwk_to_public_key(agent_jwk)
        except (KeyError, ValueError, TypeError) as exc:
            result.errors.append(f"L2 mandate cnf.jwk is malformed: {exc}")
            return result

        # 5. Normalize split L3s
        if split_l3s is not None:
            effective_split_l3s = split_l3s
        elif l3_payment is not None or l3_checkout is not None:
            effective_split_l3s = [
                SplitL3(
                    l3_payment=l3_payment,
                    l3_checkout=l3_checkout,
                    l2_payment_serialized=l2_payment_serialized,
                    l2_checkout_serialized=l2_checkout_serialized,
                )
            ]
        else:
            effective_split_l3s = []

        # Validate split L3 count matches mandate pair count
        if effective_split_l3s and len(effective_split_l3s) != len(mandate_pairs):
            result.errors.append(
                f"Split L3 count ({len(effective_split_l3s)}) does not match mandate pair count ({len(mandate_pairs)})"
            )
            return result

        # 5a. Verify each split L3 against its mandate pair
        for pair_idx, l3p in enumerate(effective_split_l3s):
            pair_result = result.pair_results[pair_idx]
            checkout_info, payment_info = mandate_pairs[pair_idx]
            l2_pm = payment_info.resolved if payment_info else None

            for l3, l3_label, l3_ser_override, claims_attr, required_vct, expected_pair_disc in [
                (
                    l3p.l3_payment,
                    "L3a (payment)",
                    l3p.l2_payment_serialized or l2_payment_serialized,
                    "l3_payment_claims",
                    _L3_PAYMENT_VCT,
                    payment_info.disc_b64 if payment_info else None,
                ),
                (
                    l3p.l3_checkout,
                    "L3b (checkout)",
                    l3p.l2_checkout_serialized or l2_checkout_serialized,
                    "l3_checkout_claims",
                    _L3_CHECKOUT_VCT,
                    checkout_info.disc_b64 if checkout_info else None,
                ),
            ]:
                if l3 is None:
                    continue

                if not isinstance(l3.payload, dict):
                    result.errors.append(f"{l3_label} payload must be a JSON object, got {type(l3.payload).__name__}")
                    return result

                # L3 MUST NOT contain cnf — terminal delegation, no further key binding
                if "cnf" in l3.payload:
                    result.errors.append(f"{l3_label} payload MUST NOT contain cnf claim")
                    return result

                if not verify_sd_jwt_signature(l3, agent_pub_key):
                    result.errors.append(f"{l3_label} signature verification failed (agent key mismatch)")
                    return result

                l3_header_err = _validate_header(l3.header, l3_label, "kb-sd-jwt")
                if l3_header_err:
                    result.errors.append(l3_header_err)
                    return result

                l3_l2_ser = l3_ser_override or l2_serialized or l2.serialize()
                actual_sd_hash = l3.payload.get("sd_hash", "")
                if not actual_sd_hash:
                    result.errors.append(f"{l3_label} missing required sd_hash binding to L2")
                    return result
                expected_sd_hash = hash_bytes(l3_l2_ser.encode("ascii"))
                if actual_sd_hash != expected_sd_hash:
                    result.errors.append(f"{l3_label} sd_hash does not match L2 serialized form")
                    return result

                # 5a-bind. Verify L3 presentation includes the correct mandate pair's disclosure.
                # Uses list membership on ~-split segments (not substring search) — safe for base64url values.
                if expected_pair_disc:
                    l2_segments = l3_l2_ser.split("~")
                    if expected_pair_disc not in l2_segments:
                        result.errors.append(
                            f"{l3_label} L2 presentation does not include mandate pair {pair_idx} "
                            "disclosure (L3-to-mandate-pair identity mismatch)"
                        )
                        return result
                    pair_result.checks_performed.append(f"pair_{pair_idx}_identity_binding")
                    result.checks_performed.append(f"pair_{pair_idx}_identity_binding")

                l3_sd_alg = l3.payload.get("_sd_alg")
                if l3_sd_alg is not None and l3_sd_alg != "sha-256":
                    result.errors.append(f"{l3_label} _sd_alg must be 'sha-256', got '{l3_sd_alg}'")
                    return result

                l3_iat = l3.payload.get("iat")
                if _is_future_dated(l3_iat, now, clock_skew_seconds):
                    result.errors.append(f"{l3_label} iat is in the future: {l3_iat}")
                    return result

                l3_exp = l3.payload.get("exp")
                if _is_expired(l3_exp, now, clock_skew_seconds):
                    result.errors.append(f"{l3_label} expired at {l3_exp}")
                    return result

                # L3 exp MUST NOT exceed 1 hour from iat
                if (
                    l3_iat is not None
                    and l3_exp is not None
                    and isinstance(l3_iat, (int, float))
                    and isinstance(l3_exp, (int, float))
                    and l3_exp - l3_iat > 3600
                ):
                    result.errors.append(f"{l3_label} exp MUST NOT exceed 1 hour from iat")
                    return result

                # L3 aud and nonce validation (per-credential: payment vs checkout)
                l3_aud = l3.payload.get("aud")
                l3_nonce = l3.payload.get("nonce")
                _exp_aud = expected_l3_payment_aud if required_vct == _L3_PAYMENT_VCT else expected_l3_checkout_aud
                _exp_nonce = (
                    expected_l3_payment_nonce if required_vct == _L3_PAYMENT_VCT else expected_l3_checkout_nonce
                )
                _l3_tag = l3_label.lower().replace(" ", "_")
                if _exp_aud is not None:
                    if l3_aud != _exp_aud:
                        result.errors.append(f"{l3_label} aud mismatch: expected '{_exp_aud}', got '{l3_aud}'")
                        return result
                    result.checks_performed.append(f"{_l3_tag}_aud")
                else:
                    if isinstance(l3_aud, str) and l3_aud:
                        result.checks_skipped.append(f"{_l3_tag}_aud (no expected value provided)")

                if _exp_nonce is not None:
                    if l3_nonce != _exp_nonce:
                        result.errors.append(f"{l3_label} nonce mismatch: expected '{_exp_nonce}', got '{l3_nonce}'")
                        return result
                    result.checks_performed.append(f"{_l3_tag}_nonce")
                else:
                    if isinstance(l3_nonce, str) and l3_nonce:
                        result.checks_skipped.append(f"{_l3_tag}_nonce (no expected value provided)")

                # L3 header kid binding: verifiers resolve the key from L2 cnf.jwk, not from L3 header
                l3_header_kid = l3.header.get("kid")
                if not isinstance(l3_header_kid, str) or not l3_header_kid:
                    result.errors.append(f"{l3_label} header missing required kid parameter")
                    return result
                if agent_kid is not None and l3_header_kid != agent_kid:
                    result.errors.append(
                        f"{l3_label} header kid '{l3_header_kid}' does not match L2 cnf.jwk.kid '{agent_kid}'"
                    )
                    return result

                l3_claims = resolve_disclosures(l3)
                setattr(pair_result, claims_attr, l3_claims)

                l3_err = _validate_l3_mandate_fields(l3_claims, l3_label, required_vct, l2_payment_mandate=l2_pm)
                if l3_err:
                    result.errors.append(l3_err)
                    return result

                pair_result.checks_performed.append(f"{l3_label.lower().replace(' ', '_')}_structural_chain")
                result.checks_performed.append(f"{l3_label.lower().replace(' ', '_')}_structural_chain")

            # 5b. Cross-reference check per pair
            if l3p.l3_payment is not None and l3p.l3_checkout is not None:
                xref_valid, xref_error = verify_l3_cross_reference(
                    pair_result.l3_payment_claims, pair_result.l3_checkout_claims
                )
                if not xref_valid:
                    result.errors.append(f"L3 cross-reference check failed: {xref_error}")
                    return result
                pair_result.checks_performed.append("l3_cross_reference")
                result.checks_performed.append("l3_cross_reference")
            elif l3p.l3_payment is not None or l3p.l3_checkout is not None:
                pair_result.checks_skipped.append("l3_cross_reference (requires both L3a and L3b)")
                result.checks_skipped.append("l3_cross_reference (requires both L3a and L3b)")

    # 6. Backward compat: populate legacy fields from first pair
    if result.pair_results:
        first = result.pair_results[0]
        result.l3_payment_claims = first.l3_payment_claims
        result.l3_checkout_claims = first.l3_checkout_claims

    result.valid = True
    return result


def _validate_l3_mandate_fields(
    l3_claims: dict,
    l3_label: str,
    required_vct: str,
    l2_payment_mandate: dict | None = None,
) -> str | None:
    """Validate required fields on closed mandates inside L3 delegate_payload.

    Returns an error message string, or None if valid.
    """
    delegates = l3_claims.get("delegate_payload", [])
    found_required_vct = False
    for delegate in delegates:
        if not isinstance(delegate, dict):
            continue
        vct = delegate.get("vct")
        if vct == required_vct:
            found_required_vct = True
        if vct == _L3_PAYMENT_VCT:
            # L3a payment mandate required fields
            payment_field_error = _validate_payment_mandate_required_fields(delegate, f"{l3_label} payment mandate")
            if payment_field_error:
                return payment_field_error
            # Cross-check L3 payment_instrument against L2 authorized value
            pi_err = _validate_l3_payment_instrument(delegate, l2_payment_mandate, l3_label)
            if pi_err:
                return pi_err
        elif vct == _L3_CHECKOUT_VCT:
            # L3b checkout mandate required fields
            for req_field in ("checkout_jwt", "checkout_hash"):
                if not delegate.get(req_field):
                    return f"{l3_label} checkout mandate missing required field: {req_field}"
    if not found_required_vct:
        if required_vct == _L3_PAYMENT_VCT:
            return f"{l3_label} missing required Layer 3 payment mandate disclosure: {required_vct}"
        if required_vct == _L3_CHECKOUT_VCT:
            return f"{l3_label} missing required Layer 3 checkout mandate disclosure: {required_vct}"
        return f"{l3_label} missing required mandate disclosure: {required_vct}"
    return None


def _is_non_empty_string(value) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _validate_payment_mandate_required_fields(mandate: dict, context: str) -> str | None:
    """Validate required fields on closed payment mandates.

    `amount=0` is valid. Empty strings are rejected for required string fields.
    """
    transaction_id = mandate.get("transaction_id")
    if not _is_non_empty_string(transaction_id):
        return f"{context} missing required field: transaction_id"

    payee = mandate.get("payee")
    if payee is None:
        return f"{context} missing required field: payee"
    if not isinstance(payee, dict):
        return f"{context} payee must be an object"
    if not _is_non_empty_string(payee.get("name")):
        return f"{context} payee missing required field: name"
    if not _is_non_empty_string(payee.get("website")):
        return f"{context} payee missing required field: website"

    payment_amount = mandate.get("payment_amount")
    if not isinstance(payment_amount, dict) or not payment_amount:
        return f"{context} missing required field: payment_amount"
    if not _is_non_empty_string(payment_amount.get("currency")):
        return f"{context} payment_amount missing required field: currency"
    amount = payment_amount.get("amount")
    if amount is None:
        return f"{context} payment_amount missing required field: amount"
    if isinstance(amount, bool) or not isinstance(amount, int):
        return f"{context} payment_amount field 'amount' must be an integer"

    payment_instrument = mandate.get("payment_instrument")
    if payment_instrument is None:
        return f"{context} missing required field: payment_instrument"
    if (
        not isinstance(payment_instrument, dict)
        or not _is_non_empty_string(payment_instrument.get("id"))
        or not _is_non_empty_string(payment_instrument.get("type"))
    ):
        return f"{context} payment_instrument missing required field: id and type are required"

    return None


def _validate_l3_payment_instrument(l3_delegate: dict, l2_payment_mandate: dict | None, l3_label: str) -> str | None:
    """Cross-check L3 payment_instrument against L2 authorized payment_instrument.

    Checks whenever L2 specifies a payment_instrument, regardless of open/closed
    VCT. Returns None when L2 has no payment mandate or no payment_instrument.
    """
    if not isinstance(l2_payment_mandate, dict):
        return None
    l2_pi = l2_payment_mandate.get("payment_instrument")
    if not isinstance(l2_pi, dict):
        return None  # L2 missing payment_instrument — caught by required-field checks
    l3_pi = l3_delegate.get("payment_instrument")
    if not isinstance(l3_pi, dict):
        return None  # L3 missing payment_instrument — caught by required-field checks
    if l3_pi.get("id") != l2_pi.get("id") or l3_pi.get("type") != l2_pi.get("type"):
        return (
            f"{l3_label} payment_instrument does not match L2 authorized value: "
            f"L3 id={l3_pi.get('id')}, type={l3_pi.get('type')} vs "
            f"L2 id={l2_pi.get('id')}, type={l2_pi.get('type')}"
        )
    return None


def _extract_mandate_pairs(
    raw_delegates: list,
    resolved_delegates: list,
    disc_str_by_hash: dict[str, str],
    is_autonomous: bool,
) -> tuple[list[tuple[_MandateInfo | None, _MandateInfo | None]], list[str]]:
    """Extract and pair checkout+payment mandates from L2 delegate_payload.

    Returns (pairs, errors). Each pair is (checkout_info, payment_info).
    """
    checkouts: list[_MandateInfo] = []
    payments: list[_MandateInfo] = []

    # 1. Collect mandates and detect duplicate disclosure references
    seen_refs: set[str] = set()
    for raw_item, resolved_item in zip(raw_delegates, resolved_delegates):
        if not isinstance(resolved_item, dict):
            continue
        vct = resolved_item.get("vct", "")
        ref_hash = raw_item.get("...") if isinstance(raw_item, dict) else None

        if ref_hash:
            if ref_hash in seen_refs:
                return [], ["L2 delegate_payload contains duplicate disclosure reference (mandate smuggling)"]
            seen_refs.add(ref_hash)

        disc_b64 = disc_str_by_hash.get(ref_hash) if ref_hash else None
        entry = _MandateInfo(resolved=resolved_item, ref_hash=ref_hash, disc_b64=disc_b64)

        if vct in _CHECKOUT_VCTS:
            checkouts.append(entry)
        elif vct in _PAYMENT_VCTS:
            payments.append(entry)

    # 2. Handle empty cases
    if not checkouts and not payments:
        return [], ["L2 delegate_payload resolved zero mandate disclosures"]

    # 3. Pair when both types present
    if checkouts and payments:
        if not is_autonomous:
            return _pair_immediate(checkouts, payments)
        else:
            return _pair_autonomous(checkouts, payments)

    # 4. Single-type only (partial disclosure in autonomous, error in immediate)
    if not is_autonomous:
        return [], ["Immediate mode requires both checkout and payment mandate disclosures"]

    # Autonomous partial disclosure: single-sided pairs
    pairs: list[tuple[_MandateInfo | None, _MandateInfo | None]] = []
    for c in checkouts:
        pairs.append((c, None))
    for p in payments:
        pairs.append((None, p))
    return pairs, []


def _pair_immediate(
    checkouts: list[_MandateInfo],
    payments: list[_MandateInfo],
) -> tuple[list[tuple[_MandateInfo | None, _MandateInfo | None]], list[str]]:
    """Pair checkout and payment mandates by checkout_hash/transaction_id."""
    # Index checkouts by checkout_hash
    checkout_by_hash: dict[str, _MandateInfo] = {}
    for c in checkouts:
        # Detect open mandates in immediate mode (they lack checkout_hash)
        if c.resolved.get("vct") == _L2_CHECKOUT_VCT_OPEN:
            return [], ["Immediate mode does not allow open checkout mandates (requires final values)"]
        ch = c.resolved.get("checkout_hash", "")
        if not ch:
            return [], ["Closed checkout mandate missing checkout_hash for pairing"]
        if ch in checkout_by_hash:
            return [], ["L2 contains duplicate checkout mandates with same pairing key (checkout_hash collision)"]
        checkout_by_hash[ch] = c

    # Index payments by transaction_id
    payment_by_tid: dict[str, _MandateInfo] = {}
    for p in payments:
        if p.resolved.get("vct") == _L2_PAYMENT_VCT_OPEN:
            return [], ["Immediate mode does not allow open payment mandates (requires final values)"]
        tid = p.resolved.get("transaction_id", "")
        if not tid:
            return [], ["Closed payment mandate missing transaction_id for pairing"]
        if tid in payment_by_tid:
            return [], ["L2 contains duplicate payment mandates with same pairing key (transaction_id collision)"]
        payment_by_tid[tid] = p

    # Match by checkout_hash == transaction_id
    pairs: list[tuple[_MandateInfo | None, _MandateInfo | None]] = []
    matched_payments: set[str] = set()
    for ch, checkout in checkout_by_hash.items():
        if ch in payment_by_tid:
            pairs.append((checkout, payment_by_tid[ch]))
            matched_payments.add(ch)
        else:
            return [], ["Orphaned checkout mandate: no payment mandate with matching transaction_id"]

    for tid in payment_by_tid:
        if tid not in matched_payments:
            return [], ["Orphaned payment mandate: no checkout mandate with matching checkout_hash"]

    return pairs, []


def _pair_autonomous(
    checkouts: list[_MandateInfo],
    payments: list[_MandateInfo],
) -> tuple[list[tuple[_MandateInfo | None, _MandateInfo | None]], list[str]]:
    """Pair open checkout and payment mandates by reference constraint."""
    # Index checkouts by their disclosure ref_hash
    checkout_by_ref: dict[str, _MandateInfo] = {}
    for c in checkouts:
        if not c.ref_hash:
            return [], ["Checkout mandate missing disclosure reference hash for pairing"]
        if c.ref_hash in checkout_by_ref:
            return [], ["L2 contains duplicate checkout mandate disclosure references (pairing key collision)"]
        checkout_by_ref[c.ref_hash] = c

    # Match payments to checkouts via conditional_transaction_id
    pairs: list[tuple[_MandateInfo | None, _MandateInfo | None]] = []
    matched_checkouts: set[str] = set()
    for p in payments:
        ref_constraint = None
        for c in p.resolved.get("constraints") or []:
            if isinstance(c, dict) and c.get("type") == "mandate.payment.reference":
                ref_constraint = c
                break
        if ref_constraint is None:
            return [], ["Open payment mandate missing mandate.payment.reference constraint for pairing"]

        cond_tid = ref_constraint.get("conditional_transaction_id", "")
        if not cond_tid:
            return [], ["mandate.payment.reference constraint missing conditional_transaction_id for pairing"]

        if cond_tid in matched_checkouts:
            return [], ["L2 contains duplicate payment mandates referencing same checkout (pairing key collision)"]

        if cond_tid in checkout_by_ref:
            pairs.append((checkout_by_ref[cond_tid], p))
            matched_checkouts.add(cond_tid)
        else:
            return [], ["Orphaned payment mandate: conditional_transaction_id does not match any checkout disclosure"]

    for ref_hash in checkout_by_ref:
        if ref_hash not in matched_checkouts:
            return [], ["Orphaned checkout mandate: no payment mandate references this checkout"]

    return pairs, []


def _verify_mandate_pair(
    checkout_mandate: dict | None,
    payment_mandate: dict | None,
    checkout_disc_b64: str | None,
    is_autonomous: bool,
) -> tuple[list[str], list[str], list[str]]:
    """Validate open mandate constraints and bindings for a single pair.

    Returns (errors, checks_performed, checks_skipped).
    """
    errors: list[str] = []
    checks_performed: list[str] = []
    checks_skipped: list[str] = []

    # Open mandate contains enforcement
    if checkout_mandate and checkout_mandate.get("vct") == _L2_CHECKOUT_VCT_OPEN:
        constraints = checkout_mandate.get("constraints") or []
        has_line_items = any(
            isinstance(c, dict) and c.get("type") == "mandate.checkout.line_items" for c in constraints
        )
        if not has_line_items:
            return ["Open checkout mandate must contain a mandate.checkout.line_items constraint"], [], []
        checks_performed.append("open_checkout_contains_line_items")

    if payment_mandate and payment_mandate.get("vct") == _L2_PAYMENT_VCT_OPEN:
        constraints = payment_mandate.get("constraints") or []
        has_reference = any(isinstance(c, dict) and c.get("type") == "mandate.payment.reference" for c in constraints)
        if not has_reference:
            return ["Open payment mandate must contain a mandate.payment.reference constraint"], [], []
        pi = payment_mandate.get("payment_instrument")
        if not isinstance(pi, dict) or not pi.get("id") or not pi.get("type"):
            return (
                ["Open payment mandate missing required field: payment_instrument (must have id and type)"],
                [],
                [],
            )
        checks_performed.append("open_payment_has_payment_instrument")
        checks_performed.append("open_payment_contains_reference")

    # Immediate mode validations
    if not is_autonomous:
        if not checkout_mandate or not payment_mandate:
            return ["Immediate mode requires both checkout and payment mandate disclosures"], [], []

        if checkout_mandate.get("vct") == _L2_CHECKOUT_VCT_OPEN:
            return ["Immediate mode does not allow open checkout mandates (requires final values)"], [], []
        if payment_mandate.get("vct") == _L2_PAYMENT_VCT_OPEN:
            return ["Immediate mode does not allow open payment mandates (requires final values)"], [], []

        for mandate, label in [(checkout_mandate, "checkout"), (payment_mandate, "payment")]:
            if "cnf" in mandate:
                return (
                    [
                        f"Immediate mode {label} mandate must not contain cnf claim "
                        "(cnf is for autonomous delegation only)"
                    ],
                    [],
                    [],
                )

        if checkout_mandate.get("vct") == _L2_CHECKOUT_VCT_FINAL:
            for req_field in ("checkout_jwt", "checkout_hash"):
                if not checkout_mandate.get(req_field):
                    return [f"Closed checkout mandate missing required field: {req_field}"], [], []
            checks_performed.append("closed_checkout_required_fields")

        if payment_mandate.get("vct") == _L2_PAYMENT_VCT_FINAL:
            payment_field_error = _validate_payment_mandate_required_fields(payment_mandate, "Closed payment mandate")
            if payment_field_error:
                return [payment_field_error], [], []
            checks_performed.append("closed_payment_required_fields")

        binding_valid, binding_error = verify_checkout_hash_binding(checkout_mandate, payment_mandate)
        if not binding_valid:
            return [f"L2 checkout-payment binding failed: {binding_error}"], [], []
        checks_performed.append("l2_checkout_payment_binding")

    # Autonomous mode: reference binding
    if is_autonomous:
        if checkout_mandate and payment_mandate:
            if not checkout_disc_b64:
                return (
                    ["L2 checkout mandate disclosure string is missing (required for reference binding verification)"],
                    [],
                    [],
                )
            binding_valid, binding_error = verify_l2_reference_binding(
                checkout_mandate, payment_mandate, checkout_disc_b64
            )
            if not binding_valid:
                return [f"L2 reference binding failed: {binding_error}"], [], []
            checks_performed.append("l2_reference_binding")
        else:
            checks_skipped.append("l2_reference_binding (requires both checkout and payment mandates)")

    return errors, checks_performed, checks_skipped


def _extract_agent_key_from_all_pairs(
    mandate_pairs: list[tuple[_MandateInfo | None, _MandateInfo | None]],
) -> tuple[dict | None, str | None, str | None]:
    """Extract the delegated agent key and kid from all L2 open mandates across pairs.

    Returns (jwk, kid, error). kid may be None for backward compatibility
    with L2 mandates that don't include cnf.jwk.kid.
    """
    agent_keys: list[dict] = []
    agent_kids: list[str | None] = []

    for checkout_info, payment_info in mandate_pairs:
        for label, info, expected_vct in [
            ("checkout", checkout_info, _L2_CHECKOUT_VCT_OPEN),
            ("payment", payment_info, _L2_PAYMENT_VCT_OPEN),
        ]:
            if info is None:
                continue
            if info.resolved.get("vct") != expected_vct:
                continue
            cnf = info.resolved.get("cnf")
            jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
            if not isinstance(jwk, dict) or not jwk:
                return None, None, f"L2 {label} open mandate missing cnf.jwk for agent delegation"
            kid = jwk.get("kid") if isinstance(jwk, dict) else None
            agent_keys.append(jwk)
            agent_kids.append(kid)

    if not agent_keys:
        return None, None, None

    # Verify all mandate cnf.jwk values are identical
    first = agent_keys[0]
    for other in agent_keys[1:]:
        if other.get("x") != first.get("x") or other.get("y") != first.get("y"):
            return None, None, "L2 mandate cnf.jwk values must be identical across all pairs but differ"

    # Verify all cnf.jwk.kid values are identical (where present)
    non_none_kids = [k for k in agent_kids if k is not None]
    if non_none_kids:
        first_kid = non_none_kids[0]
        for other_kid in non_none_kids[1:]:
            if other_kid != first_kid:
                return None, None, "L2 mandate cnf.jwk.kid values must be identical across all pairs but differ"
        return first, first_kid, None

    return first, None, None
