# Verifiable Intent — External State Attestation Constraint Proposal

**Type identifier**: `environment.market_state`
**Version**: 0.5-draft
**Status**: Draft / Proposed for Registration
**Date**: 2026-04-19
**Author**: Headless Oracle Project (headlessoracle.com)
**License**: Apache 2.0

## Abstract

This document proposes a new Verifiable Intent (VI) constraint type —
`environment.market_state` — for registration in the VI constraint type
registry defined in [constraints.md §6.2](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md#62-constraint-type-registry).

It is the first constraint type in the proposed `environment.*` namespace. A
companion sibling constraint — [`environment.wallet_state`](./environment-wallet-state.md)
(PR #22) — shares this document's algorithm shape, fail-closed rules, freshness
semantics, and algorithm agility framing. The two specifications are
intentionally structured to compose as peers in a single mandate.

The `environment.market_state` constraint is a **pre-execution environment
gate**: it requires an AI agent to obtain a cryptographically signed external
state attestation from a verified oracle and confirm it satisfies a specified
condition _before_ constructing a Layer 3 fulfillment. If the attestation
cannot be obtained, cannot be verified, or does not satisfy the expected
condition, the constraint is not satisfied and the agent MUST NOT proceed to
Layer 3 creation.

**Fail-closed by design.** Any failure in the attestation pipeline — network
error, signature mismatch, expiry, status mismatch — causes the constraint to
fail. An agent that cannot verify the external state of the world is an agent
that must not act.

The primary motivation is financial execution safety. Autonomous agents that
execute trades, redeem positions, or trigger payments during market halts or
closed sessions cause real, non-reversible harm. A cryptographically attested
market state check — enforced at the mandate layer — prevents this class of
error structurally rather than by convention.

This specification covers:
- The `environment.market_state` constraint schema
- The attestation verification algorithm agents and verifiers MUST implement
- Fail-closed failure handling requirements
- Normative freshness semantics as the primary security property (§4.6)
- Algorithm agility framing for the `environment.*` family (§4.7)
- Security considerations specific to external state dependencies
- A reference implementation (Headless Oracle)

### Companion Documents

| Document | Description |
|----------|-------------|
| [constraints.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md) | VI normative constraint type definitions and validation rules |
| [credential-format.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/credential-format.md) | Normative credential format, claim tables, and serialization |
| [security-model.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/security-model.md) | Threat model and security analysis |
| [design-rationale.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/design-rationale.md) | Why SD-JWT, algorithm choices |
| [environment-wallet-state.md](./environment-wallet-state.md) | Sibling `environment.wallet_state` constraint (PR #22) |
| [Headless Oracle SMA Protocol](https://github.com/LembaGang/sma-protocol) | Signed Market Attestation (SMA) — the state receipt format consumed by this constraint |
| [Agent Pre-Trade Safety Standard (APTS)](https://github.com/LembaGang/agent-pretrade-safety-standard) | Six-check pre-execution safety checklist that this constraint mechanises |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119] and [RFC 8174] when, and only when, they
appear in ALL CAPITALS, as shown here.

JSON data structures follow [RFC 8259]. All field names are case-sensitive.

The term **attestation** refers to a JSON object representing a signed external
state claim conforming to the Signed Market Attestation (SMA) protocol or any
compatible state receipt format that satisfies the verification requirements in §4.

---

## 2. Overview

### 2.1 What This Constraint Is

`environment.market_state` is a **pre-execution environment gate**. It
instructs the verifying agent or verifier to:

1. Fetch a signed state attestation from a designated oracle endpoint
2. Verify the Ed25519 signature against the oracle's published public key
3. Confirm the attestation is not expired
4. Confirm the attested status matches the expected value
5. Proceed to Layer 3 creation _only if all four checks pass_

The constraint encodes the user's intent that the agent MUST NOT execute during
an invalid market environment — regardless of whether the agent would otherwise
be authorised to act.

This is distinct from all currently registered VI constraint types (§4 of
[constraints.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md)),
which gate _what_ the agent may do (which merchants, which items, what amounts).
`environment.market_state` gates _when_ the agent may do it.

It is structurally identical to [`environment.wallet_state`](./environment-wallet-state.md)
(§2.1 of the companion document). Both constraints gate _when_ the agent may
act on verified external world state, not _what_ the agent may do with it. Both
are siblings in the `environment.*` namespace and compose as peers in a single
mandate.

### 2.2 Where This Constraint Appears

`environment.market_state` MAY appear in **both** VI Autonomous mode mandate
types:

- **Checkout mandate** (`vct: "mandate.checkout.open.1"`): Prevents checkout
  initiation during market closure or halt. Typical `expected_status`: `"OPEN"`.
- **Payment mandate** (`vct: "mandate.payment.open.1"`): Prevents payment
  authorisation outside valid trading sessions. Typical `expected_status`: `"OPEN"`.

When present in both mandates of a single delegated action, both constraints
MUST be satisfied independently. A constraint in the checkout mandate does not
satisfy a constraint in the payment mandate.

**Namespace**: `environment.*`. This is the first type proposed for this
namespace, with `environment.wallet_state` (PR #22) proposed as a sibling.
Future types in this namespace might include `environment.regulatory_status`,
`environment.counterparty_credit`, `environment.infrastructure_health`, or
`environment.identity_revocation`. The `environment.*` family shares a common
shape (fetch + cryptographically verify + match expected state, all
fail-closed) and composition model (evaluated before transactional constraints,
independently re-verified at L3 check time).

### 2.3 Relationship to `environment.wallet_state`

This draft and [`environment.wallet_state`](./environment-wallet-state.md)
(PR #22) are coordinated siblings. They share:

- The same section layout, fail-closed idiom, and lifecycle model
- The same composition model (§4.5 includes a joint example showing both
  constraints in a single mandate)
- The same execution-order rationale (§5.2)
- The same freshness semantics (§4.6): `max_attestation_age` is a family-wide
  field with identical meaning across all `environment.*` constraint types
- The same algorithm agility framing (§4.7): family-level agility per RFC 8725
  §3.1, with a per-type mandatory algorithm and recommended/optional extension sets

The two specs differ where their subject state differs — this constraint binds
to a market session identified by a MIC code and the receipt format is the SMA
protocol; `environment.wallet_state` binds to a wallet address identified by
JWT `sub` claim and the receipt format is ES256/JWS. Both patterns are
defensible from their respective reference implementations' signing stacks, and
both are captured by the algorithm agility framework in §4.7.

### 2.4 Lifecycle

1. **Creation**: The user, or the user's agent wallet / credential issuer,
   includes an `environment.market_state` constraint in the Layer 2 mandate at
   issuance time, specifying the oracle endpoint, the oracle's public key ID,
   the required market status, and the maximum acceptable attestation age.
2. **Binding**: The constraint is included in the selectively-disclosable
   mandate claims within Layer 2. It is signed as part of the KB-SD-JWT+KB
   envelope — any post-issuance modification invalidates the user's signature.
3. **Fulfillment gate**: Before the agent constructs Layer 3, it MUST fetch
   and verify the attestation specified in the constraint. If verification
   fails, the agent MUST NOT create Layer 3. There is no retry loop — a failed
   attestation check is a hard stop.
4. **Verification**: The verifier (merchant or payment network) re-validates
   the constraint at Layer 3 checking time using the same algorithm the agent
   used, fetching a fresh attestation if the agent-time attestation has expired.
   The verifier MUST NOT accept an agent's assertion that the constraint was
   satisfied — it MUST independently verify.

### 2.5 Fulfillment Model

Unlike registered VI constraint types that compare L2 constraints against L3
fulfillment values (derived from L3 mandate fields), `environment.market_state`
validation requires a live external fetch. The constraint is satisfied or
violated at the moment of verification based on a freshly obtained attestation,
not by comparing L2 to L3 fields.

This is an intentional design choice. Market state is ephemeral — an
attestation obtained at agent time may not reflect market state at verifier
time. Verifiers MUST perform independent attestation verification, not rely on
the agent's L3 claims about market state.

**Layer 3 evidence field**: Agents SHOULD include a
`market_state_attestation` field in the Layer 3 mandate containing the full
signed attestation receipt (as a JSON object). This provides a cryptographic
audit record of the market state the agent observed when constructing L3.
Verifiers MAY use this field to audit the agent's decision context, but MUST
NOT use it as a substitute for independent verification.

---

## 3. Constraint Structure

### 3.1 Common Schema (inherited from constraints.md §3.1)

Every VI constraint is a JSON object with a REQUIRED `type` field:

```json
{
  "type": "<domain>.<name>",
  ...additional type-specific fields...
}
```

`environment.market_state` follows this common structure with the
type-specific fields defined in §4.

### 3.2 Registration

This constraint is proposed for registration in the `environment.*` namespace,
which extends the VI constraint type registry (constraints.md §6.2) with a new
domain for environmental pre-conditions. Proposed registration entry:

| Type | Defined In | Version | Disclosure Form |
|------|-----------|---------|-----------------|
| `environment.market_state` | This document | 0.2-draft | property (full constraint) |

---

## 4. The `environment.market_state` Constraint

### Purpose

Require a cryptographically signed, unexpired market state attestation from a
verified oracle, confirming that the target market is in the expected state,
before the agent may proceed to Layer 3 fulfillment.

The constraint is fail-closed: any failure in the attestation pipeline —
including network errors, signature failures, and expiry — causes the
constraint to be treated as violated. The agent MUST NOT proceed on uncertainty.

### Appears In

- Checkout mandate (`mandate.checkout.open.1`) `constraints` array
- Payment mandate (`mandate.payment.open.1`) `constraints` array

### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"environment.market_state"` |
| `attestation_url` | string (HTTPS URL) | Yes | Endpoint to fetch the signed state attestation from. MUST be an HTTPS URL. The response MUST be a JSON attestation object conforming to §4.1. |
| `oracle_public_key_id` | string | Yes | The `key_id` value identifying the signing key in the oracle's key registry. The verifier MUST match this value against the `public_key_id` field in the fetched attestation and retrieve the corresponding public key from the oracle's `/.well-known/oracle-keys.json` endpoint. |
| `expected_status` | string | Yes | The attested status value the attestation MUST carry for this constraint to be satisfied. For market state: typically `"OPEN"`. Other values: `"CLOSED"` (for settlement-window checks). MUST NOT be `"UNKNOWN"` or `"HALTED"` — constraints requiring a halted or unknown market state are malformed and MUST be rejected. |
| `max_attestation_age` | integer | Yes | Maximum age in seconds of the attestation, measured from `issued_at` to the time of verification. MUST be a positive integer. Verifiers MUST reject attestations where `(now − issued_at) > max_attestation_age`, even if `expires_at` has not yet passed. A well-formed constraint MUST include this field; a missing `max_attestation_age` is a malformed constraint and verifiers MUST reject it (see §4.2 Step 1). There is no default value. See §4.6 for rationale. |
| `stale_cache_fallback_permitted` | boolean | No | Whether verifiers MAY use an expired key registry cache as a last-resort fallback when fresh key registry fetch fails. Verifiers MUST apply a default of `false` when absent. Deployments with strict freshness requirements (e.g., payment execution) MUST NOT set this to `true`. See §6.8 for companion verifier behaviour on fetch failure. |

#### Field Constraints

- `attestation_url` MUST use the `https` scheme. Non-HTTPS URLs MUST be
  rejected as a constraint violation (fail-closed; unencrypted oracle traffic
  is untrusted by definition).
- `oracle_public_key_id` MUST be a non-empty string. An empty string MUST be
  treated as a malformed constraint and rejected.
- `expected_status` MUST be a non-empty string drawn from the oracle's
  documented status enum. The values `"UNKNOWN"` and `"HALTED"` are
  permanently excluded: no well-formed constraint should require that a market
  be unknown or halted before the agent may act.
- `max_attestation_age` MUST be a positive integer (`>= 1`). Values less than
  `1` MUST be rejected as malformed. A missing `max_attestation_age` field is a
  malformed constraint and verifiers MUST reject such constraints per §4.2
  Step 1. There is no default value; all mandate issuers MUST declare an
  explicit TOCTOU window for each `environment.market_state` constraint. The
  freshness window is the primary exploitable surface (§4.6); silent defaults
  leave that surface undefined at the deployment boundary.
- `stale_cache_fallback_permitted`, if present, MUST be a strict boolean.
  Non-boolean values (including string `"false"`, `null`, or numeric) MUST be
  rejected as malformed per §4.2 Step 1. When absent, verifiers MUST apply a
  default of `false`; see §6.8 for the companion verifier behaviour on key
  registry fetch failure.

### 4.1 Attestation Object Format

The object returned by `attestation_url` MUST include the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | The attested market state: `OPEN`, `CLOSED`, `HALTED`, or `UNKNOWN`. |
| `issued_at` | ISO 8601 | Timestamp when the attestation was signed by the oracle. |
| `expires_at` | ISO 8601 | Timestamp after which the attestation MUST NOT be acted upon. |
| `public_key_id` | string | Identifier for the signing key used. MUST match `oracle_public_key_id` in the constraint. |
| `issuer` | string (FQDN) | Oracle operator identity. Agents resolve `{issuer}/.well-known/oracle-keys.json` to fetch the signing public key. |
| `receipt_id` | string (UUID v4) | Unique attestation identifier for deduplication and audit logging. |
| `signature` | string (hex) | Signature over the canonical payload. Algorithm MUST match the MUST-implement or a negotiated extension per §4.7; for this constraint type the MUST-implement is Ed25519 (RFC 8032). Signed over all fields except `signature`, sorted alphabetically, serialized as compact JSON, encoded as UTF-8. |

Additional signed fields (e.g., `source`, `schema_version`, `receipt_mode`,
`mic`, `halt_detection`) MAY be present in the attestation. All signed fields
are included in signature verification. Verifiers MUST NOT strip signed fields
before verification.

**Response envelope vs signed attestation**: The HTTP response body returned by
`attestation_url` MAY include unsigned wrapper fields alongside the signed
attestation — for example, `discovery_url`, an `extensions` object, or a nested
duplicate of the attestation under a `receipt` key. These wrapper fields are
NOT part of the signed attestation and MUST NOT be included in the canonical
payload during signature verification. Verifiers MUST canonicalise only the
signed attestation fields as enumerated in the oracle's published canonical
payload specification. For the Headless Oracle reference implementation this
specification is exposed at `{issuer}/v5/keys → canonical_payload_spec.receipt_fields`.
In the algorithm of §4.2, the symbol `A` refers to this signed subset of the
response body, not the full response body.

**Key discovery**: Verifiers MUST resolve the public key by fetching
`{attestation.issuer}/.well-known/oracle-keys.json` and locating the entry
where `key_id == attestation.public_key_id`. This follows RFC 8615 and the
SMA Protocol key discovery specification.

### 4.2 Validation Algorithm

**Pre-condition**: This algorithm MUST be executed before the agent creates
Layer 3. Verifiers MUST repeat this algorithm independently at Layer 3
verification time (with a fresh attestation fetch if the agent's attestation
has expired).

**Input**: constraint `C` (an `environment.market_state` object), current time `now`.

**Fail-closed rule**: Any step that cannot be completed successfully MUST
produce a **violation**. There is no partial credit and no fallback to a
permissive default.

```
function check_environment_market_state(C, now):

    # Step 1 — Validate constraint structure
    if C.attestation_url does not start with "https://":
        return violation("Non-HTTPS attestation_url: fail-closed")
    if C.oracle_public_key_id is empty:
        return violation("Empty oracle_public_key_id: constraint malformed")
    if C.expected_status is "UNKNOWN" or "HALTED":
        return violation("expected_status must not be UNKNOWN or HALTED")
    if C.max_attestation_age is absent:
        return violation("max_attestation_age is REQUIRED; constraint is malformed: fail-closed")
    let max_age = C.max_attestation_age
    if max_age < 1:
        return violation("max_attestation_age must be >= 1")
    if C.stale_cache_fallback_permitted is present and not boolean:
        return violation("stale_cache_fallback_permitted must be boolean if present: fail-closed")

    # Step 2 — Fetch attestation (timeout: 4 seconds)
    let response = http_get(C.attestation_url, timeout=4s)
    if request fails (timeout, DNS, connection error, non-2xx response):
        return violation("Attestation fetch failed: fail-closed")
    let A = parse_json(response.body)
    if parse fails:
        return violation("Attestation response is not valid JSON: fail-closed")

    # Step 3 — Verify key identity
    if A.public_key_id != C.oracle_public_key_id:
        return violation("Attestation public_key_id does not match oracle_public_key_id")

    # Step 4 — Fetch oracle public key
    let key_registry_url = "https://" + A.issuer + "/.well-known/oracle-keys.json"
    let key_registry = http_get(key_registry_url, timeout=4s)
    if request fails:
        return violation("Oracle key registry unreachable: fail-closed")
    let keys = parse_json(key_registry).keys
    let key_entry = find(keys, k => k.key_id == A.public_key_id)
    if key_entry is null:
        return violation("Signing key not found in oracle key registry: fail-closed")
    if key_entry.valid_until is not null and key_entry.valid_until < now:
        return violation("Oracle signing key has expired: fail-closed")

    # Step 5 — Verify signature (algorithm per §4.7; MUST-implement is Ed25519)
    let payload_fields = all fields of A except "signature"
    let canonical = JSON.stringify(alphabetical_sort(payload_fields))  # compact, no whitespace
    let public_key_bytes = hex_decode(key_entry.public_key)
    let signature_bytes = hex_decode(A.signature)
    let valid = ed25519_verify(signature_bytes, utf8_encode(canonical), public_key_bytes)
    if not valid:
        return violation("Attestation signature verification failed: fail-closed")

    # Step 6 — Verify attestation is not expired
    if now > parse_iso8601(A.expires_at):
        return violation("Attestation has expired (expires_at in past): fail-closed")

    # Step 7 — Verify attestation age against max_attestation_age
    let age_seconds = (now - parse_iso8601(A.issued_at)).total_seconds()
    if age_seconds > max_age:
        return violation("Attestation age exceeds max_attestation_age: fail-closed")

    # Step 8 — Verify status
    if A.status != C.expected_status:
        return violation(
            "Market status is " + A.status + ", expected " + C.expected_status + ": constraint not satisfied"
        )

    # All checks passed
    return satisfied(receipt_id=A.receipt_id)
```

**Processing order is normative.** Steps MUST be executed in order. A failure
at any step terminates the algorithm with a violation; subsequent steps MUST
NOT be executed.

**Receipt ID logging**: On satisfaction, agents and verifiers MUST log the
`receipt_id` value in their execution audit trail. This enables post-hoc
verification that the market state on which a decision was made was a legitimate,
signed attestation — not a spoofed or replayed response.

### 4.3 UNKNOWN and HALTED Status Handling

The oracle may return `status: "UNKNOWN"` or `status: "HALTED"` in legitimate
attestations. These values MUST always cause the constraint to be violated:

- `UNKNOWN` — the oracle cannot determine the market state. An uncertain world
  is a closed world for agent execution purposes.
- `HALTED` — the market is in an emergency halt. No execution is permitted
  until a signed `OPEN` attestation is obtained.

This fail-closed semantic is non-negotiable. An agent that proceeds to
execution on `UNKNOWN` market state is operating outside the safety boundary
established by this constraint.

### 4.4 Attestation Staleness During Verification

A verifier checking Layer 3 at time `T` MUST fetch a fresh attestation from
`attestation_url` if the attestation the agent embedded in L3
(per §2.5 RECOMMENDED field) is expired at time `T`. The verifier MUST apply
the full verification algorithm (§4.2) to the freshly fetched attestation.

If the fresh attestation shows a status different from `expected_status`
(e.g., the market closed between agent execution and verifier checking),
the verifier MUST treat the constraint as violated. The agent executed in a
valid environment; the verifier is recording that the environment has since
changed. Dispute resolution in this case is an application-layer concern
outside this specification.

### 4.5 Example

Checkout mandate constraint requiring NYSE to be OPEN before agent checkout:

```json
{
  "type": "environment.market_state",
  "attestation_url": "https://headlessoracle.com/v5/demo?mic=XNYS",
  "oracle_public_key_id": "key_2026_v1",
  "expected_status": "OPEN",
  "max_attestation_age": 60
}
```

Payment mandate constraint with the same gate, requiring authenticated
attestation for production execution:

```json
{
  "type": "environment.market_state",
  "attestation_url": "https://headlessoracle.com/v5/status?mic=XNYS",
  "oracle_public_key_id": "key_2026_v1",
  "expected_status": "OPEN",
  "max_attestation_age": 30
}
```

> **Note on `/v5/demo` vs `/v5/status`**: `/v5/demo` is the public unauthenticated
> endpoint returning `receipt_mode: "demo"`. Sufficient for development and testing.
> `/v5/status` requires an `X-Oracle-Key` header and returns `receipt_mode: "live"`.
> Production mandates SHOULD use `/v5/status` (authenticated) and SHOULD set
> `max_attestation_age` ≤ 60 to match the oracle's 60-second receipt TTL.

Composition with `environment.wallet_state` — both constraints in a single
mandate, both MUST be satisfied before L3:

```json
{
  "vct": "mandate.checkout.open.1",
  "constraints": [
    {
      "type": "environment.market_state",
      "attestation_url": "https://headlessoracle.com/v5/demo?mic=XNYS",
      "oracle_public_key_id": "key_2026_v1",
      "expected_status": "OPEN",
      "max_attestation_age": 60
    },
    {
      "type": "environment.wallet_state",
      "attestation_url": "https://api.insumermodel.com/v1/attest",
      "trusted_jwks": "https://api.insumermodel.com/.well-known/jwks.json",
      "expected_kid": "insumer-attest-v1",
      "expected_issuer": "https://api.insumermodel.com",
      "subject_wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      "required_condition_hashes": [
        "0xc938b71ac78df5843d6823dd78ee0a5b64dd56fa850984e954dd070285169444"
      ],
      "max_attestation_age": 300,
      "attestation_request_body": {
        "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "conditions": [
          { "type": "token_balance", "chainId": 1, "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "decimals": 6, "threshold": 1 }
        ],
        "format": "jwt"
      }
    },
    {
      "type": "mandate.checkout.allowed_merchants",
      "allowed": [
        { "name": "Alpaca Markets", "website": "https://alpaca.markets" }
      ]
    }
  ]
}
```

This is the composition the `environment.*` namespace is designed to make
expressible: *NYSE must be open **and** my wallet must still hold ≥1 USDC on
Ethereum* — both checks independently signed, independently verifiable,
independently fail-closed.

Multi-exchange example — both NYSE and LSE must be OPEN (two
`environment.market_state` constraints, both must satisfy):

```json
{
  "vct": "mandate.checkout.open.1",
  "constraints": [
    {
      "type": "environment.market_state",
      "attestation_url": "https://headlessoracle.com/v5/demo?mic=XNYS",
      "oracle_public_key_id": "key_2026_v1",
      "expected_status": "OPEN",
      "max_attestation_age": 60
    },
    {
      "type": "environment.market_state",
      "attestation_url": "https://headlessoracle.com/v5/demo?mic=XLON",
      "oracle_public_key_id": "key_2026_v1",
      "expected_status": "OPEN",
      "max_attestation_age": 60
    },
    {
      "type": "mandate.checkout.allowed_merchants",
      "allowed": [
        { "name": "Alpaca Markets", "website": "https://alpaca.markets" }
      ]
    }
  ]
}
```

For batch attestation (multiple exchanges in a single request), use the oracle's
`/v5/batch` endpoint. In this case, `attestation_url` points to the batch endpoint
and `expected_status` applies to the exchange identified in the response array.
Batch handling is outside this specification's scope and deferred to a companion
document.

### 4.6 Attestation Freshness and TOCTOU

The `max_attestation_age` field is the mandate issuer's normative declaration
of the maximum acceptable TOCTOU window between attestation signing and
constraint evaluation. It is the primary security property of any
`environment.*` constraint: the freshness window is the exploitable surface.

**Why this field is REQUIRED.** Market execution history provides a clear
catalogue of TOCTOU races caused by stale or implicit freshness windows.
The 2010 Flash Crash (~$1T in market value evaporated and recovered in 36
minutes) demonstrated how execution into rapidly-changing session state
produces non-reversible harm. Circuit breaker races — where an agent confirms
an OPEN market and then executes milliseconds into a Level 1/2/3 halt — are
the same class of bug at a shorter horizon. The 2020 CME WTI crude oil futures
contract settled at $-37.63 per barrel in part because automated systems
continued to act against a market state that no longer matched their cached
view. When freshness is left as an implementation default rather than an
explicit policy declaration, exploitable gaps are the norm, not the exception.

Attestation TTL (the oracle's `expires_at` claim) is a provider-side default;
`max_attestation_age` is a consumer-side policy bound. The two serve different
principals and MUST be independently configurable.

**Family-wide semantics.** For any `environment.*` constraint,
`max_attestation_age` carries the same meaning: the mandate issuer's
declaration of the maximum acceptable TOCTOU window between attestation
signing (`issued_at` or `iat`) and constraint evaluation (`now`). This field
SHOULD use the same name and semantics across all `environment.*` constraint
types to enable a single verification code path. The
[`environment.wallet_state`](./environment-wallet-state.md) specification (PR #22)
adopts this field and semantics identically; this specification adopts them in
lockstep.

**Guidance for mandate issuers.** Values SHOULD reflect the economic risk
of the gated action. Payment execution against volatile instruments may warrant
`max_attestation_age: 15`; compliance checks against scheduled session state
may tolerate `max_attestation_age: 60`. The reference implementation (§7)
issues attestations with a 60-second TTL; mandate issuers can narrow this to
any shorter window via `max_attestation_age`. Session-boundary races
(open/close, circuit breaker transitions) typically warrant the tightest
windows the oracle's TTL permits.

### 4.7 Algorithm Agility

**Family-wide policy.** The `environment.*` constraint family is
algorithm-agnostic at the family level, per [RFC 8725] §3.1 ("Algorithm
Verification"). Each constraint type declares a MUST-implement signing
algorithm that all conformant verifiers for that type MUST support:

| Constraint type | MUST-implement | Rationale |
|-----------------|---------------|-----------|
| `environment.market_state` | Ed25519 | Matches the reference implementation's signing stack (Headless Oracle, `@noble/ed25519`); high-performance single-curve verification; RFC 8032 deterministic signatures. |
| `environment.wallet_state` | ES256 (P-256) | Composes with VI's existing ES256/SD-JWT stack (design-rationale §5); standard JWS base64url encoding, no custom canonicalization required. |

Each constraint type SHOULD additionally support a RECOMMENDED extension set
and MAY support further algorithms. For `environment.market_state`:

- MUST: `Ed25519` (EdDSA with Ed25519 curve per RFC 8032)
- SHOULD: `ES256` (for oracles whose signing stack aligns with the VI JWS path)
- MAY: `Ed448`, `ES384`, `ES512`

Verifiers negotiate the algorithm per constraint instance by reading the
attestation's algorithm declaration (the SMA protocol includes this as a
`signature_algorithm` field where present; where absent, Ed25519 is assumed)
and confirming it is in their supported set for the constraint type. Verifiers
MUST reject attestations whose algorithm is not in their supported set — this
is a fail-closed check, not a silent downgrade.

**Avoiding accidental single-algorithm lock-in.** This agility model ensures
the `environment.*` family does not inherit a single-algorithm constraint by
accident. Each type's MUST-implement choice is defensible from its reference
implementation's signing stack; the extension sets ensure verifier libraries
can evolve without spec revisions.

**Algorithm-deprecation discipline.** Algorithm deprecation within a
registered family member is a per-type concern. Type specification authors
SHOULD specify, in the type's specification, a deprecation mechanism for
the type's MUST-implement algorithm before that algorithm is needed —
including the conditions under which the algorithm is deprecated, the
timeline for verifier migration to a successor MUST-implement, and the
backward-compatibility guarantees during the transition. The family-wide
obligation is structural: every type specification MUST declare its current
MUST-implement algorithm, and verifiers MUST honour the declaration without
fallback. Deprecation discipline ensures that the family does not inherit a
brittle commitment to any specific algorithm beyond the cryptographic
lifetime that algorithm provides.

**`environment.market_state` deprecation mechanism.**

- **Conditions.** A successor MUST-implement is declared in a minor-version
  revision of this specification when (a) cryptographic guidance from a
  recognized standards body (NIST, IRTF CFRG, an update to [RFC 8032] or
  [RFC 8725]) recommends migration away from the current MUST-implement, or
  (b) the current MUST-implement is broken in the cryptographic literature
  in a way that affects the type's threat model.
- **Timeline.** The minor-version revision declaring the successor specifies
  a verifier-migration window of at least 12 months from publication. During
  the window, verifiers MUST accept attestations signed under either the
  current MUST-implement or the successor. After the window's end date
  (named in the minor-version revision), verifiers MUST reject attestations
  signed under the deprecated algorithm.
- **Backward compatibility.** Mandate issuers SHOULD migrate to the
  successor as soon as their attestation issuer supports it. Attestation
  issuers signal successor-algorithm support by publishing the new key in
  the [RFC 8615] well-known key registry at
  `{issuer}/.well-known/oracle-keys.json`; verifiers detect issuer
  readiness via standard key-set inspection of that registry.

> **Note on family coordination**: This section is drafted in lockstep with
> [§4.7 of `environment.wallet_state`](./environment-wallet-state.md). The
> two specs declare different MUST-implement algorithms (Ed25519 here, ES256
> in wallet_state) for reasons tied to their reference implementations' signing
> stacks, but share the agility framework, the extension-set model, the
> fail-closed-negotiation requirement, and the family-wide algorithm-
> deprecation discipline (the algorithm-agnostic policy paragraph,
> single-algorithm lock-in paragraph, and family-wide deprecation paragraph
> are verbatim-portable; per-type MUST-implement table rows and the per-type
> deprecation mechanism block are the per-type swap surface). One family-wide
> question, one answer, two specs.

### 4.8 Field Scope Declaration

The `environment.*` constraint family contains fields that appear under identical names in multiple constraint types. A shared field name does not, by itself, imply shared semantics: some fields carry identical meaning across types, while others have parallel-but-mechanism-specific meaning tied to each type's trust-root mechanism. To prevent ambiguity, each field in the family MUST declare its scope under one of the categories below.

**Scope categories.** The family currently recognises three scope categories:

- **family-wide-trust-root-agnostic** — the field carries identical semantics across every `environment.*` constraint type, independent of the trust-root mechanism each type uses. A single verification code path handles the field for every type in the family.

- **per-type-trust-root-mechanism-bound** — the field's operational semantics depend on the specific trust-root mechanism of the constraint type (RFC 7517 JWKS for `environment.wallet_state`, RFC 8615 key registry for `environment.market_state`, or a future mechanism). The field name may appear in multiple specifications with parallel but mechanism-specific semantics.

- **per-type-evaluation-mechanism-bound** — the field's operational semantics depend on the constraint type's evaluation mechanism: the output shape the evaluator produces (for example, condition-hash sets for `environment.wallet_state`, status enum for `environment.market_state`) or the wire-protocol binding to the evaluator (for example, the request body shape sent to `attestation_url`). The field name may appear in multiple specifications with parallel but evaluation-specific semantics; distinct from `per-type-trust-root-mechanism-bound` in that the binding is to *how the attestation is produced and shaped*, not to *how the signing key is discovered*.

Within §4.8, 'field' encompasses both constraint schema fields declared in §4 and, where operationally relevant, JWT claims declared in §4.1.

**Scope declarations for current `environment.market_state` fields.**

| Field | Scope | Reference |
|-------|-------|-----------|
| `max_attestation_age` | family-wide-trust-root-agnostic | §4.6 |
| `attestation_url` | family-wide-trust-root-agnostic | §4.1 |
| `stale_cache_fallback_permitted` | per-type-trust-root-mechanism-bound | §6.8 |
| `oracle_public_key_id` | per-type-trust-root-mechanism-bound | §6.3 |
| `expected_status` | per-type-evaluation-mechanism-bound | §4.1 |

`max_attestation_age` is family-wide because the freshness window is a temporal property of the attestation signing event itself, independent of how the verifier retrieves the signing key. `stale_cache_fallback_permitted` is per-type because the failure mode of "stale cache fallback" is defined only against the specific cache of the constraint type's trust-root mechanism — the JWKS cache for `environment.wallet_state`, the RFC 8615 key registry cache for `environment.market_state` — and the recovery behaviour (and trust-root binding implications per §6.3) differs between mechanisms. `attestation_url` is family-wide-trust-root-agnostic because its semantic role — the HTTPS endpoint at which the verifier fetches the signed attestation — is identical across every `environment.*` constraint type, whether signing keys are discovered via RFC 7517 JWKS or RFC 8615 key registry. Per-type variance in the wire protocol (HTTP verb, request-body shape) is carried by each type's §4.1 interface specification and, where present, by per-type evaluation-mechanism-bound fields on the sibling specification (`attestation_request_body` on `environment.wallet_state`), not by the URL field itself, which names only location. The placement lands on the same basis as `max_attestation_age` in §4.6: identical semantic role across types, with per-type variance localised at neighbouring fields. `oracle_public_key_id` is per-type-trust-root-mechanism-bound because it is an RFC 8615 key registry identifier binding specific to the key-discovery mechanism `environment.market_state` uses for attestation signature verification; the sibling `environment.wallet_state` specification uses a distinct key-identifier field (`expected_kid`) against its RFC 7517 JWKS mechanism, with parallel but mechanism-specific semantics. `expected_status` is per-type-evaluation-mechanism-bound because it is a status-enum binding specific to `environment.market_state`'s evaluation mechanism: the constraint names the attested market-session status the verifier must match (per §4 schema, `OPEN` or `CLOSED`) against the attestation's session-status output (per §4.1); the sibling `environment.wallet_state` specification uses `required_condition_hashes` as the analogous evaluation-mechanism-bound field — a different per-type evaluation primitive (hash-set membership rather than status-enum equality) for the same structural role.

**Rule for future fields.** New fields introduced in any `environment.*` constraint type in future specification revisions MUST declare their scope category at introduction. Declarations are made in the constraint type's Field Scope Declaration section (this section, §4.8 in `environment.market_state`; the analogous section in each sibling specification). Additions of new scope categories beyond the three currently recognised are working-group revisions; type authors SHOULD place fields under one of the existing categories where possible rather than proposing new categories.

**Relationship to §4.6 and §4.7.** This section formalises at charter level the field-scope distinction that §4.6 (freshness) and §4.7 (algorithm agility) already imply in their specific domains: §4.6 states that `max_attestation_age` is family-wide; §4.7 establishes per-type MUST-implement algorithms with family-wide agility framework. §4.8 makes the underlying scope discipline — "which fields are family-wide, which are per-type, and why" — explicit so that future fields are not added to the family without a scope declaration.

> **Note on family coordination**: Drafted as a standalone block adoptable verbatim in `environment.wallet_state` §4.8 with the field table rows swapped for that specification's current fields (`trusted_jwks`, `subject_wallet`, and the sibling declaration of `stale_cache_fallback_permitted` under its JWKS-specific mechanism). Same pattern as §4.6, §4.7, §5.5, §6.8 — one family-wide question, one answer, two specs.

---

## 5. Validation Algorithm Integration

### 5.1 Integration with constraints.md §5.3

The `environment.market_state` constraint integrates into the VI constraint
validation algorithm (constraints.md §5.3) as a registered type. Verifiers
implementing the full VI constraint checker MUST include this type in the
`registered types` branch:

```
for each constraint in constraints:
    ctype = constraint.type

    if ctype == "environment.market_state":
        run check_environment_market_state(constraint, now)
    else if ctype == "environment.wallet_state":
        run check_environment_wallet_state(constraint, now)
    else if ctype is another registered type:
        ...
```

### 5.2 Execution Order

`environment.*` constraints (of any type) MUST be evaluated **before** all
transactional constraint types in the same mandate. Within the `environment.*`
family, evaluation order is implementation-defined except where a specific
ordering dependency is documented. If any `environment.*` constraint fails,
the agent MUST NOT evaluate remaining constraints and MUST NOT proceed to L3
creation.

Note that §5.5 Block 3 further governs verifier-side evaluation: while this section requires agents to stop at the first `environment.*` failure before L3 creation, verifiers MUST continue evaluating remaining `environment.*` constraints to completion for diagnostic-completeness purposes — see §5.5 Block 3.

**Rationale**: Evaluating amount or merchant constraints before confirming the
execution environment is valid exposes the agent to a TOCTOU race — the agent
might confirm a valid amount constraint and then execute into a closed market,
or into a wallet that no longer satisfies the entry condition. Environment
constraints gate execution; they are not co-equal with transactional
constraints. This rationale is shared 1:1 with §5.2 of
[`environment.wallet_state`](./environment-wallet-state.md).

### 5.3 Strictness Mode Interaction

`environment.market_state` is a registered type. It MUST NOT be skipped in
PERMISSIVE mode. An unknown variant of this type (e.g., a future
`environment.market_state_v2`) would be subject to normal strictness mode
handling per constraints.md §5.4.

### 5.4 Output Fields

The constraint checker result (constraints.md §5.2) MUST include, for each
evaluated `environment.market_state` constraint:

- On satisfaction: `checked` list includes `"environment.market_state"`. Implementations SHOULD also log `receipt_id` in the audit context (outside the standard result object).
- On violation: `violations` list includes the reason string from §4.2 step that failed.

### 5.5 Family Composition

**Conjunction semantics.** The `environment.*` family is a conjunction: a mandate satisfies the family's gate if and only if every `environment.*` constraint in the mandate passes. There is no partial-fulfillment path within the family.

**Mixed pass/fail.** When one `environment.*` constraint passes and another fails in the same mandate — for example, `environment.market_state` returns `OPEN` for the primary exchange while a second `environment.market_state` returns `CLOSED` for a secondary exchange, or `environment.market_state` returns `OPEN` while `environment.wallet_state` returns `pass: false` — the family's gate fails. The passing member does not rescue the failing member.

**L3 execution gate and completeness.** Verifiers MUST evaluate every `environment.*` constraint in the mandate to completion before refusing Layer 3, even after the first failure has been observed. The completeness requirement applies to the verifier-side L3-acceptance evaluation path; agent-side pre-L3-creation evaluation is governed by §5.2's short-circuit clause, which requires agents to stop at the first `environment.*` failure as a fail-closed agent-side halt distinct from the verifier's diagnostic-completeness obligation. The `violations` list MUST contain one entry per failed `environment.*` constraint regardless of which member failed first. Short-circuit evaluation of `environment.*` constraints is non-conforming because it denies downstream consumers the per-member evidence the gate depends on. Transactional constraint evaluation (`mandate.*`) after a confirmed `environment.*` failure remains implementation-defined (verifiers MAY evaluate for diagnostic completeness, MAY skip for efficiency) as long as L3 refusal is unambiguous. This composes with §5.2's ordering requirement — environment-before-transactional stays; the completeness rule layers on top.

**Per-member diagnostic output.** Each failed `environment.*` constraint MUST produce its own entry in the `violations` list. Each violation entry MUST carry two identifiers: the array index of the constraint in the mandate's `constraints[]` array as the primary machine identifier (unambiguous across any combination of constraint types and repeats), and a human-readable identifier derived from the constraint's distinguishing field. Selection of the distinguishing field is a per-type obligation declared by each constraint type specification, analogous to the per-type declaration of MUST-implement algorithms in §4.7. For `environment.market_state`, the distinguishing field is the MIC — taken from the signed attestation's `mic` field when present per §4.1, falling back to the constraint's attestation-URL parse. For `environment.wallet_state`, the distinguishing field is `subject_wallet` (REQUIRED per that spec's §4 schema, always present). Verifiers MUST NOT collapse multiple `environment.*` failures into a single generic violation. This preserves the diagnostic signal needed for post-hoc analysis and dispute resolution, and disambiguates cases where multiple constraints of the same type appear in a single mandate — the §4.5 multi-exchange example (two `environment.market_state` constraints, XNYS and XLON) is the driving case.

**Rationale.** Two arguments, co-equal, reinforcing. The semantic argument: each member of the family answers an independent question — is this market open? is this wallet still funded? Because the questions are independent, their answers compose as AND, not OR: a failure on any member removes the basis for execution. The architectural argument: conjunction also falls out of fail-closed posture directly. Any `environment.*` type whose failure mode is OR-tolerable is, by definition, outside the family's design charter — if a constraint's failure is survivable, it is not gating execution, and if it is not gating execution, it is not in the family. This matters forward. When `environment.regulatory_status`, `environment.counterparty_credit`, or any other future `environment.*` type is proposed, conjunction is not a design decision to re-litigate per type; it is a membership criterion. The per-member diagnostic requirement follows from the same logic: collapsing per-member diagnostics would destroy the audit trail that makes the family load-bearing. Preserving them makes every signed attestation recoverable from the validation output, and makes dispute resolution an application-layer concern with complete evidence rather than a debugging exercise.

> **Note on family coordination**: Drafted as a standalone block adoptable verbatim in `environment.wallet_state` §5.5 with the per-type distinguishing-field row swapped. Same pattern as §4.7 — one family-wide question, one answer, two specs.

---

## 6. Security Considerations

### 6.1 Oracle Trust Bootstrapping

The security of this constraint depends on the verifier correctly establishing
the oracle issuer's public key. The `/.well-known/oracle-keys.json` endpoint
provides a standard discovery path (RFC 8615), but initial trust in the issuer
domain requires out-of-band verification (DNSSEC, CT logs, published key
fingerprints).

Agents and verifiers SHOULD verify the oracle's public key against at least one
out-of-band source before trusting attestations. Headless Oracle publishes its
public key at:
- `https://headlessoracle.com/v5/keys`
- `https://headlessoracle.com/.well-known/oracle-keys.json`
- npm: `@headlessoracle/verify` package README

### 6.2 Attestation Replay

A valid signed attestation is replayable within its `expires_at` window. The
`max_attestation_age` field narrows this window below `expires_at` when needed.
The `receipt_id` field enables consumers that require per-receipt deduplication
to detect and reject replayed attestations within the TTL window.

For financial execution contexts, verifiers SHOULD maintain a short-lived
`receipt_id` deduplication cache (TTL: `max_attestation_age + 30s`) to prevent
a single receipt from being used to authorise multiple L3 creations.

### 6.3 Oracle Endpoint Substitution

An attacker who can modify the Layer 2 mandate could substitute a malicious
`attestation_url` pointing to an attacker-controlled server returning a
signed-looking response. This attack is prevented by the KB-SD-JWT+KB
signature on Layer 2 — any modification to `attestation_url` or
`oracle_public_key_id` invalidates the user's signature.

The sibling [`environment.wallet_state`](./environment-wallet-state.md) §6.3
documents a complementary pattern — JWKS key-binding at the issuer layer —
that further raises the attack surface for its attestation model. The two
patterns are compatible: a future revision of this specification may adopt
JWKS-style key binding as an optional hardening for oracles that publish their
signing keys via RFC 7517 JWKS alongside the existing RFC 8615 key registry.

Verifiers MUST verify the Layer 2 credential signature chain before trusting
any field in any constraint object.

### 6.4 SSRF via attestation_url

The `attestation_url` field is a user-controlled URL that verifiers will
fetch. Implementations MUST apply SSRF protections:
- Reject non-HTTPS schemes (enforced by §4 field constraints)
- Reject URLs resolving to private IP ranges (RFC 1918, loopback, link-local)
- Set a strict request timeout (RECOMMENDED: 4 seconds; MUST NOT exceed 10 seconds)
- Do not follow more than one redirect

### 6.5 Constraint Stripping

An attacker removing an `environment.market_state` constraint from a Layer 2
mandate would expand the agent's authority to execute in any market state. This
attack is prevented by the KB-SD-JWT+KB signature on Layer 2 — any removal of
constraints from the mandate payload invalidates the user's signature. Verifiers
MUST reject any mandate whose Layer 2 signature does not validate over the full
constraint list as presented; implementations MUST NOT accept mandates where the
verified signature covers only a subset of the declared constraints.

### 6.6 UNKNOWN Status Oracle Response

An oracle returning `status: "UNKNOWN"` is signalling that it cannot determine
the market state — not that the market is open. Implementations MUST treat
`UNKNOWN` (and `HALTED`) as a constraint violation (§4.3). An implementation
that treats `UNKNOWN` as a pass-through to `expected_status` comparison is
critically misconfigured and MUST be considered non-conformant.

### 6.7 Time Synchronisation

The `issued_at` age check (Step 7 of §4.2) requires that the verifier's clock
is reasonably synchronised with the oracle's clock. A clock skew exceeding
`max_attestation_age` would cause all attestations to be rejected.
Implementations SHOULD use NTP-synchronised clocks and SHOULD log
clock-skew-related failures distinctly to aid diagnosis.

### 6.8 Key Registry Caching and Key Rotation

The oracle key registry URL — `{issuer}/.well-known/oracle-keys.json`,
derived from the attestation's `issuer` per §4.1 — is the trust root for
attestation verification (§6.3). Naive implementations that re-fetch the
key registry on every verification create avoidable load on the oracle
and expose verifiers to failure modes (rate limits, transient network
errors) that are not failures of the attestation itself. This section
defines the conforming caching and rotation behaviour.

**Caching permissibility.** Verifiers MAY cache the key registry fetched
from `{issuer}/.well-known/oracle-keys.json`. Verifiers SHOULD respect
the oracle's `Cache-Control` directive when present. When `Cache-Control`
is absent, verifier-side TTL is implementation-defined, subject to the
`key_id`-mismatch rule below.

**`key_id`-mismatch as cache bust.** When the verifier encounters an
attestation whose `public_key_id` is not present as a `key_id` in the
cached key registry, the verifier MUST bypass the cache and fetch the
key registry fresh before rejecting the attestation. This ensures
attestations signed during a key-rotation window are verifiable as soon
as the new key is published, without waiting for the cache TTL to
elapse.

**Oracle rotation responsibilities.** Oracles rotating a signing key
SHOULD publish both the old and new keys in the key registry
simultaneously during a grace window. The grace window SHOULD exceed
both:

- The maximum attestation lifetime the oracle will sign with the old
  `key_id` after starting rotation.
- The verifier key registry cache TTL the oracle publishes via HTTP
  `Cache-Control`.

During the grace window, attestations signed with either `key_id` MUST
verify against their corresponding key entry. After the grace window
elapses, the oracle MAY remove the old key entry. Verifiers holding a
stale cache containing only the old key will fetch fresh and observe the
transition on the next mismatched `key_id`, or at cache expiry,
whichever comes first.

**Grace-window discoverability.** Oracles SHOULD publish rotation-start
and grace-window-end timestamps through an auditable channel. The
channel MAY be out-of-band (release notes, status page, signed rotation
announcement) or in-band via a key registry top-level metadata field
(e.g., `rotation_announcement: { rotation_started_at, previous_key_id,
new_key_id, grace_window_end }`). This specification does not mandate a
mechanism; the SHOULD is on discoverability, not form. If the working
group converges on a canonical in-band mechanism, a future revision can
elevate it to REQUIRED.

**Fail-closed on fetch failure.** If key registry fetch fails (network
error, non-2xx response, malformed JSON) and no usable cache is
available, the constraint evaluation MUST produce a violation entry.
Verifiers MUST NOT fall back to a hard-coded public key as a recovery
path — the key registry URL is the trust root, and silent fallback
undermines the §6.3 binding. When `stale_cache_fallback_permitted` is
`true`, verifiers MAY use an expired cache as a last-resort fallback on
fresh-fetch failure; when `false` (the default when the field is
absent), verifiers MUST produce a violation. For mandates where strict
freshness is required (e.g., payment execution), the field MUST NOT be
set to `true` (see §4 Field Constraints).

**Per-constraint scope.** Key registry fetch failures are per-constraint.
A fetch failure on one `environment.market_state` constraint MUST NOT
short-circuit evaluation of other `environment.*` constraints in the
mandate; each constraint produces its own violation entry independently.
This scoping preserves the diagnostic signal needed for dispute
resolution even when a single oracle endpoint is unreachable.

**Interaction with §6.2 replay cache.** The `receipt_id` dedup cache and
the key registry cache are independent. The `receipt_id` cache TTL is
bound by `max_attestation_age + 30s`; the key registry cache TTL is
bound by oracle cache directives. No cross-dependency.

---

## 7. Reference Implementation

### 7.1 Headless Oracle

[Headless Oracle](https://headlessoracle.com) is the reference implementation
of the oracle endpoint consumed by this constraint type.

| Property | Value |
|----------|-------|
| Oracle base URL | `https://headlessoracle.com` |
| Public demo endpoint | `GET /v5/demo?mic=<MIC>` (no auth) |
| Authenticated endpoint | `GET /v5/status?mic=<MIC>` (requires `X-Oracle-Key`) |
| Batch endpoint | `GET /v5/batch?mics=<MIC,MIC,...>` (requires `X-Oracle-Key`) |
| Key registry (RFC 8615) | `GET /.well-known/oracle-keys.json` |
| OpenAPI spec | `GET /openapi.json` |
| MCP endpoint | `POST /mcp` (JSON-RPC 2.0, protocol `2024-11-05`) |
| Signing algorithm | Ed25519 (RFC 8032) via `@noble/ed25519` |
| Receipt TTL | 60 seconds (`expires_at = issued_at + 60s`) |
| Supported exchanges | 28 global exchanges across Americas, Europe, Middle East, Africa, Asia, and Pacific |
| Consumer verification SDK | `@headlessoracle/verify` (npm, zero production dependencies) |

**Supported MIC codes**: XNYS, XNAS, XLON, XJPX, XPAR, XHKG, XSES, XASX, XBOM, XNSE,
XSHG, XSHE, XKRX, XJSE, XBSP, XSWX, XMIL, XIST, XSAU, XDFM, XNZE, XHEL, XSTO, XCBT,
XNYM, XCBO, XCOI, XBIN

### 7.2 Minimal Constraint Verifier (JavaScript, Web Crypto)

```javascript
async function checkMarketStateConstraint(constraint, now = new Date()) {
  const {
    attestation_url,
    oracle_public_key_id,
    expected_status,
    max_attestation_age,
  } = constraint;

  if (max_attestation_age === undefined) {
    throw new Error('max_attestation_age is REQUIRED; constraint is malformed: fail-closed');
  }

  // Step 1 — Structural validation
  if (!attestation_url.startsWith('https://')) {
    throw new Error('Non-HTTPS attestation_url: fail-closed');
  }

  // Step 2 — Fetch attestation
  let A;
  try {
    const res = await fetch(attestation_url, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    A = await res.json();
  } catch (e) {
    throw new Error(`Attestation fetch failed: ${e.message} — fail-closed`);
  }

  // Step 3 — Key identity
  if (A.public_key_id !== oracle_public_key_id) {
    throw new Error('Attestation public_key_id mismatch: fail-closed');
  }

  // Step 4 — Fetch oracle public key
  let publicKeyHex;
  try {
    const kr = await fetch(`https://${A.issuer}/.well-known/oracle-keys.json`,
      { signal: AbortSignal.timeout(4000) });
    const { keys } = await kr.json();
    const entry = keys.find(k => k.key_id === A.public_key_id);
    if (!entry) throw new Error('Key not found in registry');
    if (entry.valid_until && new Date(entry.valid_until) < now) {
      throw new Error('Oracle signing key expired');
    }
    publicKeyHex = entry.public_key;
  } catch (e) {
    throw new Error(`Key registry error: ${e.message} — fail-closed`);
  }

  // Step 5 — Verify Ed25519 signature (MUST-implement per §4.7)
  const { signature, ...payload } = A;
  const sorted = Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]));
  const canonical = new TextEncoder().encode(JSON.stringify(sorted));
  const keyBytes = Uint8Array.from(publicKeyHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const sigBytes = Uint8Array.from(signature.match(/.{2}/g).map(b => parseInt(b, 16)));
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'Ed25519' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify({ name: 'Ed25519' }, cryptoKey, sigBytes, canonical);
  if (!valid) throw new Error('Signature verification failed: fail-closed');

  // Step 6 — Check expires_at
  if (now > new Date(A.expires_at)) {
    throw new Error('Attestation expired: fail-closed');
  }

  // Step 7 — Check max_attestation_age
  const ageSeconds = (now - new Date(A.issued_at)) / 1000;
  if (ageSeconds > max_attestation_age) {
    throw new Error(`Attestation age ${ageSeconds}s exceeds max_attestation_age ${max_attestation_age}: fail-closed`);
  }

  // Step 8 — Check status
  if (A.status !== expected_status) {
    throw new Error(`Market status is ${A.status}, expected ${expected_status}: constraint not satisfied`);
  }

  return { satisfied: true, receipt_id: A.receipt_id };
}
```

### 7.3 Fail-Closed Integration Pattern (Python)

```python
import httpx
from datetime import datetime, timezone

def check_market_state_constraint(constraint: dict, now: datetime = None) -> dict:
    """
    Returns {"satisfied": True, "receipt_id": str} or raises on any failure.
    Fail-closed: any exception means the constraint is NOT satisfied.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    attestation_url = constraint["attestation_url"]
    oracle_public_key_id = constraint["oracle_public_key_id"]
    expected_status = constraint["expected_status"]
    if "max_attestation_age" not in constraint:
        raise ValueError("max_attestation_age is REQUIRED; constraint is malformed: fail-closed")
    max_attestation_age = constraint["max_attestation_age"]

    if not attestation_url.startswith("https://"):
        raise ValueError("Non-HTTPS attestation_url: fail-closed")

    # Fetch attestation
    try:
        r = httpx.get(attestation_url, timeout=4.0)
        r.raise_for_status()
        A = r.json()
    except Exception as e:
        raise RuntimeError(f"Attestation fetch failed: {e} — fail-closed")

    if A.get("public_key_id") != oracle_public_key_id:
        raise ValueError("public_key_id mismatch: fail-closed")

    # Fetch public key and verify signature using headless-oracle SDK
    from headless_oracle import verify
    result = verify(A)
    if not result.valid:
        raise ValueError(f"Attestation verification failed: {result.reason} — fail-closed")

    # Age check
    issued_at = datetime.fromisoformat(A["issued_at"].replace("Z", "+00:00"))
    age = (now - issued_at).total_seconds()
    if age > max_attestation_age:
        raise ValueError(f"Attestation age {age:.0f}s exceeds max_attestation_age {max_attestation_age}: fail-closed")

    # Status check
    if A["status"] != expected_status:
        raise ValueError(f"Market status is {A['status']}, expected {expected_status}")

    return {"satisfied": True, "receipt_id": A["receipt_id"]}
```

---

## 8. Open Questions

1. **Batch attestation URL**: Should `attestation_url` be permitted to point to a
   batch endpoint (e.g., `/v5/batch?mics=XNYS,XNAS`) with `expected_status` applying
   to a named exchange in the response array? This would reduce oracle round-trips for
   multi-exchange mandates. Proposal: add an optional `subject` field that names the
   MIC within a batch response.

2. **Oracle allowlisting**: Should the VI specification define a mechanism for users
   to allowlist trusted oracle issuers at the credential or wallet level, rather than
   per-constraint? This would prevent a malicious L2 issuer from directing the agent
   at an attacker-controlled oracle. The sibling `environment.wallet_state`
   specification (PR #22 §6.3) answers this concretely via JWKS-host key binding at
   the issuer layer. A future revision of this specification may adopt the same
   pattern as optional hardening for oracles that publish signing keys via RFC 7517
   JWKS alongside the existing RFC 8615 key registry.

3. **Offline / degraded mode**: Should the specification define a `permissive_on_timeout`
   flag that allows constraint satisfaction on network failure? The current specification
   is unconditionally fail-closed. Some deployment contexts (e.g., testing, air-gapped
   environments) might require a more permissive fallback. The working group's current
   position: no — permissive-on-timeout is a footgun. Operators who need it should use
   local oracle proxies that can return signed attestations from cache.

4. **Key rotation during execution**: If the oracle rotates its signing key between
   agent time and verifier time, the verifier will fetch a different public key and
   may fail Step 5 verification. The SMA Protocol key rotation specification requires
   oracles to serve both old and new keys during the rotation window. This constraint
   specification inherits that requirement by reference.

5. **On-chain oracle integration**: For DeFi execution contexts, `attestation_url` might
   point to an on-chain oracle or a bridge between off-chain and on-chain state. On-chain
   verification of Ed25519 signatures is possible via EIP-665. Specification of on-chain
   `attestation_url` semantics is deferred to a companion document.

6. **Family-wide subject binding**: Every `environment.*` constraint type has a natural
   "subject" — the exchange/session for this constraint (currently carried as the `mic`
   field in the SMA receipt), the wallet address for `environment.wallet_state`
   (carried as the JWT `sub` claim), potentially a counterparty DID or jurisdiction
   identifier for future types. A common subject-binding pattern across the family would
   let verifier libraries implement a single "extract subject, match against constraint,
   enforce binding" code path rather than one-off field handling per type. A future
   revision of this specification may adopt a `subject` field on the constraint and a
   matching claim in the attestation payload to align with the pattern established in
   PR #22 §8 Q5. Working group input welcome.

---

## 9. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.5-draft | 2026-05 | §4.8 Field Scope Declaration (field-scope charter); §4.7 algorithm-deprecation discipline (≥12-month migration window); Appendix C Register Discipline; Appendix D Implementation Status (RFC 6982). |
| 0.4-draft | 2026-04 | §6.8 Key Registry Caching and Rotation; stale_cache_fallback_permitted field (fail-secure default). |
| 0.3-draft | 2026-04 | §5.5 Family Composition: conjunction semantics, completeness rule, per-member disambiguation. §6.5 constraint-stripping rejection. max_attestation_age REQUIRED. |
| 0.2-draft | 2026-04 | §2.3 environment.* family framing; max_attestation_age (TOCTOU rationale, §4.6); §4.7 algorithm agility; §4.5 composition example. |
| 0.1-draft | 2026-03 | Initial draft: environment.market_state constraint type, Ed25519 attestation, fail-closed algorithm, Headless Oracle reference implementation. |

---

## Appendix A: Attestation Test Vectors

These test vectors allow constraint verifier implementors to validate their
attestation verification logic against a known-good signed receipt from Headless
Oracle.

**Attestation object (before signature)**:
```json
{
  "expires_at":     "2026-03-17T12:01:00Z",
  "issued_at":      "2026-03-17T12:00:00Z",
  "issuer":         "headlessoracle.com",
  "mic":            "XNYS",
  "public_key_id":  "key_2026_v1",
  "receipt_id":     "550e8400-e29b-41d4-a716-446655440000",
  "receipt_mode":   "live",
  "schema_version": "v5.0",
  "source":         "SCHEDULE",
  "status":         "OPEN"
}
```

**Canonical payload** (fields sorted alphabetically, compact JSON):
```
{"expires_at":"2026-03-17T12:01:00Z","issued_at":"2026-03-17T12:00:00Z","issuer":"headlessoracle.com","mic":"XNYS","public_key_id":"key_2026_v1","receipt_id":"550e8400-e29b-41d4-a716-446655440000","receipt_mode":"live","schema_version":"v5.0","source":"SCHEDULE","status":"OPEN"}
```

**Headless Oracle public key** (production, hex):
```
03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178
```

Fetch a live signed receipt at `https://headlessoracle.com/v5/demo?mic=XNYS`
and verify your canonical form construction and Ed25519 verification against it.

---

## Appendix B: Failure Mode Quick Reference

| Failure | Step | Violation Message Pattern | Agent Response |
|---------|------|--------------------------|----------------|
| Non-HTTPS `attestation_url` | 1 | `"Non-HTTPS attestation_url: fail-closed"` | Do not proceed |
| Network timeout / DNS failure | 2 | `"Attestation fetch failed: ... — fail-closed"` | Do not proceed |
| HTTP 4xx / 5xx from oracle | 2 | `"Attestation fetch failed: HTTP {N} — fail-closed"` | Do not proceed |
| Invalid JSON response | 2 | `"Attestation response is not valid JSON: fail-closed"` | Do not proceed |
| `public_key_id` mismatch | 3 | `"Attestation public_key_id does not match oracle_public_key_id"` | Do not proceed |
| Key registry unreachable | 4 | `"Oracle key registry unreachable: fail-closed"` | Do not proceed |
| Key not found in registry | 4 | `"Signing key not found in oracle key registry: fail-closed"` | Do not proceed |
| Oracle signing key expired | 4 | `"Oracle signing key has expired: fail-closed"` | Do not proceed |
| Signature verification failed | 5 | `"Attestation signature verification failed: fail-closed"` | Do not proceed; alert operator |
| Attestation `expires_at` in past | 6 | `"Attestation has expired (expires_at in past): fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| Attestation exceeds `max_attestation_age` | 7 | `"Attestation age Ns exceeds max_attestation_age M: fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| Status is `UNKNOWN` | 8 | `"Market status is UNKNOWN, expected OPEN: constraint not satisfied"` | Do not proceed; do not retry |
| Status is `HALTED` | 8 | `"Market status is HALTED, expected OPEN: constraint not satisfied"` | Do not proceed; log reason; do not retry until next signed OPEN |
| Status is `CLOSED` | 8 | `"Market status is CLOSED, expected OPEN: constraint not satisfied"` | Do not proceed; retry after next scheduled open |

---

## Appendix C: Register Discipline

**Status**: Charter proposal (skeleton). Shape only; content to converge through working-group review.

### C.1 Purpose

The `environment.*` constraint family has converged on a consistent discipline for the use of normative register (RFC 2119 keywords in ALL CAPITALS) versus descriptive register (lowercase synonyms, prose explanation, rationale paragraphs). This discipline has been applied across both `environment.market_state` (this specification) and `environment.wallet_state` (PR #22) in multiple patch-level revisions: §2.3 and §2.5 register polish in v0.5.4 on #9, and §6.9 reorg-scope and truncation-asymmetry clarifications in v0.6.1 on #22 are the most recent concrete instances. This appendix formalises the discipline so that it is visible to future contributors, reviewers, and implementers as an explicit charter property rather than an ad-hoc editorial practice.

### C.2 Normative vs. descriptive register

**Normative register**. RFC 2119 keywords (MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, OPTIONAL) in ALL CAPITALS, used when a specification intends to bind implementers to specific behaviour per RFC 2119 and RFC 8174. Load-bearing. Testable. Conformance-checkable.

**Descriptive register**. Prose that explains intent, rationale, precedent, context, or structural reasoning, using lowercase synonyms where RFC 2119 keywords would otherwise appear. Not intended to bind implementers. Not testable. Provides the surface that makes the normative register legible.

The distinction matters because a specification that mixes the two produces false-signal conformance questions — a reviewer or implementer reading prose with ALL-CAPS keywords in descriptive context cannot tell whether the text imposes a requirement or merely describes one. The v0.5.4 §2.3 register polish is the worked example: the descriptive sentence referencing §4.7's per-type MUST-implement algorithm was softened to "per-type mandatory algorithm" because §2.3 describes what §4.7 establishes rather than imposing a new requirement at §2.3 — ALL-CAPS was register confusion, not intentional normative text.

### C.3 Rules for the `environment.*` family

The following rules apply to `environment.market_state`, `environment.wallet_state`, and any future constraint type proposed for the `environment.*` namespace.

#### C.3.1 RFC 2119 keywords in normative register

RFC 2119 keywords MUST appear in ALL CAPITALS only when the containing sentence imposes a normative requirement on implementers (agents, verifiers, mandate issuers, or oracle operators). The §1 Notational Conventions boilerplate per RFC 8174 binds the interpretation.

#### C.3.2 Lowercase synonyms in descriptive register

Descriptive text — rationale paragraphs, bullet-list summaries of other sections, cross-references explaining what another section does — SHOULD use lowercase synonyms rather than ALL-CAPS RFC 2119 keywords when no new requirement is being imposed. Where the lowercase synonym would be ambiguous (e.g., "should" without a clear subject), explicit phrasing ("the type author's choice is" or "the section establishes") is preferred.

#### C.3.3 Redundancy avoidance

RFC 2119 §3 establishes that SHOULD and RECOMMENDED carry identical normative force. Field labels, section headers, and parenthetical qualifiers that duplicate the normative keyword present in the containing sentence add visual weight without adding normative content. The v0.5.4 §2.5 register polish is the worked example: "**Layer 3 evidence field (RECOMMENDED)**: Agents SHOULD include…" was shortened to "**Layer 3 evidence field**: Agents SHOULD include…" because the SHOULD carries the requirement and the RECOMMENDED label adds register noise.

#### C.3.4 Scope of application (application-layer vs. transport-layer)

Normative requirements MUST name the implementer they bind. Where the requirement could be read at multiple layers of the stack (e.g., "verifiers MUST re-verify" read as a network-transport obligation vs. a VI application-layer L3-acceptance obligation), the specification text MUST name the application-layer scope explicitly. The v0.6.1 §6.9 reorg-remediation scope clarifier is the worked example: the advisory SHOULD on re-verification at settlement time was scoped to the VI verifier's application-layer L3-acceptance logic, explicitly excluding chain client, RPC transport, and cryptographic library behaviour.

#### C.3.5 Forward rule for new sections

New sections introduced in any `environment.*` constraint type in future specification revisions MUST apply the rules of §C.3.1 through §C.3.4 at introduction. Editorial register polish (conversion of ALL-CAPS to lowercase in descriptive context, removal of RECOMMENDED/SHOULD redundancy, application-layer scope naming) is a patch-level revision (e.g., v0.5.4, v0.6.1) and does not require a minor-version bump.

### C.4 Open questions for working group

- **Q1: Normative vs. informative appendix classification.** This appendix describes an editorial discipline that the constraint-type specifications' normative sections already follow. Should Appendix C itself be classified as informative (describing the discipline) with the normative force carried by cross-references into §1, §2.3, §2.5, §6.9, etc.; or should Appendix C be classified as normative (binding future type authors to the rules at §C.3)? The current skeleton leans toward informative-with-normative-cross-references: the discipline is described here, the rules are stated here, but the binding force lives in the specific sections where the rules are applied. Working-group input welcome.

- **Q2: Register-discipline audit cadence.** The v0.3.2 (PR #9) and symmetric #22 RFC 2119 audits surfaced register issues that were addressed as P1/P2/P3 findings. Should the family adopt a formal audit cadence (e.g., pre-release audit before each minor version) or is the ad-hoc audit pattern established at v0.3.2 / v0.5.4 / v0.6.1 sufficient?

- **Q3: Scope of Appendix C over time.** This appendix opens with register discipline because that is where the family has already established concrete practice through multiple patch-level revisions (v0.5.4 §2.3/§2.5 on #9, v0.6.1 §6.9 on #22). Broader family charter principles — provider neutrality, peer-author coordination discipline, patch-level versioning conventions, lockstep commit patterns — may consolidate into Appendix C in future revisions as the practice around them matures, or may warrant a separate charter section depending on how the working group sees the relationship. Working-group input welcome on whether future consolidation under Appendix C, a separate Appendix D / Family Charter section, or a hybrid structure best serves forward clarity.

### C.5 Current instances (catalog deferred)

A full catalog of current register-discipline instances across both `environment.market_state` and `environment.wallet_state` — §1.1 Notational Conventions, §2.3 descriptive references to §4.7, §2.5 L3 evidence field label, §4.6 family-wide semantics paragraph, §4.7 MUST-implement table rationale, §4.8 scope category definitions, §5.5 rationale paragraph, §6.8 key-rotation discoverability, §6.9 reorg-remediation scope (PR #22 only), et al. — is deferred to a future patch-level revision. At that point the catalog will serve as a concrete worked-example reference for the rules at §C.3 and will be cross-referenced from the specific sections.

### C.6 Relationship to §1 Notational Conventions

This appendix extends the §1 Notational Conventions statement. §1 binds the interpretation of RFC 2119 keywords when they appear in ALL CAPITALS per RFC 8174; Appendix C states the editorial discipline for when they SHOULD appear in ALL CAPITALS (normative register, §C.3.1) versus when they SHOULD NOT (descriptive register, §C.3.2). Together, §1 and Appendix C establish the register discipline of the `environment.*` family.

> **Note on family coordination**: Drafted as a skeleton adoptable in lockstep on `environment.wallet_state` Appendix C (pending confirmation of current appendix count on PR #22). The worked-example instances at §C.3.2, §C.3.3, and §C.3.4 cite both specs; the same skeleton, ported verbatim, would appear on PR #22 with per-spec localisation where applicable. Same pattern as §4.6, §4.7, §5.5, §6.8, §4.8 — one family-wide charter principle, one answer, two specs.

---

## Appendix D: Implementation Status

**Status**: Informative, per [RFC 6982](https://datatracker.ietf.org/doc/html/rfc6982).

This appendix records the running-code implementations of `environment.market_state` and the sibling `environment.*` family known to the editors at the time of writing. Per RFC 6982 §2, this section is intended to be removed by the RFC Editor before any final standards-track publication; the GitHub history of this Internet-Draft retains it permanently as evidence of priority and as a pointer to deployed reference implementations during the working-group review window.

### D.1 Headless Oracle (`environment.market_state`)

| Property | Value |
|----------|-------|
| Organisation | Headless Oracle (headlessoracle.com) |
| License | MIT, Copyright 2026 Michael Msebenzi / LembaGang |
| Compliance endpoint | `GET https://headlessoracle.com/v5/compliance` |
| Demo endpoint | `GET https://headlessoracle.com/v5/demo?mic=<MIC>` |
| Public key registry | `GET https://headlessoracle.com/.well-known/oracle-keys.json` (RFC 8615) |
| Signing algorithm | Ed25519 (RFC 8032), per §4.7 MUST-implement |
| Receipt format | Signed Market-State Attestation (SMA) — Ed25519 signature over canonical JSON of the receipt subset specified at `GET /v5/keys` → `canonical_payload_spec` |
| Coverage | 28 global exchanges across equities, derivatives, and digital-asset venues, identified by ISO 10383 MIC codes where registered and by convention MICs for crypto-native venues without ISO registration. Authoritative per-venue `mic_type` categorisation is published at `GET /v5/exchanges` |
| Operational since | 2026-02-18 |
| Reference verifier | [github.com/headlessoracle/demo-agent](https://github.com/headlessoracle/demo-agent) (~150 lines across `src/demo.mjs` and `src/verifier.mjs`, MIT-licensed) |
| Architectural rationale | [github.com/headlessoracle/essays](https://github.com/headlessoracle/essays) |

**Supported MIC codes**: XNYS, XNAS, XLON, XJPX, XPAR, XHKG, XSES, XASX, XBOM, XNSE, XSHG, XSHE, XKRX, XJSE, XBSP, XSWX, XMIL, XIST, XSAU, XDFM, XNZE, XHEL, XSTO, XCBT, XNYM, XCBO, XCOI, XBIN.

**x402 settlement infrastructure validation**. First end-to-end x402 settlement on Base mainnet on 2026-04-03, transaction [`0xeb9da8737537e13e9818902b67b8f03b06b7da46a7c557883f409d42895b308a`](https://basescan.org/tx/0xeb9da8737537e13e9818902b67b8f03b06b7da46a7c557883f409d42895b308a) at block 44218092, settling 0.001 USDC via EIP-3009 Transfer With Authorization (the x402 v2 canonical pattern). The payer wallet was self-funded for end-to-end test of facilitator integration, response gating, and signature emission; this transaction validates the settlement infrastructure end-to-end and is not commercial revenue. The first external x402 transaction observed against the deployment was 2026-04-17.

**Reference verifier behaviour**. `headlessoracle/demo-agent` verifies XNYS via `GET /v5/demo`: it fetches the signed receipt, reconstructs the canonical payload per `GET /v5/keys` → `canonical_payload_spec` (alphabetical field sort, `JSON.stringify` with no whitespace, `signature` field excluded), and verifies the Ed25519 signature against the public key resolved from `GET /.well-known/oracle-keys.json`. Fail-closed exit semantics: exit code `0` for verified-and-OPEN, `1` for verified-and-CLOSED (or any non-OPEN verified status), `2` for verification-failed.

**Conformance to this specification**. The Headless Oracle deployment implements the §4.1 attestation interface; the §4.2 verification algorithm Steps 1 through 10; the §4.6 `max_attestation_age` family-wide freshness semantics (verifying at the constraint level rather than relying on a provider TTL); §4.7 Ed25519 MUST-implement; §6.5 Constraint Stripping rejection per the §6.5 normative MUSTs; and §6.8 RFC 8615 key registry caching with `key_id`-mismatch cache invalidation.

### D.2 InsumerAPI (`environment.wallet_state`, sibling specification)

| Property | Value |
|----------|-------|
| Organisation | InsumerAPI (insumermodel.com) |
| Sibling specification | PR #22 (`environment.wallet_state`, branch `douglasborthwick-crypto:rfc-environment-wallet-state`) |
| Attestation endpoint | `POST https://api.insumermodel.com/v1/attest` |
| JWKS endpoint | `GET https://api.insumermodel.com/.well-known/jwks.json` (RFC 7517) |
| Signing algorithm | ES256 / P-256, per `environment.wallet_state` §4.7 MUST-implement |
| Stable signing key id | `insumer-attest-v1` |
| Receipt format | ES256 JWT (RFC 7515) with REQUIRED claims `iss`, `sub`, `jti`, `iat`, `exp`, `pass`, `conditionHash` per `environment.wallet_state` §4.1 |
| JWT TTL | 1800 seconds |
| Condition hash format | `"0x" + sha256(canonical_json(evaluated_condition))`, sorted keys |
| Chain coverage | 33 chains |
| Agent-native key provisioning | `POST /v1/keys/buy` — no auth, wallet is identity, USDC/USDT/BTC on-chain payment |
| Reference verifier | [github.com/douglasborthwick-crypto/insumer-examples](https://github.com/douglasborthwick-crypto/insumer-examples) |
| License | Proprietary. Copyright 2026 Douglas Borthwick. |

InsumerAPI realises the sibling `environment.wallet_state` constraint to `environment.market_state`. It is listed here for `environment.*` family completeness; the canonical Implementation Status appendix for `environment.wallet_state` belongs in that specification (PR #22) and is the editor's call on Douglas Borthwick's side.

### D.3 Disclaimer

This appendix is not normative. Listing in Appendix D does not imply endorsement of the listed implementation by the editors, by the Verifiable Intent project, or by any inheritor of this draft. Each implementation is independently operated and independently signed. Verifiers MUST independently verify attestations from any implementation per §4.2 — implementation listing in Appendix D does not substitute for verification.

---

*End of document. Comments and revisions should be submitted as issues or pull requests to the Verifiable Intent specification repository (github.com/agent-intent/verifiable-intent) or the Headless Oracle reference implementation repository (github.com/LembaGang/headless-oracle-v5).*
