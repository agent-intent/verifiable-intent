# Verifiable Intent — Wallet State Attestation Constraint Proposal

**Type identifier**: `environment.wallet_state`
**Version**: 0.6-draft
**Status**: Draft / Proposed for Registration
**Date**: 2026-04-20
**Author**: Douglas Borthwick (InsumerAPI)
**License**: Apache 2.0

## Abstract

This document proposes a second Verifiable Intent (VI) constraint type in the
`environment.*` namespace — `environment.wallet_state` — for registration in
the VI constraint type registry defined in [constraints.md §6.2](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md#62-constraint-type-registry).
It is a direct companion to [`environment.market_state`](./external-state-attestation.md)
(PR #9) and is intentionally structured to share that document's algorithm
shape, fail-closed rules, and lifecycle model.

The `environment.wallet_state` constraint is a **pre-execution environment
gate**: it requires an AI agent to obtain a cryptographically signed on-chain
state attestation from a verified issuer and confirm that the agent's payment
source wallet still satisfies a specified boolean condition *before*
constructing a Layer 3 fulfillment. If the attestation cannot be obtained,
cannot be verified, is expired, or does not match the expected condition hash,
the constraint is not satisfied and the agent MUST NOT proceed to Layer 3
creation.

**Fail-closed by design.** Any failure in the attestation pipeline — network
error, signature mismatch, JWKS mismatch, expiry, condition hash mismatch —
causes the constraint to fail. An agent that cannot verify the state of its
payment source is an agent that must not act.

The primary motivation is payment execution safety. Autonomous agents that
execute transfers out of wallets that no longer hold the required balance, no
longer hold the required NFT, or no longer satisfy the entry condition cause
exactly the TOCTOU class of harm that [`environment.market_state`](./external-state-attestation.md)
addresses for market sessions. Wallet state is environmental, not transactional:
amount validation at L2 is not evidence that the source wallet will satisfy
the same condition at L3 verification time.

This specification covers:
- The `environment.wallet_state` constraint schema
- The abstract attestation interface any conformant issuer MUST implement (§4)
- The attestation verification algorithm agents and verifiers MUST implement
- Fail-closed failure handling requirements
- Security considerations specific to on-chain state dependencies
- A reference implementation (InsumerAPI) in §7
- A concrete answer to §8 Q2 of the `environment.market_state` proposal
  (trusted-issuer policy via JWKS key binding rather than URL binding)

### Companion Documents

| Document | Description |
|----------|-------------|
| [constraints.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md) | VI normative constraint type definitions and validation rules |
| [credential-format.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/credential-format.md) | Normative credential format, claim tables, and serialization |
| [security-model.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/security-model.md) | Threat model and security analysis |
| [design-rationale.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/design-rationale.md) | Why SD-JWT, algorithm choices |
| [external-state-attestation.md](./external-state-attestation.md) | Sibling `environment.market_state` constraint (PR #9) |
| [InsumerAPI OpenAPI](https://api.insumermodel.com/openapi.yaml) | The reference wallet-state attestation issuer consumed by this constraint |
| [insumer-examples](https://github.com/douglasborthwick-crypto/insumer-examples) | Public reference implementations and end-to-end verification scripts for InsumerAPI attestations |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119] and [RFC 8174] when, and only when, they
appear in ALL CAPITALS, as shown here.

JSON data structures follow [RFC 8259]. All field names are case-sensitive.

The term **attestation** refers to a JSON Web Token ([RFC 7519]) representing
a signed state claim that satisfies the verification requirements in §4. Any
issuer whose JWT output conforms to the abstract interface defined in §4.1 is
a valid attestation provider for this constraint type.

The term **condition hash** refers to a deterministic hash over a JSON-encoded
boolean condition predicate (e.g., "does wallet `W` hold at least `T` units of
token `C` on chain `I`?"). The hash is computed by the attestation issuer and
included in the attestation payload. Verifiers match it against constraint
content rather than re-evaluating the predicate against raw balances.

---

## 2. Overview

### 2.1 What This Constraint Is

`environment.wallet_state` is a **pre-execution environment gate**. It
instructs the verifying agent or verifier to:

1. Fetch a signed wallet state attestation from a designated issuer endpoint
2. Verify the JWT signature against the issuer's published JWKS
3. Confirm the JWT's `iss`, `sub`, and `kid` claims match the constraint
4. Confirm the attestation is not expired (`exp`) and is within the constraint's
   `max_attestation_age` window (derived from `iat`)
5. Confirm the attestation `conditionHash` array contains every hash the
   constraint requires
6. Confirm the attestation `pass` field is `true`
7. Proceed to Layer 3 creation *only if all six checks pass*

The constraint encodes the user's intent that the agent MUST NOT execute
against a payment source whose on-chain state no longer satisfies the entry
condition — regardless of whether the agent would otherwise be authorised to
act.

This is structurally identical to `environment.market_state` (§2.1 of the
companion document). Both constraints gate *when* the agent may act on verified
external world state, not *what* the agent may do with it. Both are siblings
in the `environment.*` namespace and compose as peers in a single mandate.

### 2.2 Where This Constraint Appears

`environment.wallet_state` MAY appear in **both** VI Autonomous mode mandate
types:

- **Checkout mandate** (`vct: "mandate.checkout.open.1"`): Prevents checkout
  initiation when the source wallet no longer satisfies the entry condition
  (e.g., the wallet no longer holds the minimum balance required by the
  mandate's pricing floor).
- **Payment mandate** (`vct: "mandate.payment.open.1"`): Prevents payment
  authorisation when the source wallet has moved out of the required state
  between L2 issuance and L3 verification (e.g., the wallet has since
  transferred out the required position).

When present in both mandates of a single delegated action, both constraints
MUST be satisfied independently. A constraint in the checkout mandate does not
satisfy a constraint in the payment mandate.

**Namespace**: `environment.*`. This is the second type proposed for this
namespace, following `environment.market_state` (PR #9). Future types in this
namespace might include `environment.regulatory_status`,
`environment.counterparty_credit`, `environment.infrastructure_health`, or
`environment.identity_revocation`. The `environment.*` family shares a common
shape (fetch + cryptographically verify + match expected state, all
fail-closed) and composition model (evaluated before transactional constraints,
independently re-verified at L3 check time).

### 2.3 Lifecycle

1. **Creation**: The user, or the user's agent wallet / credential issuer,
   includes an `environment.wallet_state` constraint in the Layer 2 mandate at
   issuance time, specifying the attestation endpoint, the issuer's JWKS URL,
   the expected `kid`, the subject wallet, the required condition hash(es),
   and the maximum acceptable attestation age.
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

### 2.4 Fulfillment Model

Unlike registered VI constraint types that compare L2 constraints against L3
fulfillment values (derived from L3 mandate fields), `environment.wallet_state`
validation requires a live external fetch. The constraint is satisfied or
violated at the moment of verification based on a freshly obtained attestation,
not by comparing L2 to L3 fields.

This is an intentional design choice. Wallet state is ephemeral — an
attestation obtained at agent time may not reflect wallet state at verifier
time. Verifiers MUST perform independent attestation verification, not rely on
the agent's L3 claims about wallet state.

**Layer 3 evidence field (RECOMMENDED)**: Agents SHOULD include a
`wallet_state_attestation` field in the Layer 3 mandate containing the full
signed JWT. This provides a cryptographic audit record of the wallet state the
agent observed when constructing L3. Verifiers MAY use this field to audit the
agent's decision context, but MUST NOT use it as a substitute for independent
verification.

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

`environment.wallet_state` follows this common structure with the
type-specific fields defined in §4.

### 3.2 Registration

This constraint is proposed for registration in the `environment.*` namespace
(which is itself proposed for registration by PR #9). Proposed registration
entry:

| Type | Defined In | Version | Disclosure Form |
|------|-----------|---------|-----------------|
| `environment.wallet_state` | This document | 0.2-draft | property (full constraint) |

---

## 4. The `environment.wallet_state` Constraint

### Purpose

Require a cryptographically signed, unexpired on-chain state attestation from
a trusted issuer, confirming that the source wallet currently satisfies a
specific boolean condition (encoded as a condition hash), before the agent may
proceed to Layer 3 fulfillment.

The constraint is fail-closed: any failure in the attestation pipeline —
including network errors, signature failures, JWKS mismatch, expiry, and
condition hash mismatch — causes the constraint to be treated as violated. The
agent MUST NOT proceed on uncertainty.

### Appears In

- Checkout mandate (`mandate.checkout.open.1`) `constraints` array
- Payment mandate (`mandate.payment.open.1`) `constraints` array

### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"environment.wallet_state"` |
| `attestation_url` | string (HTTPS URL) | Yes | Endpoint the verifier POSTs to in order to obtain a signed JWT attestation. MUST be an HTTPS URL. The response MUST be a JSON object containing a `jwt` field conforming to §4.1. |
| `trusted_jwks` | string (HTTPS URL) | Yes | Issuer JWKS ([RFC 7517]) URL. MUST be an HTTPS URL. The verifier fetches this JWKS to obtain the signing public key. This field — not `attestation_url` — is the policy-layer trust anchor (see §6.3). |
| `expected_kid` | string | Yes | The JWT `kid` header value the verifier MUST require. The verifier MUST locate the key in the fetched JWKS whose `kid` matches this value and use it for signature verification. |
| `expected_issuer` | string | Yes | The JWT `iss` claim value the verifier MUST require. The verifier MUST reject attestations whose `iss` differs from this value. |
| `subject_wallet` | string | Yes | The wallet address that MUST appear in the JWT `sub` claim. Binds the attestation to a specific payment source. |
| `required_condition_hashes` | array of string | Yes | One or more condition hashes (hex strings) the JWT `conditionHash` array MUST contain. Every value in this list MUST be present in the attestation's `conditionHash` array. Extra hashes in the attestation are permitted. |
| `max_attestation_age` | integer | Yes | Maximum age in seconds of the attestation, measured from JWT `iat` to the time of verification. MUST be a positive integer. Verifiers MUST reject attestations where `(now − iat) > max_attestation_age`, even if `exp` has not yet passed. A well-formed constraint MUST include this field; a missing `max_attestation_age` is a malformed constraint and verifiers MUST reject it (see §4.2 Step 1). There is no default value. See §4.6 for rationale. |
| `stale_cache_fallback_permitted` | boolean | No | Whether verifiers MAY use an expired JWKS cache as a last-resort fallback when fresh JWKS fetch fails. Verifiers MUST apply a default of `false` when absent. Deployments with strict freshness requirements (e.g., payment execution) MUST NOT set this to `true`. See §6.8 for companion verifier behaviour on fetch failure. |
| `attestation_request_body` | object | No | Optional POST body the verifier sends to `attestation_url` when fetching a fresh attestation. Verifiers MUST NOT trust this body to alter the expected claims — all binding is enforced by `expected_kid`, `expected_issuer`, `subject_wallet`, and `required_condition_hashes`. |
| `finality_depth` | integer | No | Minimum number of block confirmations past the attested block required for the attestation to be acceptable at verification time, as declared by the mandate issuer. MUST be a positive integer if present. Verifiers MUST reject attestations whose chain state reflects fewer confirmations than this value. Absent when the mandate does not constrain finality beyond per-attestation freshness. See §6.9 for rationale and composition with `max_cross_chain_skew_seconds`. |
| `max_cross_chain_skew_seconds` | integer | No | Maximum tolerated wall-clock divergence in seconds between the chain-tip timestamps observed by attestations bound to separate `environment.wallet_state` (or sibling `environment.*`) constraints in the same mandate when those attestations anchor to different chains. MUST be a positive integer if present. Applies only to multi-chain mandates; single-chain mandates ignore the field. See §6.9 for measurement basis and §4.8 for scope classification. |

#### Field Constraints

- `attestation_url` and `trusted_jwks` MUST use the `https` scheme. Non-HTTPS
  URLs MUST be rejected as a constraint violation (fail-closed; unencrypted
  attestation traffic is untrusted by definition).
- `expected_kid` and `expected_issuer` MUST be non-empty strings. Empty strings
  MUST be treated as malformed and rejected.
- `subject_wallet` MUST be a non-empty string. No address-format validation is
  performed by this constraint — the constraint is chain-agnostic and delegates
  address semantics to the attestation issuer.
- `required_condition_hashes` MUST be a non-empty array. Zero-length arrays
  MUST be rejected as malformed (a wallet-state constraint with no conditions
  to match is meaningless).
- `max_attestation_age` MUST be a positive integer (`>= 1`). Values less than
  `1` MUST be rejected as malformed. A missing `max_attestation_age` field is a
  malformed constraint and verifiers MUST reject such constraints per §4.2
  Step 1. There is no default value; all mandate issuers MUST declare an
  explicit TOCTOU window for each `environment.wallet_state` constraint. The
  freshness window is the primary exploitable surface (§4.6); silent defaults
  leave that surface undefined at the deployment boundary.
- `stale_cache_fallback_permitted`, if present, MUST be a strict boolean.
  Non-boolean values (including string `"false"`, `null`, or numeric) MUST be
  rejected as malformed per §4.2 Step 1. When absent, verifiers MUST apply a
  default of `false`; see §6.8 for the companion verifier behaviour on JWKS
  fetch failure.
- `finality_depth`, if present, MUST be a positive integer (`>= 1`).
  Non-positive or non-integer values MUST be rejected as malformed per §4.2
  Step 1. When absent, no chain-finality check beyond per-attestation
  freshness is imposed. See §6.9 for reorg-remediation posture.
- `max_cross_chain_skew_seconds`, if present, MUST be a positive integer
  (`>= 1`). Non-positive or non-integer values MUST be rejected as malformed
  per §4.2 Step 1. When absent, no cross-chain skew bound is imposed;
  per-attestation freshness (`max_attestation_age`) continues to govern
  per-constraint timing. See §6.9 for measurement basis.

### 4.1 Abstract Attestation Interface

This section defines the normative contract that any conformant wallet-state
attestation issuer MUST implement. The contract is intentionally minimal: it
specifies the claims the verification algorithm (§4.2) requires, and nothing
else. Issuers MAY include additional claims beyond those listed here;
verifiers MUST NOT strip claims before signature verification.

**Request**: Verifiers MUST send an HTTPS POST to `attestation_url` with a
JSON body. The request body schema is issuer-specific and is carried in the
constraint's `attestation_request_body` field. The response MUST be a JSON
object containing a `jwt` field whose value is a compact-serialized JWS
([RFC 7515]).

**JWT header** (REQUIRED fields):

| Field | Type | Description |
|-------|------|-------------|
| `alg` | string | Signing algorithm identifier. MUST be a named JWS algorithm per §4.7 (Algorithm Agility). For `environment.wallet_state`, the MUST-implement algorithm is `ES256`. |
| `typ` | string | MUST be `"JWT"`. |
| `kid` | string | Key identifier. MUST match `expected_kid` in the constraint. |

**JWT payload — REQUIRED claims** (normative; used by the verification
algorithm in §4.2):

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string (URL) | Issuer identifier. MUST match `expected_issuer` in the constraint. |
| `sub` | string | Subject wallet address. MUST match `subject_wallet` in the constraint. This is the standard JWT subject claim ([RFC 7519] §4.1.2), carrying the wallet address as the attestation subject — "this attestation is about this payment source" is a native JWT claim check. |
| `jti` | string | Unique attestation identifier ([RFC 7519] §4.1.7). Used for deduplication and audit logging. |
| `iat` | integer (unix seconds) | Time the attestation was signed. Used by the `max_attestation_age` check (§4.2 Step 8). |
| `exp` | integer (unix seconds) | Time after which the attestation MUST NOT be acted upon. |
| `pass` | boolean | Aggregate condition evaluation result. MUST be `true` for the constraint to be satisfied. |
| `conditionHash` | array of string | One hash per evaluated condition. Every value in `required_condition_hashes` MUST appear in this array. Hash values are opaque hex strings; the canonicalization algorithm is issuer-specific (see §7 for the reference implementation's algorithm). |

**JWT payload — OPTIONAL claims** (not used by the verification algorithm;
issuers MAY include these for audit, debugging, or application-layer
consumption):

| Claim | Type | Description |
|-------|------|-------------|
| `results` | array of object | Per-condition evaluation detail. Useful for debugging and audit trails, but verifiers MUST NOT use it as a substitute for the `conditionHash` and `pass` checks. |
| `blockNumber` | string | Block number or ledger index at which the condition was evaluated. Provides a chain-anchored audit trail. |
| `blockTimestamp` | string (ISO 8601) | Block timestamp at which the condition was evaluated. |

Issuers MAY include additional claims beyond those listed above. The
verification algorithm (§4.2) is defined solely in terms of the REQUIRED
claims; OPTIONAL and additional claims do not affect constraint satisfaction.

**Key discovery**: Verifiers MUST resolve the public key by fetching
`trusted_jwks` and locating the JWK whose `kid` matches the JWT header `kid`.
This follows [RFC 7517] (JWKS) and the standard OAuth/OpenID Connect JWT
verification path. No custom canonicalisation is required — the JWS signature
covers the standard base64url-encoded header and payload.

### 4.2 Validation Algorithm

**Pre-condition**: This algorithm MUST be executed before the agent creates
Layer 3. Verifiers MUST repeat this algorithm independently at Layer 3
verification time (with a fresh attestation fetch if the agent's attestation
has expired).

**Input**: constraint `C` (an `environment.wallet_state` object), current
time `now`.

**Fail-closed rule**: Any step that cannot be completed successfully MUST
produce a **violation**. There is no partial credit and no fallback to a
permissive default.

```
function check_environment_wallet_state(C, now):

    # Step 1 — Validate constraint structure
    if C.attestation_url does not start with "https://":
        return violation("Non-HTTPS attestation_url: fail-closed")
    if C.trusted_jwks does not start with "https://":
        return violation("Non-HTTPS trusted_jwks: fail-closed")
    if C.expected_kid is empty or C.expected_issuer is empty:
        return violation("expected_kid/expected_issuer must be non-empty")
    if C.subject_wallet is empty:
        return violation("subject_wallet must be non-empty")
    if length(C.required_condition_hashes) == 0:
        return violation("required_condition_hashes must be non-empty")
    if C.max_attestation_age is absent:
        return violation("max_attestation_age is REQUIRED; constraint is malformed: fail-closed")
    let max_age = C.max_attestation_age
    if max_age < 1:
        return violation("max_attestation_age must be >= 1")
    if C.stale_cache_fallback_permitted is present and not boolean:
        return violation("stale_cache_fallback_permitted must be boolean if present: fail-closed")

    # Step 2 — Fetch attestation (timeout: 4 seconds)
    let body = C.attestation_request_body ?? {}
    let response = http_post(C.attestation_url, body, timeout=4s)
    if request fails (timeout, DNS, connection error, non-2xx response):
        return violation("Attestation fetch failed: fail-closed")
    let response_json = parse_json(response.body)
    if parse fails or response_json.jwt is missing:
        return violation("Attestation response missing jwt field: fail-closed")
    let jwt = response_json.jwt

    # Step 3 — Decode JWT header and verify kid
    let header = jwt_header(jwt)
    if header.kid != C.expected_kid:
        return violation("JWT kid does not match expected_kid: fail-closed")

    # Step 4 — Fetch JWKS and locate signing key
    let jwks = http_get(C.trusted_jwks, timeout=4s)
    if request fails:
        return violation("JWKS unreachable: fail-closed")
    let keys = parse_json(jwks).keys
    let key_entry = find(keys, k => k.kid == header.kid)
    if key_entry is null:
        return violation("Signing key not found in JWKS: fail-closed")

    # Step 5 — Verify JWT signature
    let verified = jws_verify(jwt, key_entry)
    if not verified:
        return violation("JWT signature verification failed: fail-closed")
    let payload = jwt_payload(jwt)

    # Step 6 — Verify iss / sub
    if payload.iss != C.expected_issuer:
        return violation("JWT iss does not match expected_issuer: fail-closed")
    if payload.sub != C.subject_wallet:
        return violation("JWT sub does not match subject_wallet: fail-closed")

    # Step 7 — Verify expiry
    if now_unix() > payload.exp:
        return violation("Attestation has expired (exp in past): fail-closed")

    # Step 8 — Verify attestation age against max_attestation_age
    let age_seconds = now_unix() - payload.iat
    if age_seconds > max_age:
        return violation("Attestation age exceeds max_attestation_age: fail-closed")

    # Step 9 — Verify pass is true
    if payload.pass != true:
        return violation("Attestation pass is not true: constraint not satisfied")

    # Step 10 — Verify every required condition hash is present
    for each required_hash in C.required_condition_hashes:
        if required_hash not in payload.conditionHash:
            return violation(
                "Required condition hash " + required_hash + " not in attestation: constraint not satisfied"
            )

    # All checks passed
    return satisfied(jti=payload.jti)
```

**Processing order is normative.** Steps MUST be executed in order. A failure
at any step terminates the algorithm with a violation; subsequent steps MUST
NOT be executed.

**`jti` logging**: On satisfaction, agents and verifiers MUST log the `jti`
value in their execution audit trail. This enables post-hoc verification that
the wallet state on which a decision was made was a legitimate, signed
attestation — not a spoofed or replayed response.

### 4.3 `pass=false` Handling

The attestation issuer may return a valid, signed attestation with `pass:
false` — the wallet exists, the condition was evaluated, but the result is
negative (e.g., the wallet no longer holds the required balance). Implementations
MUST treat `pass: false` as a constraint violation (Step 9). This is the
normal, expected termination path when the wallet state has changed
unfavourably between L2 issuance and L3 verification — the fail-closed
guarantee is what makes the constraint load-bearing.

### 4.4 Attestation Staleness During Verification

A verifier checking Layer 3 at time `T` MUST fetch a fresh attestation from
`attestation_url` if the attestation the agent embedded in L3 (per §2.4
RECOMMENDED field) is expired at time `T`. The verifier MUST apply the full
verification algorithm (§4.2) to the freshly fetched attestation.

If the fresh attestation shows `pass: false` (e.g., the wallet was drained
between agent execution and verifier checking), the verifier MUST treat the
constraint as violated. The agent executed in a valid environment; the
verifier is recording that the environment has since changed. Dispute
resolution in this case is an application-layer concern outside this
specification.

### 4.5 Example

Checkout mandate constraint requiring the source wallet to hold at least
1 USDC on Ethereum mainnet before checkout:

```json
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
      {
        "type": "token_balance",
        "chainId": 1,
        "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "decimals": 6,
        "threshold": 1
      }
    ],
    "format": "jwt"
  }
}
```

Composition with `environment.market_state` — both constraints in a single
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

### 4.6 Attestation Freshness and TOCTOU

The `max_attestation_age` field is the mandate issuer's normative declaration
of the maximum acceptable TOCTOU window between attestation signing and
constraint evaluation. It is the primary security property of any
`environment.*` constraint: the freshness window is the exploitable surface.

**Why this field is REQUIRED.** The DeFi oracle exploit literature — Mango
Markets ($117M, 2022), Balancer ($116M, 2023), and the broader class of
flash-loan-enabled TOCTOU attacks — demonstrates that when freshness is left
as an implementation default rather than an explicit policy declaration,
exploitable gaps are the norm, not the exception. Attestation TTL (the
issuer's `exp` claim) is a provider-side default; `max_attestation_age` is a
consumer-side policy bound. The two serve different principals and MUST be
independently configurable.

**Family-wide semantics.** For any `environment.*` constraint,
`max_attestation_age` carries the same meaning: the mandate issuer's
declaration of the maximum acceptable TOCTOU window between attestation
signing (`iat`) and constraint evaluation (`now`). This field SHOULD use the
same name and semantics across all `environment.*` constraint types to enable
a single verification code path. The `environment.market_state` specification
(PR #9) is invited to adopt this field and semantics for lockstep alignment.

**Guidance for mandate issuers.** Values SHOULD reflect the economic risk
of the gated action. Payment execution against volatile assets may warrant
`max_attestation_age: 30`; compliance checks against stable state may tolerate
`max_attestation_age: 300`. The reference implementation (§7) issues
attestations with a 1800-second TTL; mandate issuers can narrow this to any
shorter window via `max_attestation_age`.

### 4.7 Algorithm Agility

**Family-wide policy.** The `environment.*` constraint family is
algorithm-agnostic at the family level, per [RFC 8725] §3.1 ("Algorithm
Verification"). Each constraint type declares a MUST-implement signing
algorithm that all conformant verifiers for that type MUST support:

| Constraint type | MUST-implement | Rationale |
|-----------------|---------------|-----------|
| `environment.wallet_state` | ES256 (P-256) | Composes with VI's existing ES256/SD-JWT stack (design-rationale §5); standard JWS base64url encoding, no custom canonicalization required. |
| `environment.market_state` | Ed25519 | Matches the reference implementation's signing stack (Headless Oracle); high-performance single-curve verification. |

Each constraint type SHOULD additionally support a RECOMMENDED extension set
and MAY support further algorithms. For `environment.wallet_state`:

- MUST: `ES256`
- SHOULD: `ES384`, `ES512`
- MAY: `EdDSA` (Ed25519, Ed448)

Verifiers negotiate the algorithm per constraint instance by reading the JWT
header `alg` field and confirming it is in their supported set for the
constraint type. Verifiers MUST reject attestations whose `alg` is not in
their supported set — this is a fail-closed check, not a silent downgrade.

**Avoiding accidental single-algorithm lock-in.** This agility model ensures
the `environment.*` family does not inherit a single-algorithm constraint by
accident. Each type's MUST-implement choice is defensible from its reference
implementation's signing stack; the extension sets ensure verifier libraries
can evolve without spec revisions.

> **Note for PR #9 coordination**: This section is drafted as a standalone
> block that can be adopted verbatim in `environment.market_state` §8 with
> the table rows swapped. The intent is one family-wide question, one answer,
> two specs.

### 4.8 Field Scope Declaration

The `environment.*` constraint family contains fields that appear under identical names in multiple constraint types. A shared field name does not, by itself, imply shared semantics: some fields carry identical meaning across types, while others have parallel-but-mechanism-specific meaning tied to each type's trust-root mechanism. To prevent ambiguity, each field in the family MUST declare its scope under one of the categories below.

**Scope categories.** The family currently recognises three scope categories:

- **family-wide-trust-root-agnostic** — the field carries identical semantics across every `environment.*` constraint type, independent of the trust-root mechanism each type uses. A single verification code path handles the field for every type in the family.

- **per-type-trust-root-mechanism-bound** — the field's operational semantics depend on the specific trust-root mechanism of the constraint type (RFC 7517 JWKS for `environment.wallet_state`, RFC 8615 key registry for `environment.market_state`, or a future mechanism). The field name may appear in multiple specifications with parallel but mechanism-specific semantics.

- **per-type-evaluation-mechanism-bound** — the field's operational semantics depend on the constraint type's evaluation mechanism: the output shape the evaluator produces (for example, condition-hash sets for `environment.wallet_state`, status enum for `environment.market_state`) or the wire-protocol binding to the evaluator (for example, the request body shape sent to `attestation_url`). The field name may appear in multiple specifications with parallel but evaluation-specific semantics; distinct from `per-type-trust-root-mechanism-bound` in that the binding is to *how the attestation is produced and shaped*, not to *how the signing key is discovered*.

Within §4.8, "field" encompasses both constraint schema fields declared in §4 and, where operationally relevant, JWT claims declared in §4.1.

**Scope declarations for current `environment.wallet_state` fields.**

| Field | Scope | Reference |
|-------|-------|-----------|
| `max_attestation_age` | family-wide-trust-root-agnostic | §4.6 |
| `attestation_url` | family-wide-trust-root-agnostic | §4.1 |
| `trusted_jwks` | per-type-trust-root-mechanism-bound | §6.3 |
| `expected_kid` | per-type-trust-root-mechanism-bound | §6.3 |
| `expected_issuer` | per-type-trust-root-mechanism-bound | §6.3 |
| `stale_cache_fallback_permitted` | per-type-trust-root-mechanism-bound | §6.8 |
| `subject_wallet` | per-type-evaluation-mechanism-bound | §5.5 |
| `required_condition_hashes` | per-type-evaluation-mechanism-bound | §4.1 |
| `attestation_request_body` | per-type-evaluation-mechanism-bound | §4.1 |
| `blockTimestamp` | per-type-evaluation-mechanism-bound | §4.1 |
| `finality_depth` | per-type-evaluation-mechanism-bound | §4 |
| `max_cross_chain_skew_seconds` | per-type-evaluation-mechanism-bound | §4 |

`max_attestation_age` is family-wide because the freshness window is a temporal property of the attestation signing event itself, independent of how the verifier retrieves the signing key. `attestation_url` is family-wide-trust-root-agnostic because its semantic role — the HTTPS endpoint at which the verifier fetches the signed attestation — is identical across every `environment.*` constraint type, whether signing keys are discovered via RFC 7517 JWKS or RFC 8615 key registry. Per-type variance in the wire protocol (HTTP verb, request-body shape) is carried by `attestation_request_body` (per-type-evaluation-mechanism-bound) and each type's §4.1 interface specification, not by the URL field itself, which names only location. The placement lands on the same basis as `max_attestation_age` in §4.6: identical semantic role across types, with per-type variance localised at neighbouring fields. `trusted_jwks` and `stale_cache_fallback_permitted` are per-type-trust-root-mechanism-bound because both are defined against the specific JWKS mechanism this constraint type uses: `trusted_jwks` is the RFC 7517 URL the verifier fetches to obtain the signing key (§6.3); `stale_cache_fallback_permitted` governs recovery against that same JWKS cache when fresh fetch fails (§6.8). The sibling field `stale_cache_fallback_permitted` on `environment.market_state` carries the same name but binds to the RFC 8615 key registry cache, with parallel but mechanism-specific semantics. `expected_kid` is per-type-trust-root-mechanism-bound because it is a JWT `kid` header binding specific to the JOSE signing stack `environment.wallet_state` uses for attestation signature verification; the sibling `environment.market_state` specification uses a distinct key-identifier field (`oracle_public_key_id`) against its RFC 8615 key registry, with parallel but mechanism-specific semantics. `expected_issuer` is per-type-trust-root-mechanism-bound because it is a JWT `iss` claim binding specific to the same JOSE signing stack; `environment.market_state` derives issuer identity from the attestation payload under its RFC 8615 key registry rather than from a constraint-level JOSE `iss` binding, so the constraint-level field has no direct sibling on market_state. `subject_wallet`, `required_condition_hashes`, and `attestation_request_body` are per-type-evaluation-mechanism-bound because their semantics are defined against how this constraint type produces and shapes its attestation: `subject_wallet` names the wallet the attestation is about and is matched against the JWT `sub` claim (the per-member disambiguator in §5.5); `required_condition_hashes` is the set the verifier matches against the attestation's `conditionHash` array (the wallet-state-specific output shape); `attestation_request_body` is the issuer-specific POST body the verifier sends to `attestation_url` to obtain a fresh attestation (the wire-protocol binding to the evaluator). `blockTimestamp`, where present on the attestation as an OPTIONAL JWT payload claim per §4.1, is per-type-evaluation-mechanism-bound because the claim carries the chain-tip block timestamp the attestation anchors to — a chain-reading evaluation primitive specific to wallet_state's chain-state output shape; the sibling `environment.market_state` carries no analogous claim because its evaluation reads exchange-session state rather than chain-tip state. `finality_depth` is per-type-evaluation-mechanism-bound because chain-confirmation semantics are defined only against wallet_state's chain-reading evaluation primitive; market-session types have no analogous primitive. `max_cross_chain_skew_seconds` is per-type-evaluation-mechanism-bound because cross-chain wall-clock coordination is a wallet_state-specific evaluation concern — multiple chain tips with independent finality clocks — rather than a family-wide temporal concern; the §4.8 forward rule anchors the wallet_state-local placement against speculative family-wide proliferation (see §6.9).

**Rule for future fields.** New fields introduced in any `environment.*` constraint type in future specification revisions MUST declare their scope category at introduction. Declarations are made in the constraint type's Field Scope Declaration section (this section, §4.8 in `environment.wallet_state`; the analogous section in each sibling specification). Additions of new scope categories beyond the three currently recognised are working-group revisions; type authors SHOULD place fields under one of the existing categories where possible rather than proposing new categories.

**Relationship to §4.6 and §4.7.** This section formalises at charter level the field-scope distinction that §4.6 (freshness) and §4.7 (algorithm agility) already imply in their specific domains: §4.6 states that `max_attestation_age` is family-wide; §4.7 establishes per-type MUST-implement algorithms with family-wide agility framework. §4.8 makes the underlying scope discipline — "which fields are family-wide, which are per-type, and why" — explicit so that future fields are not added to the family without a scope declaration.

> **Note on family coordination**: Mirrors `environment.market_state` §4.8 at commit [`7b97827`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/7b978279ff847ef5c0db805a883be373616116b9) with the field table rows swapped for this specification's current fields. The three scope categories, preamble, rule for future fields, and relationship to §4.6/§4.7 are verbatim family-wide prose. Same pattern as §4.6, §4.7, §5.5, §6.8 — one family-wide question, one answer, two specs.

---

## 5. Validation Algorithm Integration

### 5.1 Integration with constraints.md §5.3

The `environment.wallet_state` constraint integrates into the VI constraint
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

**Rationale**: Evaluating amount or merchant constraints before confirming the
execution environment is valid exposes the agent to a TOCTOU race — the agent
might confirm a valid amount constraint and then execute against a wallet that
no longer satisfies the entry condition, or into a closed market. This
rationale is inherited 1:1 from §5.2 of `environment.market_state`.

### 5.3 Strictness Mode Interaction

`environment.wallet_state` is a registered type. It MUST NOT be skipped in
PERMISSIVE mode. An unknown variant of this type (e.g., a future
`environment.wallet_state_v2`) would be subject to normal strictness mode
handling per constraints.md §5.4.

### 5.4 Output Fields

The constraint checker result (constraints.md §5.2) MUST include, for each
evaluated `environment.wallet_state` constraint:

- On satisfaction: `checked` list includes `"environment.wallet_state"`.
  Implementations SHOULD also log `jti` in the audit context (outside the
  standard result object).
- On violation: `violations` list includes the reason string from §4.2 step
  that failed.

### 5.5 Family Composition

**Conjunction semantics.** The `environment.*` family is a conjunction: a mandate satisfies the family's gate if and only if every `environment.*` constraint in the mandate passes. There is no partial-fulfillment path within the family.

**Mixed pass/fail.** When one `environment.*` constraint passes and another fails in the same mandate — for example, `environment.wallet_state` returns `pass: true` for a primary settlement wallet while a second `environment.wallet_state` returns `pass: false` for a gas wallet, or `environment.wallet_state` returns `pass: true` while `environment.market_state` returns `CLOSED` — the family's gate fails. The passing member does not rescue the failing member.

**L3 execution gate and completeness.** Verifiers MUST evaluate every `environment.*` constraint in the mandate to completion before refusing Layer 3, even after the first failure has been observed. The completeness requirement applies to the verifier-side L3-acceptance evaluation path; agent-side pre-L3-creation evaluation is governed by §5.2's short-circuit clause, which requires agents to stop at the first `environment.*` failure as a fail-closed agent-side halt distinct from the verifier's diagnostic-completeness obligation. The `violations` list MUST contain one entry per failed `environment.*` constraint regardless of which member failed first. Short-circuit evaluation of `environment.*` constraints is non-conforming because it denies downstream consumers the per-member evidence the gate depends on. Transactional constraint evaluation (`mandate.*`) after a confirmed `environment.*` failure remains implementation-defined (verifiers MAY evaluate for diagnostic completeness, MAY skip for efficiency) as long as L3 refusal is unambiguous. This composes with §5.2's ordering requirement — environment-before-transactional stays; the completeness rule layers on top.

**Per-member diagnostic output.** Each failed `environment.*` constraint MUST produce its own entry in the `violations` list. Each violation entry MUST carry two identifiers: the array index of the constraint in the mandate's `constraints[]` array as the primary machine identifier (unambiguous across any combination of constraint types and repeats), and a human-readable identifier derived from the constraint's distinguishing field. Selection of the distinguishing field is a per-type obligation declared by each constraint type specification, analogous to the per-type declaration of MUST-implement algorithms in §4.7. For `environment.wallet_state`, the distinguishing field is `subject_wallet` — REQUIRED per §4 schema, always present, no fallback needed. For `environment.market_state`, the distinguishing field is the MIC, taken from the signed attestation's `mic` field when present per companion §4.1, falling back to the constraint's attestation-URL parse. Verifiers MUST NOT collapse multiple `environment.*` failures into a single generic violation. This preserves the diagnostic signal needed for post-hoc analysis and dispute resolution, and disambiguates cases where multiple constraints of the same type appear in a single mandate — for `environment.wallet_state`, the driving case is multiple wallet-state constraints in a single mandate with different `subject_wallet` values (e.g., a settlement wallet and a separate gas wallet, both of which must satisfy their own condition hashes before L3).

**Rationale.** Two arguments, co-equal, reinforcing. The semantic argument: each member of the family answers an independent question — is this wallet still funded? is this market open? Because the questions are independent, their answers compose as AND, not OR: a failure on any member removes the basis for execution. The architectural argument: conjunction also falls out of fail-closed posture directly. Any `environment.*` type whose failure mode is OR-tolerable is, by definition, outside the family's design charter — if a constraint's failure is survivable, it is not gating execution, and if it is not gating execution, it is not in the family. This matters forward. When `environment.regulatory_status`, `environment.counterparty_credit`, or any other future `environment.*` type is proposed, conjunction is not a design decision to re-litigate per type; it is a membership criterion. The per-member diagnostic requirement follows from the same logic: collapsing per-member diagnostics would destroy the audit trail that makes the family load-bearing. Preserving them makes every signed attestation recoverable from the validation output, and makes dispute resolution an application-layer concern with complete evidence rather than a debugging exercise.

> **Note on family coordination**: Mirrors `environment.market_state` §5.5 at commit [`7a8987c`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/7a8987cc34752d6f7f97bb645d67cfaf129e1cda) with the per-type distinguishing-field row swapped. Same pattern as §4.7 — one family-wide question, one answer, two specs.

---

## 6. Security Considerations

### 6.1 Issuer Trust Bootstrapping

The security of this constraint depends on the verifier correctly establishing
the issuer's JWKS URL. The `/.well-known/jwks.json` path is the convention
established by [RFC 7517] and OpenID Connect Discovery; JWKS hosted at any
HTTPS URL is valid provided it is referenced explicitly by the constraint.

Initial trust in the issuer domain requires out-of-band verification (DNSSEC,
CT logs, published key fingerprints). Agents and verifiers SHOULD verify the
issuer's JWKS against at least one out-of-band source before trusting
attestations.

### 6.2 Attestation Replay

A valid signed attestation is replayable within its `exp` window. The
`max_attestation_age` field narrows this window below `exp` when needed. The
`jti` claim enables consumers that require per-attestation deduplication to
detect and reject replayed attestations within the TTL window.

For payment execution contexts, verifiers SHOULD maintain a short-lived
`jti` deduplication cache (TTL: `max_attestation_age + 30s`) to prevent a
single attestation from being used to authorise multiple L3 creations.

### 6.3 Issuer Endpoint Substitution (Answer to Companion §8 Q2)

This is the concrete answer to the open question in `environment.market_state`
§8 Q2 ("Oracle allowlisting"): **trust is bound to the signing key via JWKS,
not to the endpoint URL.**

An attacker who can modify the Layer 2 mandate could substitute a malicious
`attestation_url` pointing to an attacker-controlled server. In the current
`environment.market_state` design, the only defence is the Layer 2 signature
chain. In this design, the attacker must *additionally* substitute
`trusted_jwks` with an attacker-controlled JWKS URL, and the attacker's JWKS
URL must *also* survive the policy-layer allowlist on `trusted_jwks` hosts.

The policy-layer allowlist lives outside this constraint — in the user's
wallet policy, the credential issuer's issuance policy, or the payment
network's merchant onboarding layer, depending on deployment context. The
constraint itself is agnostic about *where* the allowlist lives, but the
binding to `trusted_jwks` (not `attestation_url`) is what makes the
allowlist-check a one-line policy decision rather than a per-endpoint
inventory.

This pattern has two further properties worth flagging:

- **Reuses VI's existing algorithm stack.** ES256 / P-256 is the required VI
  signing algorithm per design-rationale §5. Implementations already have the
  JWT + JWKS verification code path for SD-JWT and KB-SD-JWT. No second crypto
  stack, no new verification library.
- **Subject binding via native `sub` claim.** The JWT's `sub` claim is the
  wallet address, so "this attestation is about this payment source" is a
  native JWT claim check rather than a new constraint field. This is the
  shared subject-binding pattern flagged in LembaGang's review of the
  proposal.

As with `environment.market_state`, verifiers MUST verify the Layer 2
credential signature chain before trusting any field in any constraint object.

**JWKS URL migration.** The `trusted_jwks` URL is a signed L2 constraint
field. Issuers migrating to a new JWKS URL cannot be followed by existing
mandates — migration is a new-mandate event. The migration path is: issuer
publishes a new JWKS at the new URL; mandate issuers emit new mandates
targeting the new URL; existing mandates with the old URL expire naturally
via `exp`. This is a deliberate design choice that binds trust-root identity
into the signed constraint rather than into a mutable issuer-side pointer.
The cost is that URL migration is not free; the benefit is that the trust
root cannot be silently relocated.

### 6.4 SSRF via attestation_url and trusted_jwks

Both `attestation_url` and `trusted_jwks` are mandate-controlled URLs that
verifiers will fetch. Implementations MUST apply SSRF protections:
- Reject non-HTTPS schemes (enforced by §4 field constraints)
- Reject URLs resolving to private IP ranges (RFC 1918, loopback, link-local)
- Set a strict request timeout (RECOMMENDED: 4 seconds; MUST NOT exceed 10
  seconds)
- Do not follow more than one redirect

### 6.5 Constraint Stripping

An attacker removing an `environment.wallet_state` constraint from a Layer 2
mandate would expand the agent's authority to execute against any wallet
state. This attack is prevented by the KB-SD-JWT+KB signature on Layer 2 —
any removal of constraints from the mandate payload invalidates the user's
signature. Verifiers MUST reject any mandate whose Layer 2 signature does not
validate over the full constraint list as presented; implementations MUST NOT
accept mandates where the verified signature covers only a subset of the
declared constraints.

### 6.6 Condition Hash Collision Assumptions

The constraint binds the attestation to a specific boolean condition via the
`conditionHash` array. The security of this binding depends on the issuer's
condition-hashing function being collision-resistant over the space of
conditions the issuer accepts. The condition hash values in
`required_condition_hashes` are opaque to the constraint — the verifier does
not recompute them; it matches them against the attestation's `conditionHash`
array. Mandate issuers that need to precompute a condition hash to populate
`required_condition_hashes` MUST use the same canonicalisation the target
issuer uses (see §7.1 for the reference issuer's canonicalisation algorithm).

Implementations MUST NOT use a condition hash as a standalone claim (the
attestation JWT as a whole is what is signed); the hash is a binding field,
not a bearer credential.

### 6.7 Time Synchronisation

The `iat` age check (Step 8 of §4.2) requires that the verifier's clock is
reasonably synchronised with the issuer's clock. A clock skew exceeding
`max_attestation_age` would cause all attestations to be rejected.
Implementations SHOULD use NTP-synchronised clocks and SHOULD log
clock-skew-related failures distinctly to aid diagnosis.

### 6.8 JWKS Caching and Key Rotation

The `trusted_jwks` URL is the trust root for attestation verification
(§6.3). Naive implementations that re-fetch the JWKS on every verification
create avoidable load on the issuer and expose verifiers to failure modes
(rate limits, transient network errors) that are not failures of the
attestation itself. This section defines the conforming caching and
rotation behaviour.

**Caching permissibility.** Verifiers MAY cache the JWKS fetched from
`trusted_jwks`. Verifiers SHOULD respect the issuer's `Cache-Control`
directive when present. When `Cache-Control` is absent, verifier-side TTL
is implementation-defined, subject to the kid-mismatch rule below.

**Kid-mismatch as cache bust.** When the verifier encounters an
attestation whose `kid` is not present in the cached JWKS, the verifier
MUST bypass the cache and fetch the JWKS fresh before rejecting the
attestation. This ensures attestations signed during a key-rotation window
are verifiable as soon as the new key is published, without waiting for
the cache TTL to elapse.

**Issuer rotation responsibilities.** Issuers rotating a signing key
SHOULD publish both the old and new keys in the JWKS simultaneously during
a grace window. The grace window SHOULD exceed both:

- The maximum attestation lifetime the issuer will sign with the old kid
  after starting rotation.
- The verifier JWKS cache TTL the issuer publishes via HTTP `Cache-Control`.

During the grace window, attestations signed with either kid MUST verify
against their corresponding key entry. After the grace window elapses, the
issuer MAY remove the old key entry. Verifiers holding a stale cache
containing only the old key will fetch fresh and observe the transition on
the next mismatched kid, or at cache expiry, whichever comes first.

**Grace-window discoverability.** Issuers SHOULD publish rotation-start
and grace-window-end timestamps through an auditable channel. The channel
MAY be out-of-band (release notes, status page, signed rotation
announcement) or in-band via a JWKS top-level metadata field (e.g.,
`rotation_announcement: { rotation_started_at, previous_kid, new_kid,
grace_window_end }`). This specification does not mandate a mechanism; the
SHOULD is on discoverability, not form. If the working group converges on
a canonical in-band mechanism, a future revision can elevate it to
REQUIRED.

**Fail-closed on fetch failure.** If JWKS fetch fails (network error,
non-2xx response, malformed JSON) and no usable cache is available, the
constraint evaluation MUST produce a violation entry. Verifiers MUST NOT
fall back to a hard-coded public key as a recovery path — the JWKS URL is
the trust root, and silent fallback undermines the §6.3 binding. When
`stale_cache_fallback_permitted` is `true`, verifiers MAY use an expired
cache as a last-resort fallback on fresh-fetch failure; when `false` (the
default when the field is absent), verifiers MUST produce a violation. For
mandates where strict freshness is required (e.g., payment execution), the
field MUST NOT be set to `true` (see §4 Field Constraints).

**Per-constraint scope.** JWKS fetch failures are per-constraint. A fetch
failure on one `environment.wallet_state` constraint MUST NOT short-circuit
evaluation of other `environment.*` constraints in the mandate; each
constraint produces its own violation entry independently. This scoping
preserves the diagnostic signal needed for dispute resolution even when a
single issuer endpoint is unreachable.

**Interaction with §6.2 replay cache.** The `jti` dedup cache and the
JWKS cache are independent. The `jti` cache TTL is bound by
`max_attestation_age + 30s`; the JWKS cache TTL is bound by issuer cache
directives. No cross-dependency.

### 6.9 Cross-Chain Temporal Consistency

§6.7 addresses the adjacent-but-distinct concern of verifier↔issuer
wall-clock skew — the freshness check of §4.2 Step 8 against
`max_attestation_age`. This section addresses a different axis:
attested-block↔chain-tip skew and cross-chain wall-clock coordination
when a mandate composes attestations from separate chains.

**Orthogonal axes.** Cross-chain wall-clock coordination
(`max_cross_chain_skew_seconds`) and within-chain finality remediation
(reorg re-verification SHOULD) are orthogonal axes: the former bounds
tip-time divergence across chains at evaluation time; the latter addresses
attested-block reorganization on a single chain post-acceptance at
settlement time. Multi-chain mandates surface each axis independently per
participating chain.

**Finality-depth measurement.** The confirmation depth against which
`finality_depth` is evaluated is derived from the verifier's independent
read of the chain at verification time; no additional JWT claim is
required from the attestation issuer for this check, preserving the v0.2
provider-neutrality contract on §4.1.

**Reorg remediation (advisory).** Verifiers SHOULD re-verify the
attestation against the anchoring chain's then-current finality state at
settlement time to detect post-acceptance reorganization of the attested
block. This SHOULD is advisory: the specification does not mandate
synchronous chain-finality checks at L3 acceptance, since such checks
would overconstrain verifier implementations. The SHOULD applies at the
VI verifier's application-layer L3-acceptance logic and does not extend
to chain client, RPC transport, or cryptographic library behavior.

**Measurement basis for `max_cross_chain_skew_seconds`.** When
`max_cross_chain_skew_seconds` is evaluated, verifiers MUST measure
wall-clock skew across the mandate's `environment.*` attestations using
the attestation's `blockTimestamp` claim when present, falling back to
the attestation's `iat` claim otherwise. Skew is computed in Unix
seconds: verifiers MUST convert ISO 8601 `blockTimestamp` values (per
§4.1) to integer Unix seconds (truncating any sub-second precision)
before comparison. Issuers SHOULD include
`blockTimestamp` on chains where a block-time anchor is available, so
that verifiers have access to the tighter chain-tip-time measurement for
mandates that require it; issuers MAY omit `blockTimestamp` on chains
where no such anchor exists (e.g., certain non-EVM chains), in which
case `iat` governs cross-chain skew measurement and `max_attestation_age`
continues to bound per-attestation freshness. The truncation asymmetry —
verifiers MUST truncate to whole Unix seconds, issuers unconstrained on
`blockTimestamp` precision — is intentional: verifier-side truncation
ensures deterministic cross-chain comparison semantics, while issuer-
side flexibility preserves sub-second precision for consumers outside
the `max_cross_chain_skew_seconds` evaluation context.

**Placement rationale.** The scope-declaration analysis in §4.8 places
`blockTimestamp`, `finality_depth`, and `max_cross_chain_skew_seconds`
under `per-type-evaluation-mechanism-bound`, not under a family-wide
temporal dimension. The `environment.market_state` sibling does not
surface cross-venue temporal concerns distinct from per-attestation
freshness: session state is wall-clock-anchored rather than chain-
anchored; session boundaries and halt-resumption events resolve as
freshness concerns absorbed by `max_attestation_age`. §4.8's forward rule
applies: *"type authors SHOULD place fields under one of the existing
categories where possible rather than proposing new categories."* The
same discipline holds at section-level — when a field or section's need
is demonstrated for one type but not others, wallet_state-local placement
with §4.8 scope-declaration is the right pattern until evidence of
broader applicability surfaces. Future `environment.*` types that surface
cross-venue temporal concerns at working-group review time can elevate
cross-chain coordination to a family-wide §4.9 as a working-group
revision.

---

## 7. Reference Implementation: InsumerAPI

### 7.1 Overview

[InsumerAPI](https://api.insumermodel.com) is the reference implementation
of a conformant wallet-state attestation issuer for this constraint type. It
evaluates boolean conditions against live on-chain state across 33 chains and
returns ES256-signed JWTs that conform to the abstract interface defined in
§4.1.

| Property | Value |
|----------|-------|
| API base URL | `https://api.insumermodel.com` |
| Attestation endpoint | `POST /v1/attest` (requires `X-API-Key`) |
| Trust profile endpoint | `POST /v1/trust` (requires `X-API-Key`) |
| Agent-native key purchase | `POST /v1/keys/buy` (no auth; wallet is identity; USDC, USDT, or BTC) |
| JWKS (RFC 7517) | `GET /.well-known/jwks.json` |
| OpenAPI spec | `GET /openapi.yaml` |
| AI agent discovery | `GET /llms.txt` |
| Signing algorithm | ES256 (RFC 7518) via JOSE (`jose` npm package) |
| JWT TTL | 1800 seconds (`exp = iat + 1800`) |
| Key curve | P-256 (`alg: ES256`, `kty: EC`, `crv: P-256`, `kid: insumer-attest-v1`) |
| Supported chains | 33 — all major EVM chains, Solana, XRPL, Bitcoin, and additional chains documented in `/openapi.yaml` |

### 7.2 Condition Hash Canonicalization

The reference issuer computes condition hashes as:

```
conditionHash = "0x" + sha256(canonical_json(evaluated_condition))
```

where `canonical_json` is `JSON.stringify` with object keys sorted
lexicographically. The `evaluatedCondition` object contains the normalized
form of the condition as evaluated (e.g., `{ type, chainId, contractAddress,
operator, threshold, decimals }` for a `token_balance` condition).

Mandate issuers that need to precompute `required_condition_hashes` for
constraints targeting InsumerAPI MUST use this same canonicalization. The
full `evaluatedCondition` schema per condition type is documented in the
[InsumerAPI OpenAPI spec](https://api.insumermodel.com/openapi.yaml).

Other conformant issuers MAY use a different condition hash algorithm
provided it is collision-resistant and documented. The constraint's
`required_condition_hashes` values are opaque to the verification algorithm
(§4.2 Step 10) — the verifier matches them, it does not recompute them.

### 7.3 Implementation-Specific Response Claims

In addition to the REQUIRED claims defined in §4.1, the reference issuer
includes the following OPTIONAL claims in every attestation JWT:

| Claim | Type | Description |
|-------|------|-------------|
| `results` | array of object | Per-condition evaluation detail: `{ condition, label, type, chainId, met, evaluatedCondition, conditionHash }` per condition. |
| `blockNumber` | string (hex) | Block number at which the first condition was evaluated (EVM chains). |
| `blockTimestamp` | string (ISO 8601) | Block timestamp at which the first condition was evaluated. |

These claims provide a chain-anchored audit trail. Verifiers MAY log them for
audit but MUST NOT use them as a substitute for the `conditionHash` and `pass`
checks defined in §4.2.

### 7.4 Agent-Native Key Provisioning

The reference issuer supports fully autonomous key provisioning at
`POST /v1/keys/buy`: no email, no signup form, no human in the loop. An agent
submits an `appName`, a `txHash`, and a `chainId`; the endpoint verifies the
USDC, USDT, or BTC transfer on-chain, dedupes against the sender wallet, and
returns a new API key. This is structurally aligned with the VI execution
model — an agent that has on-chain spending authority on behalf of its
principal already has everything it needs to provision the key required to
fulfill `environment.wallet_state` constraints. No out-of-band credential
issuance step is required.

### 7.5 Live JWKS

Verified 2026-04-15:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
      "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
      "use": "sig",
      "alg": "ES256",
      "kid": "insumer-attest-v1"
    }
  ]
}
```

### 7.6 Minimal Constraint Verifier (JavaScript, `jose`)

```javascript
import { jwtVerify, createRemoteJWKSet } from 'jose';

async function checkWalletStateConstraint(constraint, now = new Date()) {
  const {
    attestation_url,
    trusted_jwks,
    expected_kid,
    expected_issuer,
    subject_wallet,
    required_condition_hashes,
    max_attestation_age,
    attestation_request_body = {},
  } = constraint;

  if (max_attestation_age === undefined) {
    throw new Error('max_attestation_age is REQUIRED; constraint is malformed: fail-closed');
  }

  // Step 1 — Structural validation
  if (!attestation_url.startsWith('https://') || !trusted_jwks.startsWith('https://')) {
    throw new Error('Non-HTTPS URL in constraint: fail-closed');
  }
  if (!required_condition_hashes || required_condition_hashes.length === 0) {
    throw new Error('required_condition_hashes must be non-empty: fail-closed');
  }

  // Step 2 — Fetch attestation
  let jwt;
  try {
    const res = await fetch(attestation_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestation_request_body),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    jwt = body?.data?.jwt ?? body?.jwt;
    if (!jwt) throw new Error('Response missing jwt field');
  } catch (e) {
    throw new Error(`Attestation fetch failed: ${e.message} — fail-closed`);
  }

  // Steps 3–5 — Fetch JWKS, verify signature, check iss/sub
  let payload;
  try {
    const JWKS = createRemoteJWKSet(new URL(trusted_jwks));
    const { payload: p, protectedHeader } = await jwtVerify(jwt, JWKS, {
      issuer: expected_issuer,
      subject: subject_wallet,
    });
    if (protectedHeader.kid !== expected_kid) {
      throw new Error(`kid mismatch: ${protectedHeader.kid} != ${expected_kid}`);
    }
    payload = p;
  } catch (e) {
    throw new Error(`JWT verification failed: ${e.message} — fail-closed`);
  }

  // Steps 7–8 — exp (jwtVerify already enforced) and iat age
  const nowUnix = Math.floor(now.getTime() / 1000);
  const ageSeconds = nowUnix - payload.iat;
  if (ageSeconds > max_attestation_age) {
    throw new Error(`Attestation age ${ageSeconds}s exceeds max_attestation_age ${max_attestation_age}: fail-closed`);
  }

  // Step 9 — pass must be true
  if (payload.pass !== true) {
    throw new Error('Attestation pass is not true: constraint not satisfied');
  }

  // Step 10 — every required condition hash must be present
  const attestedHashes = new Set(payload.conditionHash || []);
  for (const required of required_condition_hashes) {
    if (!attestedHashes.has(required)) {
      throw new Error(`Required condition hash ${required} not in attestation: constraint not satisfied`);
    }
  }

  return { satisfied: true, jti: payload.jti };
}
```

### 7.7 Fail-Closed Integration Pattern (Python)

```python
import httpx
from jose import jwt as jose_jwt

def check_wallet_state_constraint(constraint: dict, now_unix: int) -> dict:
    """
    Returns {"satisfied": True, "jti": str} or raises on any failure.
    Fail-closed: any exception means the constraint is NOT satisfied.
    """
    attestation_url = constraint["attestation_url"]
    trusted_jwks = constraint["trusted_jwks"]
    expected_kid = constraint["expected_kid"]
    expected_issuer = constraint["expected_issuer"]
    subject_wallet = constraint["subject_wallet"]
    required_condition_hashes = constraint["required_condition_hashes"]
    if "max_attestation_age" not in constraint:
        raise ValueError("max_attestation_age is REQUIRED; constraint is malformed: fail-closed")
    max_attestation_age = constraint["max_attestation_age"]
    request_body = constraint.get("attestation_request_body", {})

    if not attestation_url.startswith("https://") or not trusted_jwks.startswith("https://"):
        raise ValueError("Non-HTTPS URL: fail-closed")
    if not required_condition_hashes:
        raise ValueError("required_condition_hashes must be non-empty: fail-closed")

    # Fetch attestation JWT
    try:
        r = httpx.post(attestation_url, json=request_body, timeout=4.0)
        r.raise_for_status()
        body = r.json()
        token = body.get("data", {}).get("jwt") or body.get("jwt")
        if not token:
            raise ValueError("Response missing jwt field")
    except Exception as e:
        raise RuntimeError(f"Attestation fetch failed: {e} — fail-closed")

    # Fetch JWKS
    try:
        jwks = httpx.get(trusted_jwks, timeout=4.0).json()
    except Exception as e:
        raise RuntimeError(f"JWKS fetch failed: {e} — fail-closed")

    # Verify signature (jose handles iss, sub, exp, kid → JWK lookup)
    try:
        unverified_header = jose_jwt.get_unverified_header(token)
        if unverified_header.get("kid") != expected_kid:
            raise ValueError("kid mismatch")
        key = next(k for k in jwks["keys"] if k["kid"] == expected_kid)
        payload = jose_jwt.decode(
            token, key, algorithms=[key["alg"]],
            issuer=expected_issuer, subject=subject_wallet,
            options={"verify_aud": False},
        )
    except Exception as e:
        raise ValueError(f"JWT verification failed: {e} — fail-closed")

    # Age check
    age = now_unix - int(payload["iat"])
    if age > max_attestation_age:
        raise ValueError(f"Attestation age {age}s exceeds max_attestation_age {max_attestation_age}: fail-closed")

    # pass check
    if payload.get("pass") is not True:
        raise ValueError("Attestation pass is not true")

    # condition hash check
    attested = set(payload.get("conditionHash", []))
    for required in required_condition_hashes:
        if required not in attested:
            raise ValueError(f"Required condition hash {required} not in attestation")

    return {"satisfied": True, "jti": payload["jti"]}
```

---

## 8. Open Questions

1. **Batch attestation.** Should `attestation_url` be permitted to return an
   attestation covering multiple subject wallets or multiple condition sets
   in a single JWT, with the constraint identifying a subset via claim path?
   This would reduce round-trips for mandates that gate on multiple payment
   sources. Proposal: defer to a `environment.wallet_state_batch` type rather
   than overloading this one.

2. **On-chain verification.** For fully on-chain execution contexts, the
   JWT verification step could be performed by a smart contract using
   P-256 precompile ([EIP-7212](https://eips.ethereum.org/EIPS/eip-7212)) or
   a verifier contract. Specification of on-chain `attestation_url` semantics
   (including IPFS-based attestation blobs and on-chain oracle bridges) is
   deferred to a companion document.

3. **Condition hash extensibility.** This draft binds the constraint to one
   or more literal condition hashes. A future extension could support a
   constraint-time predicate language (e.g., "the attestation MUST contain a
   hash matching this template") to reduce the need for pre-computed hashes
   in mandate issuance. Deferred to v0.2.

4. **Multi-issuer composition.** Can a single `environment.wallet_state`
   constraint require attestations from two independent issuers
   (e.g., InsumerAPI and a second wallet-state issuer) for defence-in-depth?
   Current answer: compose two separate `environment.wallet_state` constraints
   in the mandate. A shorthand `required_issuers` array could be added in
   v0.2 if there is demand.

5. **Family-wide `subject` binding.** LembaGang's review of this proposal
   raised a generalisation worth recording: every `environment.*` constraint
   type has a natural "subject" — the exchange/session for `market_state`,
   the wallet for `wallet_state`, potentially a counterparty DID or
   jurisdiction identifier for future types. A common `subject` claim pattern
   across the family would let verifier libraries implement a single
   "extract subject, match against constraint, enforce binding" code path
   rather than one-off field handling per type. This draft uses the JWT
   `sub` claim to carry the subject wallet, which is directly compatible
   with that unification if the market_state spec adopts a `sub` claim for
   the MIC code or session identifier in a future revision. Working group
   input welcome; this draft does not dictate the family-wide shape but its
   per-type implementation is designed to be a clean fit for one.

---

## 9. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.6.4-draft | 2026-05-03 | **Appendix D: Implementation Status (RFC 6982)** — new appendix listing the running-code implementations of the `environment.*` family. D.1 records InsumerAPI as the running implementation of `environment.wallet_state` — endpoints, License row (proprietary, copyright Douglas Borthwick), ES256/P-256 signing per §4.7 MUST-implement, kid `insumer-attest-v1`, 1800-second JWT TTL, 33-chain coverage (30 EVM + Solana + XRPL + Bitcoin), USDC/USDT/BTC agent-native key provisioning at `POST /v1/keys/buy` per §7.4, condition hash canonicalization per §7.2, and conformance pointer set for §4.1 / §4.2 / §4.6 / §4.7 / §4.8 / §5.5 / §6.5 / §6.8 / §6.9. Refers to §7 for full reference-implementation prose rather than duplicating. D.2 records Headless Oracle as the running implementation of the sibling `environment.market_state` constraint type ([PR #9](https://github.com/agent-intent/verifiable-intent/pull/9)) — endpoints, Ed25519 signing per `environment.market_state` §4.7, 28-exchange coverage, reference verifier; listed for `environment.*` family completeness, with the canonical Implementation Status appendix for `environment.market_state` belonging in PR #9 (editor's call on Michael Msebenzi / LembaGang's side). D.3 disclaimer states that listing is not endorsement and verifiers MUST independently verify per §4.2 regardless of Appendix D listing. Per RFC 6982 §2, the appendix is intended to be removed by the RFC Editor before any final standards-track publication; the GitHub history of this Internet-Draft retains it permanently. **§7.1 + §7.4 source-of-truth alignment**: `POST /v1/keys/buy` payment methods updated from "USDC or BTC" / "USDC (or BTC)" to "USDC, USDT, or BTC" matching production behavior (`openapi.yaml` PaymentChainId: EVM chains and Solana accept USDC and USDT; Bitcoin accepts BTC). §7.4 prose around agent-key-bootstrap rationale generalised from "the authority to spend USDC" to "on-chain spending authority" — drops the canonical-token enumeration mismatch with the §7.4 endpoint enumeration above it without losing the rhetorical argument. Document header stays at `0.6-draft`; v0.6.4 is a patch-level refinement adding an informative appendix and aligning §7 prose with production — no algorithm changes, no security-model changes, no §4 schema changes, no InsumerAPI-side code changes required. Sibling-mirror coordination: independent of the parallel Appendix D landing on the `environment.market_state` side per LembaGang's [`LembaGang/verifiable-intent` commit `21a156cd`](https://github.com/LembaGang/verifiable-intent/commit/21a156cd) anchor (*"a parallel Appendix D on PR #22 is the editor's call on the environment.wallet_state side and is expected to land independently on Douglas Borthwick's timing"*). |
| 0.6.3-draft | 2026-04-23 | **PR #23 field-alignment-v2 propagation** — first coordination commit following Mastercard's [PR #23 merge](https://github.com/agent-intent/verifiable-intent/pull/23) (Reda, Apr 20 2026), mirroring LembaGang's [PR #9 v0.5.6-draft](https://github.com/agent-intent/verifiable-intent/pull/9) propagation commit [`68f4db4`](https://github.com/agent-intent/verifiable-intent/commit/68f4db4) per LembaGang's Apr 23 08:59 UTC handoff note on [PR #9 comment 4303094991](https://github.com/agent-intent/verifiable-intent/pull/9#issuecomment-4303094991) (*"The parallel `environment.wallet_state` RFC lives on a separate file and will propagate its own PR #23 touchpoints independently. No byte-identical mirror is required for this patch."*). Eight touchpoints in `spec/environment-wallet-state.md`, grouped into five categories matching the PR #9 propagation shape. (1) **VCT version suffix** `mandate.checkout.open` → `mandate.checkout.open.1` — 3 occurrences: §2.2 dual-mode prose, §4 Appears In, §4.5 composition example (*NYSE must be open and source wallet must still hold ≥1 USDC*). (2) **VCT version suffix** `mandate.payment.open` → `mandate.payment.open.1` — 2 occurrences: §2.2 dual-mode prose, §4 Appears In. (3) **Constraint type pluralisation** `mandate.checkout.allowed_merchant` → `mandate.checkout.allowed_merchants` — 1 occurrence in §4.5 composition example. (4) **Constraint field generalisation** `allowed_merchants` → `allowed` — 1 occurrence in §4.5 composition example, paired with the pluralisation above. (5) **§5.5 Block 3 prose collapse** `(mandate.*, payment.*)` → `(mandate.*)` — 1 occurrence reflecting PR #23's move of payment constraints under the `mandate.*` prefix. No semantic changes to `environment.wallet_state` itself. Additive PR #23 fields (`match_mode`, `constraint_policy`, `risk_data`) are out of scope — they belong to transactional constraint types, not the `environment.*` family. Document header stays at `0.6-draft` per patch-level convention established at v0.5.1 and reaffirmed at v0.5.3 / v0.6.1 / v0.6.2; v0.6.3 is a patch-level refinement matching LembaGang's PR #9 v0.5.5 → v0.5.6 patch bump for identical propagation work. No algorithm changes; no security-model changes; no InsumerAPI-side code changes required. Sole-authored propagation mirrors LembaGang's sole-authored `Signed-off-by:` trailer discipline on `68f4db4` — no `Co-Authored-By:` trailers on either side. |
| 0.6.2-draft | 2026-04-21 | **Appendix C: Register Discipline (skeleton proposal)** — lockstep mirror of [PR #9 v0.5.5-draft](https://github.com/agent-intent/verifiable-intent/pull/9/commits/01490df8da81fc9482c5d18794380d366961ee80) commit [`01490df`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/01490df8da81fc9482c5d18794380d366961ee80) (LembaGang, Headless Oracle) per LembaGang's Apr 21 22:37 UTC converge signal on [PR #9 comment 4292298210](https://github.com/agent-intent/verifiable-intent/pull/9#issuecomment-4292298210). Six sections at C.1 through C.6, with C.3 containing five rules (RFC 2119 keywords in normative register, lowercase synonyms in descriptive register, redundancy avoidance, application-layer scope, forward rule) and C.4 raising three open questions for working-group review (informative-vs-normative classification, audit cadence, scope evolution over time). C.5 catalog of current instances deferred to a future revision so this round stays skeleton-shaped. Letter alignment confirmed C-to-C, no offset (Appendix A Attestation Test Vectors + Appendix B Failure Mode Quick Reference + Appendix C Register Discipline on both sides). Per-spec localisation at C.1 only (PR-number inversion: `environment.market_state` → PR #9, `environment.wallet_state` → this specification) plus the coordination Note-block rewrite resolving the "pending confirmation of current appendix count on PR #22" caveat and flipping port direction (mirrored-from, not drafted-for). C.2 through C.6 byte-identical to PR #9 `01490df`. Four dispositions all landed as-drafted per [Douglas's Apr 21 four-disposition read on PR #9 comment 4292173322](https://github.com/agent-intent/verifiable-intent/pull/9#issuecomment-4292173322): (a) self-reference tension — MUSTs at C.3.1/C.3.4/C.3.5 kept, preamble does the binding-scope work; Q1 informative-with-normative-cross-references; Q2 deferred to WG with mild preference for continued ad-hoc cadence (forward-scoped if formalised, no retroactive burden); Q3 kept open as drafted with four properties verbatim (provider neutrality, peer-author coordination discipline, patch-level versioning conventions, lockstep commit patterns). Document header stays at `0.6-draft` per patch-level convention established at v0.5.1 and reaffirmed at v0.5.3 / v0.6.1; v0.6.2 is a patch-level refinement. No algorithm changes; no security-model changes; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle). |
| 0.6.1-draft | 2026-04-21 | **§6.9 prose micro-revisions — application-layer scope clarifier + intentional asymmetry naming.** Two additive clarifying sentences in §6.9 responding to LembaGang's §6.9 P3 observations on [PR #22 comment 4288852741](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4288852741) per [Doug's Apr 21 dispositions comment 4289437125](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4289437125) (P3 #1 not taking; P3 #2 and P3 #3 taken as v0.6.1). (1) **Reorg remediation (advisory) — application-layer scope clarifier.** One closing sentence appended to the §6.9 reorg-remediation block naming the advisory SHOULD as the VI verifier's application-layer L3-acceptance logic and excluding chain client, RPC transport, and cryptographic library behavior from its scope. Pre-empts the implementer-reading-§6.9-cold misread of "chain-finality checks" as a network/transport-layer obligation. (2) **Measurement basis — sub-second truncation asymmetry named as intentional.** One closing sentence appended to the §6.9 measurement-basis block naming the verifier-side MUST-truncate / issuer-side unconstrained asymmetry on `blockTimestamp` precision as intentional: verifier-side truncation ensures deterministic cross-chain comparison semantics; issuer-side flexibility preserves sub-second precision for consumers outside the `max_cross_chain_skew_seconds` evaluation context. Both insertions are purely additive — no deletions, no rewording of existing prose, no changes outside §6.9. Document header stays at `0.6-draft` per patch-level convention established at v0.5.1 and reaffirmed at v0.5.3. No algorithm changes; no security-model changes; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle). |
| 0.6-draft | 2026-04-20 | **Cross-chain temporal consistency** — the third and final of the four original held-back follow-ups from LembaGang's Apr 16 review, coordinated on PR #22 with LembaGang's Apr 19 19:09 scope-confirm ([comment 4276613295](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276613295)) and Apr 20 ratification ([comment 4279340548](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4279340548)). Five touchpoints, all wallet_state-local per Option 1 locked Apr 19. (1) **§4 schema** — adds two OPTIONAL fields: `finality_depth` (positive integer, minimum block confirmations past attested block; mandate-issuer-declared) and `max_cross_chain_skew_seconds` (positive integer, maximum tolerated wall-clock divergence across chain-tip timestamps for multi-chain mandates). Companion Field Constraints bullets added matching the `stale_cache_fallback_permitted` malformedness pattern. (2) **§4.1** — unchanged. The v0.2 provider-neutrality contract (7 REQUIRED core claims + `results`/`blockNumber`/`blockTimestamp` OPTIONAL for second-conformant-implementation portability across non-EVM chains) is preserved; no elevation of `blockTimestamp` to REQUIRED. (3) **§4.8 preamble clarification** — one-sentence inline clarification placed between the three scope-category bullets and the "Scope declarations..." header: *"Within §4.8, "field" encompasses both constraint schema fields declared in §4 and, where operationally relevant, JWT claims declared in §4.1."* Wallet_state-local; preserves verbatim cross-spec byte-identity of the preamble sentence and the three category bullets with PR #9 §4.8 at [`85c6594`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/85c65940855aa441789ab9b53002ba959c8d6f86). (4) **§4.8 field table + rationale** — three new rows under `per-type-evaluation-mechanism-bound`: `blockTimestamp` (references existing §4.1 OPTIONAL JWT claim), `finality_depth` (references new §4 constraint field), `max_cross_chain_skew_seconds` (references new §4 constraint field). Rationale paragraph extended with three trailing semicolon-joined sentences in category order paralleling the v0.5.1/v0.5.2 structure; `blockTimestamp`'s rationale inlines a sibling-no-analog clarification pre-empting the WG-reviewer question of why `environment.market_state` has no corresponding entry. (5) **§6.9 Cross-Chain Temporal Consistency** — new security-considerations section placed between §6.8 JWKS caching/rotation and the §7 Reference Implementation section. Six blocks: §6.7 adjacency opening distinguishing verifier↔issuer wall-clock skew from attested-block↔chain-tip skew; orthogonal-axes boundary sentence (pre-acceptance×cross-chain via `max_cross_chain_skew_seconds`, post-acceptance×within-chain via reorg advisory SHOULD); finality-depth measurement note (`finality_depth` check derived from the verifier's independent chain read at verification time, no additional JWT claim required from issuer, preserving the v0.2 provider-neutrality contract on §4.1); reorg remediation advisory (verifier-bound SHOULD on re-verification at settlement time, explicitly not a synchronous chain-finality mandate); measurement-basis note for `max_cross_chain_skew_seconds` (verifier MUST measure skew using `blockTimestamp` when present, falling back to `iat`, with explicit canonicalization — ISO 8601 `blockTimestamp` values per §4.1 MUST be converted to integer Unix seconds, truncating any sub-second precision, before comparison; issuer SHOULD include `blockTimestamp` on chains with a block-time anchor, MAY omit on chains without); and placement rationale anchored in the §4.8 forward rule against speculative family-wide §4.9 proliferation. LembaGang's Apr 19 three-scenario walk-through of `environment.market_state`'s temporal surface (normal state / session boundary / halt-resumption) confirmed no cross-venue skew distinct from per-attestation freshness — `max_attestation_age` absorbs all three — supporting wallet_state-local placement. Document header bumps `0.5-draft` → `0.6-draft`; new-section-level surface matches the v0.5 §4.8-addition precedent for minor-version release discipline. No algorithm changes; no security-model changes beyond §6.9 additions; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle). |
| 0.5.3-draft | 2026-04-20 | **§5.2 body addition + §5.5 Block 3 bridge sentence** (lockstep mirror of [PR #9 v0.5.3](https://github.com/agent-intent/verifiable-intent/pull/9/commits/85c65940855aa441789ab9b53002ba959c8d6f86) commit [`85c6594`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/85c65940855aa441789ab9b53002ba959c8d6f86), LembaGang, Headless Oracle). §5.2 gains the short-circuit sentence verbatim from PR #9 §5.2: *"If any `environment.*` constraint fails, the agent MUST NOT evaluate remaining constraints and MUST NOT proceed to L3 creation."* Brings §5.2 body to parity with #9 and makes the pre-existing "inherited 1:1 from §5.2 of `environment.market_state`" rationale note truthful about body content, not only rationale. §5.5 Block 3 gains the family-wide bridge sentence verbatim from PR #9 §5.5 Block 3 at `85c6594`: *"The completeness requirement applies to the verifier-side L3-acceptance evaluation path; agent-side pre-L3-creation evaluation is governed by §5.2's short-circuit clause, which requires agents to stop at the first `environment.*` failure as a fail-closed agent-side halt distinct from the verifier's diagnostic-completeness obligation."* Resolves the §5.2/§5.5 register tension flagged in PR #9's RFC 2119 audit P3-1: §5.2 binds agents at pre-L3-creation (short-circuit, fail-closed); §5.5 Block 3 binds verifiers at L3-acceptance (completeness, diagnostic). Both rules stand; the bridge sentence makes the phase distinction explicit so neither register reads as contradicting the other. Venue Option A (§5.5 Block 3 placement). Precision rewrite adopted verbatim per [PR #9 precision flag](https://github.com/agent-intent/verifiable-intent/pull/9#issuecomment-4279319395) (permits→requires, self-gating optimization→fail-closed agent-side halt). Document header stays at `0.5-draft`; v0.5.3 is a patch-level refinement per the convention established in [`7b97827`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/7b978279ff847ef5c0db805a883be373616116b9). No algorithm changes; no security-model changes; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle). |
| 0.5.1-draft | 2026-04-19 | **§4.8 table completeness**: added three rows and three rationale entries closing the coverage asymmetry flagged by LembaGang in [comment 4276249269](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276249269) — the §4.8 preamble at v0.5 stated that each field in the family MUST declare its scope, but the field table covered only 6/9 `environment.wallet_state` constraint fields (missing `attestation_url`, `expected_kid`, `expected_issuer`). Path (1) selected — complete the table rather than narrow the preamble's universal quantifier — per Doug's [comment 4276295574](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276295574) and LembaGang's green-light in [comment 4276315303](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276315303). Three table rows: `attestation_url` (family-wide-trust-root-agnostic, §4.1); `expected_kid` and `expected_issuer` (per-type-trust-root-mechanism-bound, §6.3). Three rationale entries integrated into the §4.8 post-table paragraph in category order (the `attestation_url` entry is a three-sentence block carrying the WG-reviewer pre-emption; `expected_kid` and `expected_issuer` are one-sentence entries semicolon-joined with their market_state sibling notes). The `attestation_url` rationale pre-empts the §4.8-internal question of why the URL is family-wide when `attestation_request_body` (which targets the same URL) is per-type-evaluation-mechanism-bound: the placement lands on the same basis as `max_attestation_age` in §4.6 — identical semantic role across types, with per-type variance localised at neighbouring fields (HTTP verb, request-body shape). `expected_kid` and `expected_issuer` are classified on JOSE-signing-stack specificity: both are JWT header/claim bindings parallel-but-mechanism-specific on `environment.market_state`, which uses RFC 8615 key registry (`oracle_public_key_id`) and derives issuer identity from the attestation payload rather than from a constraint-level JOSE `iss` binding. Document header stays at `0.5-draft` — patch-level refinement, not a new minor version (matches LembaGang's convention on commit [`7b97827`](https://github.com/agent-intent/verifiable-intent/commit/7b978279ff847ef5c0db805a883be373616116b9) where PR #9 shipped v0.5.1-draft with header unchanged). No schema changes; no algorithm changes; no security-model changes; no changes outside §4.8; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle); LembaGang to mirror onto PR #9 as v0.5.2-draft with `attestation_url` (family-wide-trust-root-agnostic), `oracle_public_key_id` (per-type-trust-root-mechanism-bound), and `expected_status` (per-type-evaluation-mechanism-bound — status-enum analog to `required_condition_hashes`) per [comment 4276315303](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276315303). |
| 0.5-draft | 2026-04-19 | **§4.8 Field Scope Declaration**: new family-charter section mirroring [PR #9 v0.5.1-draft](https://github.com/agent-intent/verifiable-intent/pull/9/commits/7b978279ff847ef5c0db805a883be373616116b9) (commit `7b97827`, LembaGang, Headless Oracle) per LembaGang's sequencing in [comment 4276111822](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4276111822) and Doug's third-category proposal in [comment 4275984904](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4275984904). Three scope categories defined verbatim from `7b97827` as family-wide prose: `family-wide-trust-root-agnostic` (identical semantics across every `environment.*` type), `per-type-trust-root-mechanism-bound` (semantics bound to the type's trust-root mechanism — RFC 7517 JWKS here, RFC 8615 key registry on `environment.market_state`), and `per-type-evaluation-mechanism-bound` (semantics bound to the type's evaluation-mechanism output shape or wire-protocol binding). Field table populated for current `environment.wallet_state` fields: `max_attestation_age` (family-wide-trust-root-agnostic, per §4.6); `trusted_jwks` and `stale_cache_fallback_permitted` (per-type-trust-root-mechanism-bound, per §6.3 and §6.8); `subject_wallet`, `required_condition_hashes`, and `attestation_request_body` (per-type-evaluation-mechanism-bound, per §5.5 and §4.1). `subject_wallet` placement argued by swap test: replace ES256+JWKS with an Ed25519 scheme that binds wallets through a different mechanism and `subject_wallet` still does the §5.5 per-member disambiguation job against whatever the new format calls the wallet identifier; the `sub: <wallet>` binding lives in the attestation payload, not in this constraint field. **Rule for future fields**: all new `environment.*` fields MUST declare scope category at introduction; additions beyond these three are working-group revisions. **Relationship to §4.6 and §4.7**: §4.8 formalises at charter level the scope distinction §4.6 (`max_attestation_age` family-wide) and §4.7 (per-type MUST-implement with family-wide agility framework) already imply; §4.6 and §4.7 normative text unchanged. Also retroactively bumps document header from 0.2-draft to 0.5-draft, capturing the v0.3 / v0.3.1 / v0.4 commits' omission of the header update. No algorithm changes; no security-model changes; no §6.* or §7.* changes; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle). |
| 0.4-draft | 2026-04-18 | Coordinated v0.4 release with [PR #9 `environment.market_state`](https://github.com/agent-intent/verifiable-intent/pull/9) as a single-commit-on-both-specs bundle per LembaGang's (b) proposal ([accepted](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4274334595) by Doug, [locked](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4274435668) by LembaGang). Bundles six items. **Audit-parity port from PR #9 v0.3.2** (commit [`57fd7b6`](https://github.com/agent-intent/verifiable-intent/commit/57fd7b6), LembaGang, Headless Oracle). (1) **`max_attestation_age` strictness** — removed absent-case default of 300 seconds from the §4 schema row, the §4 Field Constraints bullet, the §4.2 pseudocode (Step 1), and both JS (§7.6) and Python (§7.7) reference implementations. Missing `max_attestation_age` is now uniformly malformed; verifiers MUST reject per §4.2 Step 1. Closes the v0.2 REQUIRED-elevation-with-retained-default contradiction. (2) **§6.5 Constraint Stripping** — added normative sentences requiring verifiers to reject mandates whose Layer 2 signature does not validate over the full constraint list, and prohibiting acceptance of subset-signed mandates. **Three consumer-policy additions** (Doug's [Apr 18 17:42 proposal](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4274241447), LembaGang-approved). (3) new `stale_cache_fallback_permitted` **OPTIONAL** boolean field (default `false`) — new §4 schema row + Field Constraints bullet (with boolean-type hygiene clause) + §4.2 Step 1 type-check; companion paragraph in §6.8 replacing the stale-cache sentences in the "Fail-closed on fetch failure" paragraph; payment-execution mandates MUST NOT set `true`. Shape follows the v0.3.2 rule-narrowing: REQUIRED remains the right pattern where no nontrivial default is safe across deployment classes (`max_attestation_age`); OPTIONAL-with-default is the right pattern where a single default is correct for almost all deployments (`stale_cache_fallback_permitted`). Parallel-construction Field Constraints bullet matches the `max_attestation_age` pattern. (4) **§6.8 grace-window discoverability** — issuers SHOULD publish rotation-start and grace-window-end timestamps through an auditable channel (out-of-band OR in-band `rotation_announcement` metadata); SHOULD is on discoverability, not form. (5) **§6.3 JWKS URL migration** — added paragraph documenting `trusted_jwks` URL change as a new-mandate event by design; trust-root rigidity is a deliberate cost/benefit (cannot be silently relocated, at the cost of non-free URL migration). (6) **SHALL→MUST normalization: not needed** — post-audit verification on both specs shows all SHALL references sit in the RFC 2119 Notational Conventions boilerplate; zero substantive usage elsewhere (LembaGang's P3 finding withdrawn on PR #9, symmetric on #22). No architectural changes; no family-wide changes; no InsumerAPI-side code changes required. Co-drafted with LembaGang (Headless Oracle) over PRs #9 and #22; §6.8 lift onto PR #9 v0.4 per agreed sequencing. |
| 0.3.1-draft | 2026-04-18 | Mirrors PR #9 v0.3 §5.5 Family Composition (commit [`7a8987c`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/7a8987cc34752d6f7f97bb645d67cfaf129e1cda), LembaGang, Headless Oracle) into `environment.wallet_state`. Two refinements surfaced in [PR #22 discussion](https://github.com/agent-intent/verifiable-intent/pull/22) folded into §5.5. **Gap 1 (completeness rule)**: verifiers MUST evaluate every `environment.*` constraint in the mandate to completion before refusing Layer 3; short-circuit evaluation is non-conforming; transactional-constraint evaluation after a confirmed `environment.*` failure remains implementation-defined. Composes with §5.2 ordering. **Gap 2 (per-member disambiguation)**: every violation entry carries both an array-index machine identifier and a per-type human-readable identifier (`subject_wallet` for `environment.wallet_state`, MIC for `environment.market_state`); driving case is multiple same-type constraints in a single mandate. **Rationale** presents semantic and architectural arguments as co-equal — conjunction as a family membership criterion, not a per-type design decision. No changes elsewhere in the spec; §4.1, §4.5, §4.7, §5.2, §6.*, §7.* untouched; no InsumerAPI-side code changes required. |
| 0.3-draft | 2026-04-17 | Addresses the first of the four held-back follow-ups from [LembaGang comment 4260672256](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4260672256): **composition semantics on mixed pass/fail**. New §5.5 Family Composition — conjunction semantics, named answer for the mixed pass/fail case (one `environment.*` passes, another fails → family gate fails), L3 execution gate as explicit normative rule, per-member diagnostic output requirement. §5.2 and all other sections unchanged. Drafted as standalone block adoptable verbatim in `environment.market_state` §5.5 with no changes — same pattern as §4.7. |
| 0.2-draft | 2026-04-16 | Revision addressing LembaGang review ([comment 4259989585](https://github.com/agent-intent/verifiable-intent/pull/22#issuecomment-4259989585)). **Provider neutrality**: §4.1 restructured as abstract attestation interface — 7 REQUIRED JWT claims (`iss`, `sub`, `jti`, `iat`, `exp`, `pass`, `conditionHash`) define the normative contract; `results`, `blockNumber`, `blockTimestamp` moved to OPTIONAL; condition hash canonicalization moved to §7.2 as issuer-specific detail. A second conformant implementation needs only the 7 core claims and a JWKS. **Attestation freshness**: `max_age_seconds` renamed to `max_attestation_age`, elevated to REQUIRED with normative default of 300, new §4.6 documents TOCTOU rationale and family-wide semantics. **Algorithm agility**: new §4.7 resolves former Q1 — family-level agility per RFC 8725 §3.1, per-type MUST-implement algorithm (ES256 for wallet_state, Ed25519 for market_state), SHOULD/MAY extension sets, drafted as standalone block for adoption in PR #9. Former Q1 (algorithm negotiation) removed from §8 and resolved in §4.7. Former Q6 (family-wide subject binding) renumbered to Q5. InsumerAPI-specific content (§6.1 JWKS URLs, §6.6 canonicalization detail) consolidated in §7. §7 restructured with subsections: §7.1 overview, §7.2 canonicalization, §7.3 implementation-specific claims, §7.4 agent-native provisioning, §7.5 live JWKS, §7.6–7.7 reference verifiers. |
| 0.1-draft | 2026-04-15 | Initial draft. `environment.wallet_state` constraint type. ES256 JWT + JWKS attestation verification. Fail-closed algorithm. InsumerAPI as reference implementation. Proposed for registration in VI constraint type registry. Answers companion §8 Q2 (trusted_issuers) via JWKS-host allowlisting. |

---

## Appendix A: Attestation Test Vectors

These test vectors allow constraint verifier implementors to validate their
attestation verification logic against a known-good signed receipt from the
reference implementation (InsumerAPI, §7).

**Request** (POST `https://api.insumermodel.com/v1/attest`):

```json
{
  "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "conditions": [
    {
      "type": "token_balance",
      "chainId": 1,
      "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "decimals": 6,
      "threshold": 1
    }
  ],
  "format": "jwt"
}
```

**Response JWT header** (base64url-decoded):

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "insumer-attest-v1"
}
```

**Response JWT payload** (base64url-decoded, 2026-04-15 live call):

```json
{
  "pass": true,
  "conditionHash": [
    "0xc938b71ac78df5843d6823dd78ee0a5b64dd56fa850984e954dd070285169444"
  ],
  "blockNumber": "0x17bbfc5",
  "blockTimestamp": "2026-04-15T19:14:23.000Z",
  "results": [ /* per-condition detail */ ],
  "iss": "https://api.insumermodel.com",
  "sub": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "jti": "ATST-12B74029669F14F9",
  "iat": 1776280474,
  "exp": 1776282274
}
```

**Public key** (P-256, from `https://api.insumermodel.com/.well-known/jwks.json`):

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
  "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
  "use": "sig",
  "alg": "ES256",
  "kid": "insumer-attest-v1"
}
```

Fetch a fresh JWT at `POST https://api.insumermodel.com/v1/attest` and verify
it against the JWKS above using any standard JOSE library. Human developers
can get a free-tier key in ~10 seconds at
[`https://insumermodel.com/developers/`](https://insumermodel.com/developers/);
autonomous agents can self-provision via `POST /v1/keys/buy` using an
on-chain USDC or BTC payment (see §7.4). A working end-to-end verifier is
published at
[`github.com/douglasborthwick-crypto/insumer-examples`](https://github.com/douglasborthwick-crypto/insumer-examples).

---

## Appendix B: Failure Mode Quick Reference

| Failure | Step | Violation Message Pattern | Agent Response |
|---------|------|--------------------------|----------------|
| Non-HTTPS `attestation_url` or `trusted_jwks` | 1 | `"Non-HTTPS URL in constraint: fail-closed"` | Do not proceed |
| Empty `required_condition_hashes` | 1 | `"required_condition_hashes must be non-empty: fail-closed"` | Do not proceed |
| Network timeout / DNS failure | 2 | `"Attestation fetch failed: ... — fail-closed"` | Do not proceed |
| HTTP 4xx / 5xx from issuer | 2 | `"Attestation fetch failed: HTTP {N} — fail-closed"` | Do not proceed |
| Response missing `jwt` field | 2 | `"Attestation response missing jwt field: fail-closed"` | Do not proceed |
| `kid` mismatch | 3 | `"JWT kid does not match expected_kid: fail-closed"` | Do not proceed |
| JWKS unreachable | 4 | `"JWKS unreachable: fail-closed"` | Do not proceed |
| `kid` not found in JWKS | 4 | `"Signing key not found in JWKS: fail-closed"` | Do not proceed |
| JWT signature invalid | 5 | `"JWT signature verification failed: fail-closed"` | Do not proceed; alert operator |
| `iss` mismatch | 6 | `"JWT iss does not match expected_issuer: fail-closed"` | Do not proceed |
| `sub` mismatch | 6 | `"JWT sub does not match subject_wallet: fail-closed"` | Do not proceed |
| `exp` in past | 7 | `"Attestation has expired (exp in past): fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| `iat` age > `max_attestation_age` | 8 | `"Attestation age Ns exceeds max_attestation_age M: fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| `pass` is `false` | 9 | `"Attestation pass is not true: constraint not satisfied"` | Do not proceed; wallet state has changed |
| Required condition hash missing | 10 | `"Required condition hash {hash} not in attestation: constraint not satisfied"` | Do not proceed; log reason |

---

## Appendix C: Register Discipline

**Status**: Charter proposal (skeleton). Shape only; content to converge through working-group review.

### C.1 Purpose

The `environment.*` constraint family has converged on a consistent discipline for the use of normative register (RFC 2119 keywords in ALL CAPITALS) versus descriptive register (lowercase synonyms, prose explanation, rationale paragraphs). This discipline has been applied across both `environment.market_state` (PR #9) and `environment.wallet_state` (this specification) in multiple patch-level revisions: §2.3 and §2.5 register polish in v0.5.4 on #9, and §6.9 reorg-scope and truncation-asymmetry clarifications in v0.6.1 on #22 are the most recent concrete instances. This appendix formalises the discipline so that it is visible to future contributors, reviewers, and implementers as an explicit charter property rather than an ad-hoc editorial practice.

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

> **Note on family coordination**: Mirrors `environment.market_state` Appendix C at commit [`01490df`](https://github.com/agent-intent/verifiable-intent/pull/9/commits/01490df8da81fc9482c5d18794380d366961ee80); appendix letter alignment confirmed C-to-C, no offset. The worked-example instances at §C.3.2, §C.3.3, and §C.3.4 cite both specs; substantive body localisation is at C.1 only (PR-number inversion preserves cross-reference integrity), while this coordination Note is per-spec by construction. Same pattern as §4.6, §4.7, §5.5, §6.8, §4.8 — one family-wide charter principle, one answer, two specs.

## Appendix D: Implementation Status

**Status**: Informative, per [RFC 6982](https://datatracker.ietf.org/doc/html/rfc6982).

This appendix records the running-code implementations of `environment.wallet_state` and the sibling `environment.*` family known to the editors at the time of writing. Per RFC 6982 §2, this section is intended to be removed by the RFC Editor before any final standards-track publication; the GitHub history of this Internet-Draft retains it permanently as evidence of priority and as a pointer to deployed reference implementations during the working-group review window.

### D.1 InsumerAPI (`environment.wallet_state`)

| Property | Value |
|----------|-------|
| Organisation | InsumerAPI (insumermodel.com) |
| License | Proprietary. Copyright 2026 Douglas Borthwick. |
| Attestation endpoint | `POST https://api.insumermodel.com/v1/attest` (requires `X-API-Key`) |
| JWKS endpoint | `GET https://api.insumermodel.com/.well-known/jwks.json` (RFC 7517) |
| Signing algorithm | ES256 / P-256 (RFC 7518), per §4.7 MUST-implement |
| Stable signing key id | `insumer-attest-v1` |
| Receipt format | ES256 JWT (RFC 7515) carrying the seven REQUIRED claims at §4.1 (`iss`, `sub`, `jti`, `iat`, `exp`, `pass`, `conditionHash`) plus the implementation-specific OPTIONAL claims at §7.3 (`results`, `blockNumber`, `blockTimestamp`) |
| Condition hash canonicalization | `"0x" + sha256(canonical_json(evaluatedCondition))` with object keys sorted lexicographically, per §7.2 |
| JWT TTL | 1800 seconds (`exp = iat + 1800`) |
| Coverage | 33 chains (30 EVM chains + Solana + XRPL + Bitcoin); full enumeration at [`https://api.insumermodel.com/openapi.yaml`](https://api.insumermodel.com/openapi.yaml) |
| Agent-native key provisioning | `POST /v1/keys/buy` — no auth, wallet is identity, USDC/USDT/BTC on-chain payment, per §7.4 |
| Reference verifiers | [InsumerAPI examples](https://github.com/douglasborthwick-crypto/insumer-examples) (end-to-end verification scripts); minimal constraint verifier (JavaScript, `jose`) at §7.6; fail-closed integration pattern (Python) at §7.7 |
| OpenAPI spec | `GET https://api.insumermodel.com/openapi.yaml` |

**Conformance to this specification.** The InsumerAPI deployment implements the §4.1 attestation interface (the seven REQUIRED claims; the §7.3 implementation-specific OPTIONAL claims layer on top); the §4.2 verification algorithm Steps 1 through 11; the §4.6 family-wide `max_attestation_age` semantics (verified at the constraint level, not via any deployment-side TTL); §4.7 ES256 MUST-implement; §4.8 field scope declarations across all current `environment.wallet_state` fields; §5.5 Family Composition conjunction and per-member diagnostic completeness; §6.5 Constraint Stripping rejection per the §6.5 normative MUSTs; §6.8 RFC 7517 JWKS caching with `key_id`-mismatch cache invalidation and the §4 `stale_cache_fallback_permitted` honor pattern; and §6.9 Cross-Chain Temporal Consistency including verifier-side `blockTimestamp` truncation and `finality_depth` measurement-basis discipline.

Refer to **§7. Reference Implementation: InsumerAPI** for the full reference-implementation prose: §7.1 overview, §7.2 condition hash canonicalization, §7.3 implementation-specific response claims, §7.4 agent-native key provisioning, §7.5 live JWKS, §7.6 minimal constraint verifier (JavaScript, `jose`), §7.7 fail-closed integration pattern (Python).

### D.2 Headless Oracle (`environment.market_state`, sibling specification)

| Property | Value |
|----------|-------|
| Organisation | Headless Oracle (headlessoracle.com) |
| Sibling specification | [PR #9](https://github.com/agent-intent/verifiable-intent/pull/9) (`environment.market_state`) |
| Compliance endpoint | `GET https://headlessoracle.com/v5/compliance` |
| Public key registry | `GET https://headlessoracle.com/.well-known/oracle-keys.json` (RFC 8615) |
| Signing algorithm | Ed25519 (RFC 8032), per `environment.market_state` §4.7 MUST-implement |
| Receipt format | Signed Market-State Attestation (SMA) — Ed25519 signature over canonical JSON |
| Coverage | 28 global exchanges across equities, derivatives, and digital-asset venues, identified by ISO 10383 MIC codes where registered and by convention MICs for crypto-native venues; per-venue `mic_type` categorisation at `GET /v5/exchanges` |
| Reference verifier | [`headlessoracle/demo-agent`](https://github.com/headlessoracle/demo-agent) (~150 lines, MIT) |
| Operational since | 2026-02-18 |

Headless Oracle realises the sibling `environment.market_state` constraint to `environment.wallet_state`. It is listed here for `environment.*` family completeness; the canonical Implementation Status appendix for `environment.market_state` belongs in that specification ([PR #9](https://github.com/agent-intent/verifiable-intent/pull/9)) and is the editor's call on Michael Msebenzi / LembaGang's side.

### D.3 Disclaimer

This appendix is not normative. Listing in Appendix D does not imply endorsement of the listed implementation by the editors, by the Verifiable Intent project, or by any inheritor of this draft. Each implementation is independently operated and independently signed. Verifiers MUST independently verify attestations from any implementation per §4.2 — implementation listing in Appendix D does not substitute for verification.

---

*End of document. Comments and revisions should be submitted as issues or
pull requests to the Verifiable Intent specification repository
(github.com/agent-intent/verifiable-intent). The InsumerAPI reference issuer
is documented at `https://api.insumermodel.com/openapi.yaml` and
`https://insumermodel.com/developers/api-reference/`.*
