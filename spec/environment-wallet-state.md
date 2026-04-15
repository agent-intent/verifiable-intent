# Verifiable Intent — Wallet State Attestation Constraint Proposal

**Type identifier**: `environment.wallet_state`
**Version**: 0.1-draft
**Status**: Draft / Proposed for Registration
**Date**: 2026-04-15
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
- The attestation verification algorithm agents and verifiers MUST implement
- Fail-closed failure handling requirements
- Security considerations specific to on-chain state dependencies
- A reference implementation (InsumerAPI)
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
a signed on-chain state claim conforming to the InsumerAPI wallet-attestation
format or any compatible JWT+JWKS format that satisfies the verification
requirements in §4.

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
2. Verify the ES256 JWT signature against the issuer's published JWKS
3. Confirm the JWT's `iss`, `sub`, and `kid` claims match the constraint
4. Confirm the attestation is not expired (`exp`) and is within the constraint's
   `max_age_seconds` window (derived from `iat`)
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

- **Checkout mandate** (`vct: "mandate.checkout.open"`): Prevents checkout
  initiation when the source wallet no longer satisfies the entry condition
  (e.g., the wallet no longer holds the minimum balance required by the
  mandate's pricing floor).
- **Payment mandate** (`vct: "mandate.payment.open"`): Prevents payment
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
| `environment.wallet_state` | This document | 0.1-draft | property (full constraint) |

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

- Checkout mandate (`mandate.checkout.open`) `constraints` array
- Payment mandate (`mandate.payment.open`) `constraints` array

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
| `max_age_seconds` | integer | No | Maximum age in seconds of the attestation, measured from JWT `iat` to the time of verification. Default: `300`. MUST be a positive integer. Verifiers MUST reject attestations where `(now − iat) > max_age_seconds`, even if `exp` has not yet passed. |
| `attestation_request_body` | object | No | Optional POST body the verifier sends to `attestation_url` when fetching a fresh attestation. Verifiers MUST NOT trust this body to alter the expected claims — all binding is enforced by `expected_kid`, `expected_issuer`, `subject_wallet`, and `required_condition_hashes`. |

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
- `max_age_seconds` defaults to `300` when absent. Values less than `1` MUST
  be rejected as malformed. Values exceeding the issuer's JWT TTL (typically
  1800 seconds for InsumerAPI) SHOULD be rejected by implementations that know
  the issuer's TTL out-of-band.

### 4.1 Attestation JWT Format

The JWT returned in the `jwt` field of the attestation endpoint response MUST
have the following claims. Additional claims MAY be present; verifiers MUST
NOT strip claims before signature verification.

**JWT header**:

| Field | Type | Description |
|-------|------|-------------|
| `alg` | string | Signing algorithm identifier. MUST be a named JWS algorithm (e.g., `ES256`, `EdDSA`). See §8 Q2 for algorithm negotiation. |
| `typ` | string | MUST be `"JWT"`. |
| `kid` | string | Key identifier. MUST match `expected_kid` in the constraint. |

**JWT payload**:

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string (URL) | Issuer identifier. MUST match `expected_issuer` in the constraint. |
| `sub` | string | Subject wallet address. MUST match `subject_wallet` in the constraint. |
| `jti` | string | Unique attestation identifier (for deduplication and audit logging). |
| `iat` | integer (unix seconds) | Time the attestation was signed. |
| `exp` | integer (unix seconds) | Time after which the attestation MUST NOT be acted upon. |
| `pass` | boolean | Aggregate condition evaluation result. MUST be `true` for the constraint to be satisfied. |
| `conditionHash` | array of string | One hash per evaluated condition, in evaluation order. Every value in `required_condition_hashes` MUST appear in this array. |
| `results` | array of object | Per-condition evaluation detail. Verifiers MAY log this for audit but MUST NOT use it as a substitute for the `conditionHash` check. |
| `blockNumber` | string (hex, optional) | Block number at which the first condition was evaluated. Recorded for audit trail. |
| `blockTimestamp` | ISO 8601 (optional) | Block timestamp at which the first condition was evaluated. Recorded for audit trail. |

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
    let max_age = C.max_age_seconds ?? 300
    if max_age < 1:
        return violation("max_age_seconds must be >= 1")

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

    # Step 8 — Verify attestation age against max_age_seconds
    let age_seconds = now_unix() - payload.iat
    if age_seconds > max_age:
        return violation("Attestation age exceeds max_age_seconds: fail-closed")

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
  "max_age_seconds": 300,
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
  "vct": "mandate.checkout.open",
  "constraints": [
    {
      "type": "environment.market_state",
      "attestation_url": "https://headlessoracle.com/v5/demo?mic=XNYS",
      "oracle_public_key_id": "key_2026_v1",
      "expected_status": "OPEN",
      "max_age_seconds": 60
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
      "max_age_seconds": 300,
      "attestation_request_body": {
        "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "conditions": [
          { "type": "token_balance", "chainId": 1, "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "decimals": 6, "threshold": 1 }
        ],
        "format": "jwt"
      }
    },
    {
      "type": "mandate.checkout.allowed_merchant",
      "allowed_merchants": [
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
ordering dependency is documented.

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
attestations. InsumerAPI publishes its JWKS at:
- `https://api.insumermodel.com/.well-known/jwks.json`
- Documented in the `.well-known` block of `https://api.insumermodel.com/llms.txt`

### 6.2 Attestation Replay

A valid signed attestation is replayable within its `exp` window. The
`max_age_seconds` field narrows this window below `exp` when needed. The
`jti` claim enables consumers that require per-attestation deduplication to
detect and reject replayed attestations within the TTL window.

For payment execution contexts, verifiers SHOULD maintain a short-lived
`jti` deduplication cache (TTL: `max_age_seconds + 30s`) to prevent a single
attestation from being used to authorise multiple L3 creations.

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
  stack, no new verification library. The reference implementation's JWT is
  directly consumable by any existing VI JWS verifier.
- **Subject binding via native `sub` claim.** The JWT's `sub` claim is the
  wallet address, so "this attestation is about this payment source" is a
  native JWT claim check rather than a new constraint field. This is the
  shared subject-binding pattern flagged in LembaGang's review of the
  proposal.

As with `environment.market_state`, verifiers MUST verify the Layer 2
credential signature chain before trusting any field in any constraint object.

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
signature.

### 6.6 Condition Hash Collision Assumptions

The constraint binds the attestation to a specific boolean condition via the
`conditionHash` array. The security of this binding depends on the issuer's
condition-hashing function being collision-resistant over the space of
conditions the issuer accepts. The reference implementation (InsumerAPI)
computes the condition hash as `"0x" + sha256(canonical_json(evaluated_condition))`,
where `canonical_json` is `JSON.stringify` with object keys sorted
lexicographically. Verifiers that need to precompute a condition hash to
populate `required_condition_hashes` MUST use the same canonicalisation the
issuer uses; the reference issuer's canonicalisation is documented at
`https://api.insumermodel.com/openapi.yaml`.

Implementations MUST NOT use a condition hash as a standalone claim (the
attestation JWT as a whole is what is signed); the hash is a binding field,
not a bearer credential.

### 6.7 Time Synchronisation

The `iat` age check (Step 8 of §4.2) requires that the verifier's clock is
reasonably synchronised with the issuer's clock. A clock skew exceeding
`max_age_seconds` would cause all attestations to be rejected. Implementations
SHOULD use NTP-synchronised clocks and SHOULD log clock-skew-related failures
distinctly to aid diagnosis.

---

## 7. Reference Implementation

### 7.1 InsumerAPI

[InsumerAPI](https://api.insumermodel.com) is the reference implementation
of the wallet-state attestation issuer consumed by this constraint type. It
evaluates boolean conditions against live on-chain state across 33 chains and
returns ES256-signed JWTs that are directly verifiable using the JWT + JWKS
pattern specified in §4.

| Property | Value |
|----------|-------|
| API base URL | `https://api.insumermodel.com` |
| Attestation endpoint | `POST /v1/attest` (requires `X-API-Key`) |
| Trust profile endpoint | `POST /v1/trust` (requires `X-API-Key`) |
| Agent-native key purchase | `POST /v1/keys/buy` (no auth; wallet is identity; USDC or BTC) |
| JWKS (RFC 7517) | `GET /.well-known/jwks.json` |
| OpenAPI spec | `GET /openapi.yaml` |
| Signing algorithm | ES256 (RFC 7518) via JOSE (`jose` npm package) |
| JWT TTL | 1800 seconds (`exp = iat + 1800`) |
| Condition hash algorithm | `"0x" + sha256(canonical_json(evaluated_condition))`, sorted keys |
| Supported chains | 33 — all major EVM chains, Solana, XRPL, Bitcoin, and additional chains documented in `/openapi.yaml` |
| Key curve | P-256 (`alg: ES256`, `kty: EC`, `crv: P-256`, `kid: insumer-attest-v1`) |

**Agent-native provisioning.** The reference issuer supports fully
autonomous key provisioning at `POST /v1/keys/buy`: no email, no signup form,
no human in the loop. An agent submits an `appName`, a `txHash`, and a
`chainId`; the endpoint verifies the USDC (or BTC) transfer on-chain,
dedupes against the sender wallet, and returns a new API key. This is
structurally aligned with the VI execution model — an agent that has the
authority to spend USDC on behalf of its principal already has everything
it needs to provision the key required to fulfill `environment.wallet_state`
constraints. No out-of-band credential issuance step is required.

**Live JWKS** (verified 2026-04-15):

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

### 7.2 Minimal Constraint Verifier (JavaScript, `jose`)

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
    max_age_seconds = 300,
    attestation_request_body = {},
  } = constraint;

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
  if (ageSeconds > max_age_seconds) {
    throw new Error(`Attestation age ${ageSeconds}s exceeds max_age_seconds ${max_age_seconds}: fail-closed`);
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

### 7.3 Fail-Closed Integration Pattern (Python)

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
    max_age_seconds = constraint.get("max_age_seconds", 300)
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
    if age > max_age_seconds:
        raise ValueError(f"Attestation age {age}s exceeds max_age_seconds {max_age_seconds}: fail-closed")

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

1. **Algorithm negotiation for `environment.*` constraints.** The companion
   `environment.market_state` draft uses Ed25519 with a custom alphabetically-sorted
   canonical JSON payload. This draft uses ES256 with standard JWS base64url
   encoding — the same stack VI already requires for SD-JWT. A minimum-friction
   answer would be: each `environment.*` constraint type declares its own
   signing algorithm, verifiers negotiate a supported set, and the
   constraint-type-level `alg` selection is the point of record. A maximum-
   unification answer would be: all `environment.*` constraints MUST emit JWS
   so verifiers need exactly one verification path. Working group input
   welcome; this draft is intentionally agnostic about the broader family
   decision and specifies ES256 only for its own type.

2. **Batch attestation.** Should `attestation_url` be permitted to return an
   attestation covering multiple subject wallets or multiple condition sets
   in a single JWT, with the constraint identifying a subset via claim path?
   This would reduce round-trips for mandates that gate on multiple payment
   sources. Proposal: defer to a `environment.wallet_state_batch` type rather
   than overloading this one.

3. **On-chain verification.** For fully on-chain execution contexts, the
   JWT verification step could be performed by a smart contract using
   P-256 precompile ([EIP-7212](https://eips.ethereum.org/EIPS/eip-7212)) or
   a verifier contract. Specification of on-chain `attestation_url` semantics
   (including IPFS-based attestation blobs and on-chain oracle bridges) is
   deferred to a companion document.

4. **Condition hash extensibility.** This draft binds the constraint to one
   or more literal condition hashes. A future extension could support a
   constraint-time predicate language (e.g., "the attestation MUST contain a
   hash matching this template") to reduce the need for pre-computed hashes
   in mandate issuance. Deferred to v0.2.

5. **Multi-issuer composition.** Can a single `environment.wallet_state`
   constraint require attestations from two independent issuers
   (e.g., InsumerAPI and a second wallet-state issuer) for defence-in-depth?
   Current answer: compose two separate `environment.wallet_state` constraints
   in the mandate. A shorthand `required_issuers` array could be added in
   v0.2 if there is demand.

6. **Family-wide `subject` binding.** LembaGang's review of this proposal
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
| 0.1-draft | 2026-04-15 | Initial draft. `environment.wallet_state` constraint type. ES256 JWT + JWKS attestation verification. Fail-closed algorithm. InsumerAPI as reference implementation. Proposed for registration in VI constraint type registry. Answers companion §8 Q2 (trusted_issuers) via JWKS-host allowlisting. |

---

## Appendix A: Attestation Test Vectors

These test vectors allow constraint verifier implementors to validate their
attestation verification logic against a known-good signed receipt from
InsumerAPI.

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
on-chain USDC or BTC payment (see §7.1). A working end-to-end verifier is
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
| `iat` age > `max_age_seconds` | 8 | `"Attestation age Ns exceeds max_age_seconds M: fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| `pass` is `false` | 9 | `"Attestation pass is not true: constraint not satisfied"` | Do not proceed; wallet state has changed |
| Required condition hash missing | 10 | `"Required condition hash {hash} not in attestation: constraint not satisfied"` | Do not proceed; log reason |

---

*End of document. Comments and revisions should be submitted as issues or
pull requests to the Verifiable Intent specification repository
(github.com/agent-intent/verifiable-intent). The InsumerAPI reference issuer
is documented at `https://api.insumermodel.com/openapi.yaml` and
`https://insumermodel.com/developers/api-reference/`.*
