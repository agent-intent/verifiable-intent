# Verifiable Intent — External State Attestation Constraint Proposal

**Type identifier**: `environment.market_state`
**Version**: 0.1-draft
**Status**: Draft / Proposed for Registration
**Date**: 2026-03-17
**Author**: Headless Oracle Project (headlessoracle.com)
**License**: Apache 2.0

## Abstract

This document proposes a new Verifiable Intent (VI) constraint type —
`environment.market_state` — for registration in the VI constraint type
registry defined in [constraints.md §6.2](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md#62-constraint-type-registry).

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
- Security considerations specific to external state dependencies
- A reference implementation (Headless Oracle)

### Companion Documents

| Document | Description |
|----------|-------------|
| [constraints.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/constraints.md) | VI normative constraint type definitions and validation rules |
| [credential-format.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/credential-format.md) | Normative credential format, claim tables, and serialization |
| [security-model.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/security-model.md) | Threat model and security analysis |
| [design-rationale.md](https://github.com/agent-intent/verifiable-intent/blob/main/spec/design-rationale.md) | Why SD-JWT, algorithm choices |
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

### 2.2 Where This Constraint Appears

`environment.market_state` MAY appear in **both** VI Autonomous mode mandate
types:

- **Checkout mandate** (`vct: "mandate.checkout.open"`): Prevents checkout
  initiation during market closure or halt. Typical `expected_status`: `"OPEN"`.
- **Payment mandate** (`vct: "mandate.payment.open"`): Prevents payment
  authorisation outside valid trading sessions. Typical `expected_status`: `"OPEN"`.

When present in both mandates of a single delegated action, both constraints
MUST be satisfied independently. A constraint in the checkout mandate does not
satisfy a constraint in the payment mandate.

**Namespace**: `environment.*`. This namespace is proposed for registration to
cover constraints that gate agent actions on verified external world state.
Future types in this namespace might include `environment.regulatory_status`,
`environment.counterparty_credit`, or `environment.infrastructure_health`.

### 2.3 Lifecycle

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

### 2.4 Fulfillment Model

Unlike registered VI constraint types that compare L2 constraints against L3
fulfillment values (derived from L3 mandate fields), `environment.market_state`
validation requires a live external fetch. The constraint is satisfied or
violated at the moment of verification based on a freshly obtained attestation,
not by comparing L2 to L3 fields.

This is an intentional design choice. Market state is ephemeral — an
attestation obtained at agent time may not reflect market state at verifier
time. Verifiers MUST perform independent attestation verification, not rely on
the agent's L3 claims about market state.

**Layer 3 evidence field (RECOMMENDED)**: Agents SHOULD include a
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
| `environment.market_state` | This document | 0.1-draft | property (full constraint) |

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

- Checkout mandate (`mandate.checkout.open`) `constraints` array
- Payment mandate (`mandate.payment.open`) `constraints` array

### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"environment.market_state"` |
| `attestation_url` | string (HTTPS URL) | Yes | Endpoint to fetch the signed state attestation from. MUST be an HTTPS URL. The response MUST be a JSON attestation object conforming to §4.1. |
| `oracle_public_key_id` | string | Yes | The `key_id` value identifying the signing key in the oracle's key registry. The verifier MUST match this value against the `key_id` field in the fetched attestation and retrieve the corresponding public key from the oracle's `/.well-known/oracle-keys.json` endpoint. |
| `expected_status` | string | Yes | The attested status value the attestation MUST carry for this constraint to be satisfied. For market state: typically `"OPEN"`. Other values: `"CLOSED"` (for settlement-window checks). MUST NOT be `"UNKNOWN"` or `"HALTED"` — constraints requiring a halted or unknown market state are malformed and MUST be rejected. |
| `max_age_seconds` | integer | No | Maximum age in seconds of the attestation, measured from `issued_at` to the time of verification. Default: `60`. MUST be a positive integer. Verifiers MUST reject attestations where `(now − issued_at) > max_age_seconds`, even if `expires_at` has not yet passed. |

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
- `max_age_seconds` defaults to `60` when absent. Values less than `1` MUST
  be rejected as malformed.

### 4.1 Attestation Object Format

The object returned by `attestation_url` MUST include the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | The attested market state: `OPEN`, `CLOSED`, `HALTED`, or `UNKNOWN`. |
| `issued_at` | ISO 8601 | Timestamp when the attestation was signed by the oracle. |
| `expires_at` | ISO 8601 | Timestamp after which the attestation MUST NOT be acted upon. |
| `key_id` | string | Identifier for the signing key used. MUST match `oracle_public_key_id` in the constraint. |
| `issuer` | string (FQDN) | Oracle operator identity. Agents resolve `{issuer}/.well-known/oracle-keys.json` to fetch the signing public key. |
| `receipt_id` | string (UUID v4) | Unique attestation identifier for deduplication and audit logging. |
| `signature` | string (hex) | Ed25519 signature over the canonical payload (all fields except `signature`, sorted alphabetically, serialized as compact JSON, encoded as UTF-8). |

Additional fields (e.g., `source`, `schema_version`, `receipt_mode`, `mic`) MAY
be present. They are included in signature verification if present in the
canonical payload. Verifiers MUST NOT strip fields before verification.

**Key discovery**: Verifiers MUST resolve the public key by fetching
`{attestation.issuer}/.well-known/oracle-keys.json` and locating the entry
where `id == attestation.key_id`. This follows RFC 8615 and the SMA Protocol
key discovery specification.

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
    let max_age = C.max_age_seconds ?? 60
    if max_age < 1:
        return violation("max_age_seconds must be >= 1")

    # Step 2 — Fetch attestation (timeout: 4 seconds)
    let response = http_get(C.attestation_url, timeout=4s)
    if request fails (timeout, DNS, connection error, non-2xx response):
        return violation("Attestation fetch failed: fail-closed")
    let A = parse_json(response.body)
    if parse fails:
        return violation("Attestation response is not valid JSON: fail-closed")

    # Step 3 — Verify key identity
    if A.key_id != C.oracle_public_key_id:
        return violation("Attestation key_id does not match oracle_public_key_id")

    # Step 4 — Fetch oracle public key
    let key_registry_url = "https://" + A.issuer + "/.well-known/oracle-keys.json"
    let key_registry = http_get(key_registry_url, timeout=4s)
    if request fails:
        return violation("Oracle key registry unreachable: fail-closed")
    let keys = parse_json(key_registry).keys
    let key_entry = find(keys, k => k.id == A.key_id)
    if key_entry is null:
        return violation("Signing key not found in oracle key registry: fail-closed")
    if key_entry.valid_until is not null and key_entry.valid_until < now:
        return violation("Oracle signing key has expired: fail-closed")

    # Step 5 — Verify Ed25519 signature
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

    # Step 7 — Verify attestation age against max_age_seconds
    let age_seconds = (now - parse_iso8601(A.issued_at)).total_seconds()
    if age_seconds > max_age:
        return violation("Attestation age exceeds max_age_seconds: fail-closed")

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
(per §2.4 RECOMMENDED field) is expired at time `T`. The verifier MUST apply
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
  "max_age_seconds": 60
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
  "max_age_seconds": 30
}
```

> **Note on `/v5/demo` vs `/v5/status`**: `/v5/demo` is the public unauthenticated
> endpoint returning `receipt_mode: "demo"`. Sufficient for development and testing.
> `/v5/status` requires an `X-Oracle-Key` header and returns `receipt_mode: "live"`.
> Production mandates SHOULD use `/v5/status` (authenticated) and SHOULD set
> `max_age_seconds` ≤ 60 to match the oracle's 60-second receipt TTL.

Multi-exchange example — both NYSE and LSE must be OPEN (two constraints, both must satisfy):

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
      "type": "environment.market_state",
      "attestation_url": "https://headlessoracle.com/v5/demo?mic=XLON",
      "oracle_public_key_id": "key_2026_v1",
      "expected_status": "OPEN",
      "max_age_seconds": 60
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

For batch attestation (multiple exchanges in a single request), use the oracle's
`/v5/batch` endpoint. In this case, `attestation_url` points to the batch endpoint
and `expected_status` applies to the exchange identified in the response array.
Batch handling is outside this specification's scope and deferred to a companion
document.

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
        ...
    else if ctype is another registered type:
        ...
```

### 5.2 Execution Order

`environment.market_state` constraints MUST be evaluated **before** all other
constraint types in the same mandate. If a market state constraint fails, the
agent MUST NOT evaluate remaining constraints and MUST NOT proceed to L3
creation.

**Rationale**: Evaluating amount or merchant constraints before confirming the
execution environment is valid exposes the agent to a TOCTOU race — the agent
might confirm a valid amount constraint and then execute into a closed market.
Environment constraints gate execution; they are not co-equal with
transactional constraints.

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
`max_age_seconds` field narrows this window below `expires_at` when needed.
The `receipt_id` field enables consumers that require per-receipt deduplication
to detect and reject replayed attestations within the TTL window.

For financial execution contexts, verifiers SHOULD maintain a short-lived
`receipt_id` deduplication cache (TTL: `max_age_seconds + 30s`) to prevent
a single receipt from being used to authorise multiple L3 creations.

### 6.3 Oracle Endpoint Substitution

An attacker who can modify the Layer 2 mandate could substitute a malicious
`attestation_url` pointing to an attacker-controlled server returning a
signed-looking response. This attack is prevented by the KB-SD-JWT+KB
signature on Layer 2 — any modification to `attestation_url` or
`oracle_public_key_id` invalidates the user's signature.

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
constraints from the mandate payload invalidates the user's signature.

### 6.6 UNKNOWN Status Oracle Response

An oracle returning `status: "UNKNOWN"` is signalling that it cannot determine
the market state — not that the market is open. Implementations MUST treat
`UNKNOWN` (and `HALTED`) as a constraint violation (§4.3). An implementation
that treats `UNKNOWN` as a pass-through to `expected_status` comparison is
critically misconfigured and MUST be considered non-conformant.

### 6.7 Time Synchronisation

The `issued_at` age check (Step 7 of §4.2) requires that the verifier's clock
is reasonably synchronised with the oracle's clock. A clock skew exceeding
`max_age_seconds` would cause all attestations to be rejected. Implementations
SHOULD use NTP-synchronised clocks and SHOULD log clock-skew-related failures
distinctly to aid diagnosis.

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
| Supported exchanges | 23 global exchanges across Americas, Europe, Middle East, Africa, Asia, and Pacific |
| Consumer verification SDK | `@headlessoracle/verify` (npm, zero production dependencies) |

**Supported MIC codes**: XNYS, XNAS, XBSP, XLON, XPAR, XSWX, XMIL, XHEL, XSTO, XIST,
XSAU, XDFM, XJSE, XSHG, XSHE, XHKG, XJPX, XKRX, XBOM, XNSE, XSES, XASX, XNZE

### 7.2 Minimal Constraint Verifier (JavaScript, Web Crypto)

```javascript
async function checkMarketStateConstraint(constraint, now = new Date()) {
  const {
    attestation_url,
    oracle_public_key_id,
    expected_status,
    max_age_seconds = 60,
  } = constraint;

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
  if (A.key_id !== oracle_public_key_id) {
    throw new Error('Attestation key_id mismatch: fail-closed');
  }

  // Step 4 — Fetch oracle public key
  let publicKeyHex;
  try {
    const kr = await fetch(`https://${A.issuer}/.well-known/oracle-keys.json`,
      { signal: AbortSignal.timeout(4000) });
    const { keys } = await kr.json();
    const entry = keys.find(k => k.id === A.key_id);
    if (!entry) throw new Error('Key not found in registry');
    if (entry.valid_until && new Date(entry.valid_until) < now) {
      throw new Error('Oracle signing key expired');
    }
    publicKeyHex = entry.public_key;
  } catch (e) {
    throw new Error(`Key registry error: ${e.message} — fail-closed`);
  }

  // Step 5 — Verify Ed25519 signature
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

  // Step 7 — Check max_age_seconds
  const ageSeconds = (now - new Date(A.issued_at)) / 1000;
  if (ageSeconds > max_age_seconds) {
    throw new Error(`Attestation age ${ageSeconds}s exceeds max_age_seconds ${max_age_seconds}: fail-closed`);
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
    max_age_seconds = constraint.get("max_age_seconds", 60)

    if not attestation_url.startswith("https://"):
        raise ValueError("Non-HTTPS attestation_url: fail-closed")

    # Fetch attestation
    try:
        r = httpx.get(attestation_url, timeout=4.0)
        r.raise_for_status()
        A = r.json()
    except Exception as e:
        raise RuntimeError(f"Attestation fetch failed: {e} — fail-closed")

    if A.get("key_id") != oracle_public_key_id:
        raise ValueError("key_id mismatch: fail-closed")

    # Fetch public key and verify signature using headless-oracle SDK
    from headless_oracle import verify
    result = verify(A)
    if not result.valid:
        raise ValueError(f"Attestation verification failed: {result.reason} — fail-closed")

    # Age check
    issued_at = datetime.fromisoformat(A["issued_at"].replace("Z", "+00:00"))
    age = (now - issued_at).total_seconds()
    if age > max_age_seconds:
        raise ValueError(f"Attestation age {age:.0f}s exceeds max_age_seconds {max_age_seconds}: fail-closed")

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
   at an attacker-controlled oracle. Proposal: a `trusted_issuers` field in the wallet
   policy layer (outside constraint scope).

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

---

## 9. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1-draft | 2026-03-17 | Initial draft. `environment.market_state` constraint type. Ed25519 attestation verification. Fail-closed algorithm. Headless Oracle as reference implementation. Proposed for registration in VI constraint type registry. |

---

## Appendix A: Attestation Test Vectors

These test vectors allow constraint verifier implementors to validate their
attestation verification logic against a known-good signed receipt from Headless
Oracle.

**Attestation object (before signature)**:
```json
{
  "expires_at": "2026-03-17T12:01:00Z",
  "issued_at":  "2026-03-17T12:00:00Z",
  "issuer":     "headlessoracle.com",
  "key_id":     "key_2026_v1",
  "mic":        "XNYS",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "receipt_mode": "live",
  "schema_version": "v5.0",
  "source":     "SCHEDULE",
  "status":     "OPEN"
}
```

**Canonical payload** (fields sorted alphabetically, compact JSON):
```
{"expires_at":"2026-03-17T12:01:00Z","issued_at":"2026-03-17T12:00:00Z","issuer":"headlessoracle.com","key_id":"key_2026_v1","mic":"XNYS","receipt_id":"550e8400-e29b-41d4-a716-446655440000","receipt_mode":"live","schema_version":"v5.0","source":"SCHEDULE","status":"OPEN"}
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
| `key_id` mismatch | 3 | `"Attestation key_id does not match oracle_public_key_id"` | Do not proceed |
| Key registry unreachable | 4 | `"Oracle key registry unreachable: fail-closed"` | Do not proceed |
| Key not found in registry | 4 | `"Signing key not found in oracle key registry: fail-closed"` | Do not proceed |
| Oracle signing key expired | 4 | `"Oracle signing key has expired: fail-closed"` | Do not proceed |
| Signature verification failed | 5 | `"Attestation signature verification failed: fail-closed"` | Do not proceed; alert operator |
| Attestation `expires_at` in past | 6 | `"Attestation has expired (expires_at in past): fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| Attestation exceeds `max_age_seconds` | 7 | `"Attestation age Ns exceeds max_age_seconds M: fail-closed"` | Re-fetch; if re-fetch fails, do not proceed |
| Status is `UNKNOWN` | 8 | `"Market status is UNKNOWN, expected OPEN: constraint not satisfied"` | Do not proceed; do not retry |
| Status is `HALTED` | 8 | `"Market status is HALTED, expected OPEN: constraint not satisfied"` | Do not proceed; log reason; do not retry until next signed OPEN |
| Status is `CLOSED` | 8 | `"Market status is CLOSED, expected OPEN: constraint not satisfied"` | Do not proceed; retry after next scheduled open |

---

*End of document. Comments and revisions should be submitted as issues or pull requests to the Verifiable Intent specification repository (github.com/agent-intent/verifiable-intent) or the Headless Oracle reference implementation repository (github.com/LembaGang/headless-oracle-v5).*
