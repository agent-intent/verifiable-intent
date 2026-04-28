# RFC: Extensibility of Constraint Vocabulary to Support Environmental Execution States (environment.market_state)

**Constraint type identifier**: `environment.market_state`
**Version**: 0.1-draft
**Status**: Proposed for Registration
**Date**: 2026-03-22
**Author**: Headless Oracle Project (headlessoracle.com)
**License**: Apache 2.0

---

## Abstract

This document proposes registration of the `environment.market_state` constraint type in
the Verifiable Intent specification. The constraint gates autonomous financial agent
execution on a cryptographically signed, independently verifiable attestation that the
target exchange is operational at the moment of execution.

The existing Verifiable Intent constraint vocabulary covers authorization, financial caps,
and asset selection. All current constraint types are evaluated at intent generation time
and remain static for the life of the credential. Autonomous agents, however, execute
asynchronously — long after the intent was generated. A cryptographically authorized order
can still execute into a closed exchange, a circuit breaker halt, or a settlement window,
causing real financial harm regardless of authorization validity.

Without environmental attestation, an issuer cannot distinguish between an agent that
executed correctly in a broken environment versus an agent that went rogue. This is a
liability attribution problem for the issuer network, not merely a technical edge case.

`environment.market_state` is a fail-closed constraint type that fills this gap. It
requires a fresh **Signed Market Attestation (SMA)** — a cryptographically signed,
independently verifiable oracle receipt — to be fetched and verified at execution time
before any action proceeds. If the oracle cannot produce a valid SMA, the agent MUST NOT
proceed. The absence of proof is itself proof of unsafety. The `receipt_id` from every
successful verification provides issuers with dispute-grade evidence that the execution
environment was valid at the exact moment of action.

### Companion Documents

| Document | Location | Description |
|---|---|---|
| SMA Protocol Specification | github.com/LembaGang/sma-protocol/blob/master/SPEC.md | Full normative specification for SMA receipt format and signing algorithm |
| Agent Pre-Trade Safety Standard (APTS) | github.com/LembaGang/agent-pretrade-safety-standard/blob/master/STANDARD.md | 6-check pre-execution safety checklist for autonomous agents |
| Reference Implementation | headlessoracle.com | Live oracle: 23 exchanges, Ed25519 signing, MCP + REST |
| Verification SDK | npmjs.com/package/@headlessoracle/verify | Zero-dependency JS/TS verifier |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
and only when, they appear in all capitals, as shown here.

---

## 2. Overview

### 2.1 What This Constraint Is

`environment.market_state` is an execution-time gate that requires a fresh, cryptographically
signed attestation of exchange operational status before an autonomous agent proceeds with
a financial action on that exchange. It is registered in the `environment.*` constraint
namespace as a policy requirement within the Layer 2 Intent credential; it does not modify
the credential structure.

The constraint is **fail-closed by design**. Any failure in the attestation pipeline —
network error, signature verification failure, expired receipt, UNKNOWN or HALTED status —
causes the constraint to fail and MUST prevent execution. There is no fallback to a
permissive default.

This is not a preference or advisory. It is a hard gate. An issuer whose agents execute
this constraint can produce a signed `receipt_id` for every execution — dispute-grade
evidence that the market was verified operational before the action was taken.

### 2.2 Where This Constraint Appears

`environment.market_state` appears in `mandate.constraints[]` for any mandate that involves
execution on a regulated equity, bond, or derivatives exchange. It is evaluated by the
executing agent, not the authorizing principal.

Examples of mandates where this constraint SHOULD appear:

- "Buy 100 shares of AAPL on NYSE" → constraint subject: `XNYS`
- "Rebalance portfolio across NASDAQ and LSE at market open" → two constraints, `XNAS` + `XLON`
- "Execute stop-loss order on Tokyo exchange if price crosses threshold" → subject: `XJPX`

### 2.3 Lifecycle

```
Mandate issued by principal
    │
    ▼
Agent receives mandate
    │
    ▼
[STEP 1] Evaluate environment.market_state constraint
    │  ├─ Fetch fresh SMA receipt from oracle
    │  ├─ Verify Ed25519 signature
    │  ├─ Check receipt TTL (expires_at > now)
    │  └─ Check status ∈ required_status
    │
    ├─ FAIL → halt all execution, do not evaluate further constraints
    │
    ▼
[STEP 2] Evaluate payment / authorization constraints
    │
    ▼
[STEP 3] Execute mandate
    │
    ▼
Audit log: receipt_id recorded alongside execution record
```

### 2.4 Fulfillment Model

This constraint is **oracle-fulfilled**. The executing agent fetches a signed attestation
from an independent oracle operator, verifies the attestation cryptographically, and
evaluates the attested status against the constraint's `required_status` set.

The oracle operator does not participate in execution. The constraint is satisfied entirely
within the agent's verification pipeline. No trust in the oracle's execution path is
required — only trust in the oracle's signing key, which is publicly discoverable and
independently verifiable.

---

## 3. Temporal Gap in the Existing Constraint Vocabulary

### 3.1 Static vs. Dynamic Constraints

The existing Verifiable Intent constraint vocabulary — `payment.*`, `cart.*`, `authorization.*`
— establishes cryptographic boundaries over counterparty identity, asset selection, and
financial caps. These constraints share a critical property: they are **static**. They are
evaluated at intent generation time (T=0) and remain fixed for the life of the credential.
This is correct for authorization. The principal's permission to spend does not change
minute to minute.

Autonomous agents, however, execute asynchronously — hours, days, or weeks after intent
generation. The execution environment (the operational state of a regulated exchange) is
**highly dynamic** and MUST be evaluated at the exact moment of execution (T=1). No
current constraint type in the Verifiable Intent vocabulary addresses this temporal gap.

```
T=0  Principal issues mandate with payment.budget and authorization constraints
     └─ All existing constraints evaluated and cryptographically bound here

     [time passes — exchange may open, close, halt, or enter settlement window]

T=1  Agent attempts execution
     └─ Exchange state at T=1 is unknown to the T=0 credential
     └─ No existing constraint type covers this
```

### 3.2 The Constraint This RFC Registers

`environment.market_state` resolves this gap by acting as a **policy requirement within
the Layer 2 Intent credential**: the principal specifies which oracle to consult, the
maximum acceptable attestation age, and the required market status. The constraint travels
with the mandate.

At execution time (T=1), the agent:

1. Fetches a fresh Signed Market Attestation (SMA) from the specified oracle
2. Verifies the Ed25519 signature and TTL locally
3. Attaches the verified `receipt_id` to the Layer 3 Action payload as evidence

The Intent credential itself does not expire due to changing market conditions. Only the
SMA evidence is time-bounded (60-second TTL). This cleanly separates:

- **Static authorization proof** (Layer 2 credential) — the principal's intent, bound at T=0
- **Dynamic environmental proof** (Layer 3 evidence) — the oracle's attestation, fetched at T=1

The credential structure is not modified. The existing SD-JWT format is preserved. A new
constraint type is registered; no new credential layer is introduced.

### 3.3 Why This Matters for Issuers

Without environmental attestation, a valid Verifiable Intent mandate can execute into an
unavailable market — triggering retry loops, queued orders that execute at unpredictable
prices, and, most critically, an issuer who cannot distinguish between an agent that
executed correctly in a broken environment versus an agent that exceeded its mandate. This
is a liability attribution problem, not merely a technical inconvenience.

`environment.market_state` is a fail-closed primitive. If the oracle cannot produce a valid
SMA — for any reason — the agent MUST NOT proceed. The absence of proof is itself proof
of unsafety. The `receipt_id` attached to every successful execution provides issuers with
dispute-grade evidence that the execution environment was valid at the exact moment of
action.

---

## 4. Constraint Schema

### 4.1 Constraint Object Fields

The `environment.market_state` constraint object appears in `mandate.constraints[]` with
the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | MUST be `"environment.market_state"` |
| `subject` | string | REQUIRED | ISO 10383 MIC code identifying the target exchange (e.g. `"XNYS"`) |
| `required_status` | string[] | REQUIRED | MUST be `["OPEN"]`. The oracle-attested market status required before execution proceeds. MUST NOT contain `"UNKNOWN"` or `"HALTED"`. |
| `max_age_seconds` | integer | REQUIRED | Maximum age of a valid SMA receipt in seconds. MUST be ≤ the oracle's published TTL (typically 60). Agents MUST re-fetch if the cached receipt is older than this value. |
| `oracle` | object | REQUIRED | Oracle descriptor. See §4.2. |
| `fallback` | string | OPTIONAL | Action on constraint failure: `"halt"` (default) or `"defer"`. `"defer"` reschedules the mandate for a subsequent evaluation window; the agent MUST NOT execute immediately. If absent, treat as `"halt"`. |

**Note on `required_status`**: For this version of the constraint, `required_status` MUST
be `["OPEN"]`. Extensions to support closed-market or post-session execution windows are
deferred to follow-on work and are out of scope for this RFC.

### 4.2 Oracle Subobject

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string (FQDN) | REQUIRED | Oracle operator domain. Used to construct key discovery URL: `{issuer}/.well-known/oracle-keys.json` (RFC 8615). Also used to construct the receipt endpoint: `{issuer}/v5/status?mic={subject}`. |
| `key_id` | string | RECOMMENDED | Expected signing key identifier. If provided, agents MUST reject receipts whose `key_id` does not match. Enables pinning without hardcoding the public key. |
| `public_key` | string (hex) | OPTIONAL | Hex-encoded Ed25519 public key. If provided, agents SHOULD use this key directly and skip the key registry fetch (reduces latency). If absent, agents MUST fetch the key from `{issuer}/.well-known/oracle-keys.json`. |
| `endpoint` | string (URL) | OPTIONAL | Full URL override for the receipt endpoint. Useful for non-standard oracle deployments. If absent, agents MUST construct the URL as `https://{issuer}/v5/status?mic={subject}`. |

### 4.3 Constraint Registration

| Field | Value |
|---|---|
| Type identifier | `environment.market_state` |
| Domain | `environment` |
| Name | `market_state` |
| Version | `0.1-draft` |
| Defined in | This document |
| Disclosure form | `property` (full constraint object in credential) |
| Evaluator | Executing agent |
| Failure mode | Fail-closed (halt execution) |
| Requires network access | Yes (oracle fetch) |

### 4.4 Complete Constraint Example

```json
{
  "type": "environment.market_state",
  "subject": "XNYS",
  "required_status": ["OPEN"],
  "max_age_seconds": 60,
  "oracle": {
    "issuer": "headlessoracle.com",
    "key_id": "key_2026_v1",
    "public_key": "03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178"
  },
  "fallback": "halt"
}
```

---

## 5. Validation Algorithm

### 5.1 Overview

Validation of an `environment.market_state` constraint proceeds through five sequential
stages. Failure at any stage terminates validation and produces a constraint failure.
There is no partial success.

```
FUNCTION validate_environment_market_state(constraint, agent_context):

  STAGE 1: Fetch SMA receipt
  STAGE 2: Verify Ed25519 signature
  STAGE 3: Verify receipt TTL
  STAGE 4: Verify status
  STAGE 5: Return result

  On ANY failure in stages 1–4: RETURN ConstraintResult.FAIL
  After stage 4 success: RETURN ConstraintResult.PASS
```

### 5.2 Stage 1: Fetch SMA Receipt

```
endpoint = constraint.oracle.endpoint
           ?? "https://{constraint.oracle.issuer}/v5/status?mic={constraint.subject}"

receipt, err = http_get(endpoint,
  headers  = {"X-Oracle-Key": agent.oracle_api_key},
  timeout  = 4000ms
)

IF err OR receipt.http_status != 200:
  LOG "SMA_FETCH_FAILED: {err}"
  RETURN FAIL  // network error, DNS failure, or oracle internal error
```

**Timeout rationale**: 4 seconds is the RECOMMENDED maximum. Agents that block
indefinitely on oracle requests create cascading failure modes in multi-agent pipelines.

**Authentication**: The oracle MAY require an API key. Agents MUST obtain a key from the
oracle operator before executing mandates with this constraint. The reference implementation
offers a public `/v5/demo` endpoint for testing (unauthenticated, `receipt_mode: "demo"`)
and an authenticated `/v5/status` endpoint for production (authenticated, `receipt_mode: "live"`).

### 5.3 Stage 2: Verify Ed25519 Signature

```
// Get the signing public key
IF constraint.oracle.public_key is present:
  public_key_bytes = hex_decode(constraint.oracle.public_key)
ELSE:
  key_registry = http_get("https://{constraint.oracle.issuer}/.well-known/oracle-keys.json")
  key_entry = key_registry.keys.find(k => k.id == receipt.key_id)
  IF key_entry is null: RETURN FAIL  // key not found
  public_key_bytes = hex_decode(key_entry.public_key)

// Verify key_id matches if pinned
IF constraint.oracle.key_id is present AND receipt.key_id != constraint.oracle.key_id:
  LOG "SMA_KEY_ID_MISMATCH: expected {constraint.oracle.key_id}, got {receipt.key_id}"
  RETURN FAIL

// Reconstruct canonical payload
payload_fields = {all receipt fields EXCEPT "signature"}
sorted_keys = sort_keys_alphabetically(payload_fields)
canonical = JSON.stringify(sorted_keys, separators=(',', ':'))
canonical_bytes = utf8_encode(canonical)

// Verify signature
signature_bytes = hex_decode(receipt.signature)
valid = ed25519_verify(signature_bytes, canonical_bytes, public_key_bytes)

IF NOT valid:
  LOG "SMA_SIGNATURE_INVALID: receipt_id={receipt.receipt_id}"
  RETURN FAIL
```

**Key caching**: Agents SHOULD cache the public key from the key registry to avoid a
network fetch on every verification. The cache MUST be invalidated on signature failure
(the oracle may have rotated keys). The `public_key` field in the constraint object
allows high-frequency agents to skip the registry fetch entirely.

### 5.4 Stage 3: Verify Receipt TTL

```
now = current_utc_time()
expires_at = parse_iso8601(receipt.expires_at)

IF expires_at <= now:
  LOG "SMA_RECEIPT_EXPIRED: expires_at={receipt.expires_at}, now={now}"
  RETURN FAIL

age_seconds = (now - parse_iso8601(receipt.issued_at)).total_seconds()
IF age_seconds > constraint.max_age_seconds:
  LOG "SMA_RECEIPT_TOO_OLD: age={age_seconds}s, max={constraint.max_age_seconds}s"
  RETURN FAIL

// Check receipt_mode — demo receipts MUST NOT be used for production decisions
IF receipt.receipt_mode == "demo":
  LOG "SMA_DEMO_RECEIPT_REJECTED: receipt_mode=demo is not valid for production mandates"
  RETURN FAIL
```

**Clock skew**: Agents operating in environments with potentially skewed system clocks
SHOULD apply a clock-skew allowance of ≤ 5 seconds. Agents MUST NOT apply a skew
allowance large enough to permit acting on an oracle-expired receipt.

### 5.5 Stage 4: Verify Status

```
// Fail-closed status handling
IF receipt.status == "UNKNOWN":
  LOG "SMA_STATUS_UNKNOWN: oracle fail-closed signal — halt all execution"
  RETURN FAIL

IF receipt.status == "HALTED":
  LOG "SMA_STATUS_HALTED: reason={receipt.reason ?? 'unspecified'}"
  RETURN FAIL

IF receipt.status NOT IN constraint.required_status:
  LOG "SMA_STATUS_MISMATCH: got={receipt.status}, required={constraint.required_status}"
  RETURN FAIL

// All checks passed
LOG "SMA_VALIDATED: receipt_id={receipt.receipt_id}, status={receipt.status}, mic={receipt.mic}"
RETURN PASS with metadata = {receipt_id: receipt.receipt_id, oracle_status: receipt.status}
```

**UNKNOWN treatment**: `UNKNOWN` means the oracle cannot determine market state. This is
the oracle's own fail-closed signal — it MUST be treated as CLOSED/HALT by all consumers.
An oracle returning UNKNOWN is operating correctly; consumers that treat UNKNOWN as OPEN
are operating incorrectly.

### 5.6 Complete Pseudocode

```
FUNCTION validate_environment_market_state(constraint):
  // Stage 1: Fetch
  endpoint = constraint.oracle.endpoint
             ?? "https://" + constraint.oracle.issuer + "/v5/status?mic=" + constraint.subject
  receipt, err = http_get(endpoint, timeout=4000ms)
  IF err OR status != 200: RETURN FAIL("FETCH_ERROR")

  // Stage 2: Signature
  IF constraint.oracle.public_key:
    pub = hex_decode(constraint.oracle.public_key)
  ELSE:
    reg = http_get("https://" + constraint.oracle.issuer + "/.well-known/oracle-keys.json")
    entry = reg.keys.find(k.id == receipt.key_id)
    IF NOT entry: RETURN FAIL("KEY_NOT_FOUND")
    pub = hex_decode(entry.public_key)
  IF constraint.oracle.key_id AND receipt.key_id != constraint.oracle.key_id:
    RETURN FAIL("KEY_ID_MISMATCH")
  fields = {k: receipt[k] for k in receipt if k != "signature"}
  canonical = json_canonical(fields)
  IF NOT ed25519_verify(hex_decode(receipt.signature), utf8(canonical), pub):
    RETURN FAIL("INVALID_SIGNATURE")

  // Stage 3: TTL
  IF parse_iso8601(receipt.expires_at) <= now(): RETURN FAIL("EXPIRED")
  IF (now() - parse_iso8601(receipt.issued_at)).seconds > constraint.max_age_seconds:
    RETURN FAIL("TOO_OLD")
  IF receipt.receipt_mode == "demo": RETURN FAIL("DEMO_RECEIPT")

  // Stage 4: Status
  IF receipt.status == "UNKNOWN": RETURN FAIL("STATUS_UNKNOWN")
  IF receipt.status == "HALTED": RETURN FAIL("STATUS_HALTED")
  IF receipt.status NOT IN constraint.required_status:
    RETURN FAIL("STATUS_MISMATCH")

  RETURN PASS({receipt_id: receipt.receipt_id, oracle_status: receipt.status})
```

---

## 6. Integration with constraints.md

### 6.1 Integration with §5.3 Validation Order

`environment.market_state` MUST be evaluated **before** any `payment.*` or `authorization.*`
constraints in the same mandate. The rationale: it is wasteful and potentially harmful to
authorize a payment for execution in a closed or halted market.

The RECOMMENDED constraint evaluation order for mandates involving exchange execution is:

```
1. environment.market_state   (this constraint — fail-closed gate)
2. authorization.*            (principal intent verification)
3. payment.*                  (payment authorization, x402 verification)
4. cart.* / execution.*       (order parameters)
```

**Note to spec maintainers**: This evaluation order SHOULD be reflected in the
`constraints.md §5.3` ordering guidance. If the spec does not currently prescribe
`environment.*` evaluation order relative to `payment.*`, this RFC proposes that
`environment.*` constraints be evaluated first as a class.

### 6.2 Strictness Mode Interaction

In `strictness: "strict"` mode, `environment.market_state` failure MUST cause the entire
mandate to fail immediately. No further constraints are evaluated.

In `strictness: "lenient"` mode (if supported by the VI spec), `environment.market_state`
MUST still behave fail-closed. There is no lenient mode for market state — a closed market
does not accept orders regardless of the principal's preferences.

### 6.3 Output Fields

On constraint pass, the following fields SHOULD be added to the mandate execution record:

| Field | Type | Description |
|---|---|---|
| `oracle_receipt_id` | UUID | The `receipt_id` from the verified SMA receipt |
| `oracle_status` | string | The verified status value (e.g. `"OPEN"`) |
| `oracle_verified_at` | ISO 8601 | The `issued_at` timestamp from the receipt |
| `oracle_expires_at` | ISO 8601 | The `expires_at` timestamp from the receipt |

These fields enable post-hoc audit: given a mandate execution record, a regulator or
dispute resolution system can confirm what market state the agent verified before execution.

---

## 7. Constraint Examples

### 7.1 Standard Equity Execution — Single Exchange

A mandate authorizing a market buy order on NYSE:

```json
{
  "id": "mandate-7f3a9b2c",
  "intent": "buy",
  "amount": {"currency": "USD", "value": "5000"},
  "constraints": [
    {
      "type": "environment.market_state",
      "subject": "XNYS",
      "required_status": ["OPEN"],
      "max_age_seconds": 60,
      "oracle": {
        "issuer": "headlessoracle.com",
        "key_id": "key_2026_v1",
        "public_key": "03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178"
      }
    },
    {
      "type": "payment.budget",
      "limit": {"currency": "USD", "value": "5000"}
    }
  ]
}
```

The SMA constraint is evaluated first. If NYSE is closed (e.g. 16:01 ET), the mandate
fails before the payment constraint is ever checked.

### 7.2 Halt Scenario — Circuit Breaker L1

At 14:23 UTC, NYSE triggers a Level 1 circuit breaker. The oracle returns:

```json
{
  "receipt_id": "d4e7f920-3b1a-4c8e-9f2d-7a1b3c5e8f0a",
  "issued_at": "2026-03-22T14:23:07.441Z",
  "expires_at": "2026-03-22T14:24:07.441Z",
  "issuer": "headlessoracle.com",
  "mic": "XNYS",
  "status": "HALTED",
  "source": "OVERRIDE",
  "reason": "NYSE circuit breaker L1 — trading halted 15 minutes",
  "receipt_mode": "live",
  "schema_version": "v5.0",
  "public_key_id": "key_2026_v1",
  "signature": "<ed25519-hex>"
}
```

Stage 4 of the validation algorithm detects `status: "HALTED"` and returns FAIL. The
agent halts. The `reason` field is logged in the execution record. No order is submitted.

### 7.3 Multi-Exchange Portfolio Rebalance

A mandate covering three exchanges uses three separate `environment.market_state`
constraints. All three MUST pass before any execution proceeds:

```json
{
  "constraints": [
    {
      "type": "environment.market_state",
      "subject": "XNYS",
      "required_status": ["OPEN"],
      "max_age_seconds": 60,
      "oracle": { "issuer": "headlessoracle.com", "key_id": "key_2026_v1" }
    },
    {
      "type": "environment.market_state",
      "subject": "XLON",
      "required_status": ["OPEN"],
      "max_age_seconds": 60,
      "oracle": { "issuer": "headlessoracle.com", "key_id": "key_2026_v1" }
    },
    {
      "type": "environment.market_state",
      "subject": "XJPX",
      "required_status": ["OPEN"],
      "max_age_seconds": 60,
      "oracle": { "issuer": "headlessoracle.com", "key_id": "key_2026_v1" }
    }
  ]
}
```

**Batch optimization**: The reference implementation provides `GET /v5/batch?mics=XNYS,XLON,XJPX`
which returns independently signed receipts for all three exchanges in a single authenticated
request. Agents MAY use this endpoint to satisfy all three constraints with one network call,
verifying each receipt independently before evaluating each constraint.

The batch response includes a `summary.safe_to_execute` field that is `true` only when all
requested exchanges are OPEN and none are HALTED or UNKNOWN. Agents MUST still verify each
receipt individually — `safe_to_execute` is a convenience field and does not replace
per-receipt Ed25519 verification.

### 7.4 Deferred Execution — Market Not Yet Open

```json
{
  "type": "environment.market_state",
  "subject": "XNAS",
  "required_status": ["OPEN"],
  "max_age_seconds": 60,
  "oracle": { "issuer": "headlessoracle.com", "key_id": "key_2026_v1" },
  "fallback": "defer"
}
```

At 09:00 ET (30 minutes before NASDAQ open), the agent evaluates this constraint and
receives `status: "CLOSED"`. With `fallback: "defer"`, the agent re-queues the mandate
for evaluation at the next poll interval rather than failing it permanently. At 09:30 ET,
NASDAQ opens, the constraint passes, and execution proceeds.

**Important**: `fallback: "defer"` MUST NOT cause an agent to execute immediately on any
closed or unknown status. It defers the evaluation — it does not relax the constraint.

---

## 8. Extension Namespace (Future Work)

The `environment.*` namespace is intentionally generic. Future registrations MAY extend
this pattern to other execution environments where runtime state verification is required
before an agent acts. Such extensions are out of scope for this RFC and will be addressed
in follow-on submissions.

---

## 9. Relationship to x402 Payment Protocol

x402 is a payment primitive: can the agent afford to pay, and can the payment be
verified on-chain? `environment.market_state` is an environmental primitive: is the
execution venue operational? Together, they close the two main safety gaps in autonomous
agent execution:

```
Complete agent execution safety =
    authorization_valid (Verifiable Intent)
  + market_operational  (environment.market_state, this RFC)
  + payment_verified    (x402)
```

**Integration pattern**: In a mandate that uses x402 micropayments to access the oracle,
the `environment.market_state` constraint itself is what triggers the x402 payment.
The oracle returns HTTP 402 with an x402 payload when the requesting agent lacks an API key.
The agent pays (0.001 USDC on Base mainnet), retries with `X-Payment: {txHash}`, and
receives the signed receipt. The constraint then evaluates the receipt normally.

This creates a self-funding constraint: an agent authorized to spend on equities can also
autonomously pay for the oracle verification that gates its own execution.

**Execution sequence with x402**:

```
Agent → GET /v5/status?mic=XNYS (no API key)
Oracle → HTTP 402 {x402: {amount: "1000", currency: "USDC", network: "base-mainnet", ...}}
Agent → pays 0.001 USDC to oracle wallet on Base
Agent → GET /v5/status?mic=XNYS (with X-Payment: {txHash})
Oracle → HTTP 200 {status: "OPEN", signature: "...", ...}
Agent → verifies receipt → constraint passes → executes mandate
```

---

## 10. Relationship to Mastercard Verifiable Intent

Mastercard's CDO articulates the Verifiable Intent thesis: in autonomous agent commerce,
cryptographic proof replaces human approval. Purchase authorization = cryptographic proof.
This is the correct framing for the authorization layer.

The `environment.market_state` constraint extends this thesis to the environmental layer:
**market state verification = cryptographic proof**.

Mastercard's domain is the authorization handshake: the cardholder (principal) authorizes
an agent to spend. The SMA domain is the environmental handshake: the exchange confirms it
is open to receive orders. These are sequential, not competitive.

```
Mastercard Verifiable Intent:
  "Is the principal authorized to make this payment?" → cryptographic proof

environment.market_state (this RFC):
  "Is the exchange operational to receive this order?" → cryptographic proof

Together:
  "The authorized agent verified market state before executing." → auditable, composable
```

The Verifiable Intent framework becomes stronger, not more complex, by incorporating
`environment.market_state`. A mandate that carries both authorization proof and
environmental proof is more auditable, more defensible in dispute resolution, and more
appropriate for automated execution at scale than a mandate with authorization alone.

**Practical implication**: A financial institution using Verifiable Intent for agent
authorization SHOULD include `environment.market_state` constraints in any mandate
involving regulated market execution. Without it, the mandate provides strong authorization
but no environmental guarantee — the trust chain is incomplete.

---

## 11. Security Considerations

### 11.1 SSRF and Oracle Endpoint Pinning

The `oracle.endpoint` field, if present in a mandate, is fetched by the executing agent.
A malicious principal could construct an `oracle.endpoint` pointing to an internal network
resource (SSRF). Agent runtimes MUST validate that oracle endpoints resolve to public IP
addresses and MUST NOT follow `oracle.endpoint` values without domain allowlisting.

The RECOMMENDED mitigation is to require that `oracle.issuer` matches a domain on an
allowlist of known oracle operators, and to construct the endpoint URL from `issuer` rather
than accepting an arbitrary `endpoint` override.

### 11.2 Replay Attacks

The `expires_at` field limits the replay window to the TTL duration (60 seconds for the
reference implementation). An attacker who captures a valid OPEN receipt can replay it for
at most 60 seconds. Agents that enforce `expires_at` strictly are protected.

For stricter replay protection within the TTL window, agents MAY track `receipt_id` values
seen in the current session and reject duplicates. The reference implementation also
provides `receipt_id` deduplication on the oracle side.

### 11.3 Clock Skew

Agents with system clocks skewed more than the TTL (60 seconds) will fail to validate
legitimately fresh receipts or will accept legitimately expired ones. Agents SHOULD use
NTP-synchronized clocks and SHOULD apply a maximum clock-skew allowance of 5 seconds.
Agent runtimes SHOULD reject any `environment.market_state` constraint evaluation if the
system clock cannot be verified as synchronized.

### 11.4 Key Trust Bootstrapping

The security of the signature verification depends on the agent correctly identifying the
oracle's public key. The `oracle.public_key` field in the constraint enables key pinning.
When pinning is used, the constraint author MUST update the key pin before key rotation.
Agents relying on key registry discovery MUST re-fetch on signature failure (the oracle
may have rotated).

The reference implementation publishes its current public key through three independent
channels: `/.well-known/oracle-keys.json` (RFC 8615), `/v5/keys` (Oracle-specific registry),
and the npm package `@headlessoracle/verify`. Agents SHOULD verify consistency across
channels during initial onboarding.

### 11.5 Fail-Closed Is Non-Negotiable

An oracle that defaults to OPEN on any failure is a liability, not an oracle. The
`environment.market_state` constraint MUST treat all failure modes (network error, invalid
signature, expired receipt, UNKNOWN status) identically: **halt execution**.

This applies to the oracle implementation as well as the agent's constraint evaluator.
The reference implementation implements a 4-tier fail-closed architecture:

- Tier 0: Manual override check (circuit breaker → HALTED)
- Tier 1: Schedule-based computation (OPEN/CLOSED)
- Tier 2: Tier 1 failure → signed UNKNOWN (fail-closed, still signed)
- Tier 3: Signing failure → unsigned CRITICAL_FAILURE (500, UNKNOWN — halt)

Implementors of oracle systems used with this constraint MUST provide equivalent
fail-closed guarantees. An oracle that silently returns OPEN when uncertain is
incompatible with this constraint type.

### 11.6 Partial Batch Trust

When using a batch oracle endpoint (§7.3), agents MUST verify each receipt independently.
A compromised oracle could return a valid signature for some receipts and a forged
`safe_to_execute: true` summary. The summary is a convenience field; it does not carry
a separate signature and MUST NOT replace per-receipt verification.

---

## 12. Reference Implementation

To demonstrate implementation viability of the `environment.market_state` constraint, an
open-source reference implementation is available at github.com/LembaGang/headless-oracle-v5.
This Cloudflare Workers deployment provides sub-second Ed25519-signed market attestations
for 23 global exchanges and fulfills the oracle requirements specified in §4.

Use of this implementation is not required; any oracle capable of producing SMA receipts
conforming to the schema in §4 and the signing specification in §5 is compliant with
this RFC.

The reference implementation exposes the following endpoints relevant to constraint
evaluation:

| Endpoint | Purpose |
|---|---|
| `GET /v5/status?mic={MIC}` | Authenticated SMA receipt (production) |
| `GET /v5/demo?mic={MIC}` | Unauthenticated SMA receipt (`receipt_mode: "demo"` — testing only) |
| `GET /v5/batch?mics={MIC,MIC,...}` | Batch SMA receipts, independently signed |
| `GET /.well-known/oracle-keys.json` | RFC 8615 key discovery |
| `GET /v5/keys` | Full key registry with canonical payload spec |

### 12.1 Minimal Verifier (JavaScript — Web Crypto, zero dependencies)

```javascript
async function validateSMAConstraint(constraint, apiKey) {
  const url = `https://${constraint.oracle.issuer}/v5/status?mic=${constraint.subject}`;

  // Stage 1: Fetch
  const resp = await fetch(url, {
    headers: apiKey ? { 'X-Oracle-Key': apiKey } : {},
    signal: AbortSignal.timeout(4000)
  });
  if (!resp.ok) return { pass: false, reason: 'FETCH_ERROR' };
  const receipt = await resp.json();

  // Stage 2: Signature
  const { signature, ...payload } = receipt;
  const sorted = Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]));
  const canonical = JSON.stringify(sorted);
  const pubKeyHex = constraint.oracle.public_key ?? await fetchPublicKey(constraint.oracle.issuer, receipt.key_id);
  const pubKey = await crypto.subtle.importKey('raw', hexToBytes(pubKeyHex), { name: 'Ed25519' }, false, ['verify']);
  const valid = await crypto.subtle.verify('Ed25519', pubKey, hexToBytes(signature), new TextEncoder().encode(canonical));
  if (!valid) return { pass: false, reason: 'INVALID_SIGNATURE' };

  // Stage 3: TTL
  if (new Date(receipt.expires_at) <= new Date()) return { pass: false, reason: 'EXPIRED' };
  if (receipt.receipt_mode === 'demo') return { pass: false, reason: 'DEMO_RECEIPT' };

  // Stage 4: Status
  if (receipt.status === 'UNKNOWN') return { pass: false, reason: 'STATUS_UNKNOWN' };
  if (receipt.status === 'HALTED') return { pass: false, reason: 'STATUS_HALTED' };
  if (!constraint.required_status.includes(receipt.status)) return { pass: false, reason: 'STATUS_MISMATCH' };

  return { pass: true, receipt_id: receipt.receipt_id, oracle_status: receipt.status };
}

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

async function fetchPublicKey(issuer, keyId) {
  const reg = await (await fetch(`https://${issuer}/.well-known/oracle-keys.json`)).json();
  const entry = reg.keys.find(k => k.id === keyId);
  if (!entry) throw new Error(`Key ${keyId} not found`);
  return entry.public_key;
}
```

### 12.2 Minimal Verifier (Python — PyNaCl)

```python
import json, time
from datetime import datetime, timezone
import nacl.signing
import httpx

def validate_sma_constraint(constraint, api_key=None):
    # Stage 1: Fetch
    url = f"https://{constraint['oracle']['issuer']}/v5/status?mic={constraint['subject']}"
    headers = {'X-Oracle-Key': api_key} if api_key else {}
    try:
        resp = httpx.get(url, headers=headers, timeout=4.0)
        resp.raise_for_status()
        receipt = resp.json()
    except Exception as e:
        return {'pass': False, 'reason': f'FETCH_ERROR: {e}'}

    # Stage 2: Signature
    sig_hex = receipt.pop('signature')
    canonical = json.dumps(dict(sorted(receipt.items())), separators=(',', ':'))
    pub_hex = constraint['oracle'].get('public_key') or fetch_public_key(
        constraint['oracle']['issuer'], receipt['key_id']
    )
    try:
        vk = nacl.signing.VerifyKey(bytes.fromhex(pub_hex))
        vk.verify(canonical.encode(), bytes.fromhex(sig_hex))
    except Exception:
        return {'pass': False, 'reason': 'INVALID_SIGNATURE'}
    receipt['signature'] = sig_hex  # restore

    # Stage 3: TTL
    expires = datetime.fromisoformat(receipt['expires_at'].replace('Z', '+00:00'))
    if expires <= datetime.now(timezone.utc):
        return {'pass': False, 'reason': 'EXPIRED'}
    if receipt.get('receipt_mode') == 'demo':
        return {'pass': False, 'reason': 'DEMO_RECEIPT'}

    # Stage 4: Status
    if receipt['status'] == 'UNKNOWN': return {'pass': False, 'reason': 'STATUS_UNKNOWN'}
    if receipt['status'] == 'HALTED': return {'pass': False, 'reason': 'STATUS_HALTED'}
    if receipt['status'] not in constraint['required_status']:
        return {'pass': False, 'reason': 'STATUS_MISMATCH'}

    return {'pass': True, 'receipt_id': receipt['receipt_id'], 'oracle_status': receipt['status']}
```

### 12.3 Zero-Dependency npm Package

```bash
npm install @headlessoracle/verify
```

```javascript
import { verify } from '@headlessoracle/verify';

const receipt = await fetch('https://headlessoracle.com/v5/status?mic=XNYS', {
  headers: { 'X-Oracle-Key': process.env.ORACLE_KEY }
}).then(r => r.json());

const result = await verify(receipt, {
  publicKey: '03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178'
});
// result: { valid: true, receipt: {...} } or { valid: false, reason: 'EXPIRED' | ... }
```

---

## 13. Open Questions for the Working Group

1. **Execution order in constraints.md**: Should `environment.*` constraints be normatively
   required to evaluate before `payment.*` constraints in the VI spec? Or is ordering left
   to the mandate author? The security case for normative ordering is strong — but it may
   conflict with implementors who batch all constraint evaluation.

2. **Oracle allowlisting**: Should the spec define a mechanism for mandate authors to
   express which oracle operators are acceptable for a given constraint? A mandate that
   allows any oracle implementing this constraint is accepting trust in potentially unknown
   operators. A registry of conformant oracles would help, but who maintains it?

3. **Multi-oracle quorum**: The current design trusts a single oracle operator per
   constraint. A 2-of-3 quorum design would eliminate the single-operator trust assumption
   but requires specifying quorum semantics. Should quorum be addressed in this RFC
   or a separate companion RFC?

4. **Extension namespace governance**: The `environment.*` namespace is proposed as a
   general pattern for runtime state verification constraints. What criteria should govern
   future registrations in this namespace? Should a companion RFC establish a formal
   registration process, or is working group review of individual PRs sufficient?

5. **Mandate-level vs. constraint-level oracle config**: The `oracle` subobject appears in
   each constraint. If a mandate has three `environment.market_state` constraints all using
   the same oracle, the oracle config is repeated three times. Should there be a
   mandate-level `oracle_config` map that constraints can reference by key?

---

## 14. Changelog

| Version | Date | Changes |
|---|---|---|
| 0.1-draft | 2026-03-22 | Initial proposal submitted to verifiable-intent working group |

---

## Appendix A: Live Test Vectors

The reference implementation provides live, fresh test vectors at:

```
GET https://headlessoracle.com/v5/demo?mic=XNYS
```

This endpoint requires no authentication and returns a fresh signed receipt with
`receipt_mode: "demo"`. The receipt can be used to test the full validation algorithm
in §5.

**Key material for verification**:

```
issuer:      headlessoracle.com
key_id:      key_2026_v1
public_key:  03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178
algorithm:   Ed25519
discovery:   https://headlessoracle.com/.well-known/oracle-keys.json
```

**Example receipt shape** (field values are illustrative; actual values vary per request):

```json
{
  "expires_at":     "2026-03-22T14:31:00.000Z",
  "issued_at":      "2026-03-22T14:30:00.000Z",
  "issuer":         "headlessoracle.com",
  "key_id":         "key_2026_v1",
  "mic":            "XNYS",
  "public_key_id":  "03dc27993a2c...",
  "receipt_id":     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "receipt_mode":   "demo",
  "schema_version": "v5.0",
  "signature":      "<64-byte Ed25519 signature, hex-encoded>",
  "source":         "SCHEDULE",
  "status":         "OPEN"
}
```

**Canonical payload construction** (alphabetical key sort, compact JSON):

The canonical payload for signature verification is constructed by:
1. Collecting all fields except `signature`
2. Sorting keys alphabetically: `expires_at`, `issued_at`, `issuer`, `key_id`, `mic`,
   `public_key_id`, `receipt_id`, `receipt_mode`, `schema_version`, `source`, `status`
3. Serializing with `JSON.stringify({...sorted}, null, 0)` — no whitespace

**OVERRIDE receipt additional field**: When `source` is `"OVERRIDE"` or `"REALTIME"`,
the receipt includes a `reason` field (e.g. `"NYSE circuit breaker L1"`). This field is
included in the canonical payload and is therefore tamper-evident.

**Conformance test**: A correct verifier applied to a fresh `/v5/demo` receipt SHOULD
return valid unless the receipt has expired. A verifier that returns invalid on a fresh
receipt has a canonicalization error. Check: is your key sort alphabetical (case-sensitive)?
Is your JSON serializer using no whitespace between tokens?

---

## Appendix B: Failure Mode Quick Reference

| Failure | Stage | Reason Code | Required Agent Action |
|---|---|---|---|
| Network timeout / connection error | 1 | `FETCH_ERROR` | Halt — treat as UNKNOWN |
| HTTP 4xx from oracle | 1 | `FETCH_ERROR` | Halt — do not retry immediately |
| HTTP 5xx from oracle | 1 | `FETCH_ERROR` | Halt — oracle infrastructure failure |
| Key not found in registry | 2 | `KEY_NOT_FOUND` | Halt — possible key rotation |
| key_id mismatch | 2 | `KEY_ID_MISMATCH` | Halt — possible key substitution attack |
| Ed25519 signature invalid | 2 | `INVALID_SIGNATURE` | Halt + alert operator — serious |
| `expires_at` in the past | 3 | `EXPIRED` | Re-fetch; if re-fetch fails, halt |
| Receipt older than `max_age_seconds` | 3 | `TOO_OLD` | Re-fetch |
| `receipt_mode: "demo"` | 3 | `DEMO_RECEIPT` | Halt — configure production API key |
| `status: "UNKNOWN"` | 4 | `STATUS_UNKNOWN` | Halt immediately — oracle fail-closed signal |
| `status: "HALTED"` | 4 | `STATUS_HALTED` | Halt — log `reason` field; await OPEN |
| `status` not in `required_status` | 4 | `STATUS_MISMATCH` | Halt or defer per `fallback` field |

**The invariant**: no row in this table results in execution. Every failure mode results
in halt or defer. This is not configurable.

---

## Appendix C: Constraint Type Registration Summary

```yaml
type_identifier: environment.market_state
domain: environment
name: market_state
version: 0.1-draft
status: proposed
defined_in: spec/environment-market-state.md
disclosure_form: property
evaluator: executing_agent
failure_mode: fail-closed
requires_network: true
extension_namespace: environment.* (see §8)
reference_implementations:
  - name: Headless Oracle
    url: https://headlessoracle.com
    exchanges: 23
    protocols: [REST, MCP, A2A]
    auth: [apiKey, x402, OAuth2]
    sdk: https://npmjs.com/package/@headlessoracle/verify
```
