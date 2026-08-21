# Verifiable Intent — Price Integrity Attestation Constraint Proposal

**Type identifier**: `environment.price_integrity`
**Version**: 0.2-draft
**Status**: Draft / Proposed for Registration
**Date**: 2026-08-21
**Author**: YuTao Peng (Insight)
**License**: Apache 2.0
**Namespace**: `environment.*`
**Related constraints**: `environment.market_state` (#9), `environment.wallet_state` (#22)

> This document is the normative file proposed for `spec/environment-price-integrity.md`.
> It follows the standalone-spec shape used by PR #9 and PR #22. It is intentionally
> protocol-agnostic and does not require a particular transport for the agent. The
> reference wire example uses HTTPS because the attestation is fetched as an HTTP
> resource and MUST be protected against endpoint substitution and SSRF.

---

## Abstract

This proposal defines `environment.price_integrity`, an environmental constraint
for Verifiable Intent Autonomous mode (Layer 3) execution. It requires an agent
and verifier to obtain and independently validate a short-lived, signed oracle
attestation binding a price-integrity verdict to the asset pair and subject chain
being used by the action.

A valid mandate proves that an agent is authorized to act within a delegated
scope. It does not prove that the price data used at execution time is fresh,
sufficiently covered, or free from a detected integrity failure. This constraint
closes that authorization-to-execution gap without making a price oracle a
replacement for the mandate or for other environmental constraints.

`environment.price_integrity` composes with `environment.market_state` and
`environment.wallet_state` as a logical conjunction. Every required environment
member MUST pass before execution is accepted. A missing, expired, unverifiable,
or negative member MUST fail closed.

## Companion Documents

- `spec/constraints.md` — common constraint structure and validation integration.
- `spec/external-state-attestation.md` — `environment.market_state` sibling
  proposal (PR #9).
- `spec/environment-wallet-state.md` — `environment.wallet_state` sibling
  proposal (PR #22).
- `spec/security-model.md` — repository-wide security model.

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they
appear in ALL CAPITALS, as shown here.

JSON field names are case-sensitive. The receipt's top-level `signedAt` value is
an ISO 8601 string; the signed `data.validUntil` and `data.checkedAt` values are
Unix seconds. Identifiers are compared as exact strings unless this document
specifies another comparison.

## 2. Overview

### 2.1 What This Constraint Is

`environment.price_integrity` is a pre-Layer-3 execution gate. It answers:

> Is the price data bound to this action currently trustworthy enough to use?

It is not a price quote, a trading recommendation, a guarantee of execution
price, or an endorsement of a particular provider. It is a signed, attributable,
refutable statement from an oracle implementation whose claim can be checked by
an independent verifier.

The constraint is fail-closed. Network errors, malformed responses, asset-pair
mismatches, subject-chain mismatches, signature failures, stale receipts, and
negative verdicts MUST be treated as constraint violations.

### 2.2 Where This Constraint Appears

The constraint MAY appear in the `constraints` array of:

- checkout mandates: `mandate.checkout.open.1`;
- payment mandates: `mandate.payment.open.1`.

It applies to Autonomous mode, where an agent creates Layer 3 fulfillment.
Immediate mode remains user-confirmed and does not use this autonomous
pre-execution constraint.

### 2.3 Lifecycle

1. The mandate issuer binds the asset pair, subject chain, attestation endpoint,
   trusted key identifier, and maximum acceptable attestation age.
2. The agent obtains a signed price-integrity attestation before creating L3.
3. The agent checks the attestation locally and MUST stop on the first failed
   `environment.*` member.
4. The verifier independently repeats the check at L3 acceptance time and
   records all environment violations for diagnostic completeness.

### 2.4 Layer 3 Evidence

Agents SHOULD include a `price_integrity_attestation` field in the Layer 3
mandate containing the complete signed receipt observed when creating L3. A
verifier MAY use this field to audit the agent's decision context, but MUST NOT
use it as a substitute for independently fetching and verifying the current
attestation at L3 acceptance time.

### 2.5 Family Composition

`environment.price_integrity` is one member of the `environment.*` family. The
family is conjunctive:

```text
environment.market_state
AND environment.price_integrity
AND environment.wallet_state
```

Only the members present in a mandate are evaluated, but every present member
MUST pass. One passing member MUST NOT compensate for another failing member.

## 3. Constraint Structure

### 3.1 Common Schema

The constraint follows `spec/constraints.md` §3.1:

```json
{
  "type": "environment.price_integrity",
  "attestation_url": "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample",
  "oracle_public_key_id": "insight-oracle-safety-v2",
  "source_asset_id": "eip155:1/slip44:60",
  "destination_asset_id": "eip155:1/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "subject_chain_id": 1,
  "max_attestation_age": 600
}
```

### 3.2 Registration

This constraint is proposed for registration in the `environment.*` namespace
(which is itself proposed by PR #9 and extended by PR #22). Proposed
registration entry:

| Type | Defined In | Version | Disclosure Form |
|---|---|---|---|
| `environment.price_integrity` | This document | 0.2-draft | property (full constraint) |

The constraint follows the validation integration rules in
`spec/constraints.md` §5.3. The repository-wide registry and SDK model can be
updated as a follow-up integration step after working-group review, matching
the staged approach used by PR #9 and PR #22.

### 3.3 Field Scope Declaration

The fields are classified so future `environment.*` siblings can distinguish
family-wide semantics from mechanism-specific semantics.

| Field | Type | Required | Scope | Description |
|---|---|---:|---|---|
| `type` | string | Yes | family-wide | MUST be `environment.price_integrity`. |
| `attestation_url` | HTTPS URL | Yes | family-wide, trust-root-agnostic | Resource from which the verifier fetches the signed attestation. |
| `max_attestation_age` | positive integer | Yes | family-wide, trust-root-agnostic | Maximum accepted age measured from signed `checkedAt`/`issued_at` to verification. No default. |
| `oracle_public_key_id` | non-empty string | Yes | per-type, trust-root-mechanism-bound | Expected `key_id` in the issuer's published key document. |
| `source_asset_id` | string | Yes | per-type, evaluation-mechanism-bound | Exact source asset identifier bound to the action. |
| `destination_asset_id` | string | Yes | per-type, evaluation-mechanism-bound | Exact destination/quote asset identifier bound to the action. |
| `subject_chain_id` | positive integer | Yes | per-type, evaluation-mechanism-bound | Chain on which the asset pair is evaluated. |
| `stale_cache_fallback_permitted` | boolean | No | per-type, trust-root-mechanism-bound | Defaults to `false`; strict payment deployments MUST NOT set it to `true`. |

### 3.4 Constraint Field Rules

- `attestation_url` MUST use `https`. Non-HTTPS URLs MUST be rejected.
- `attestation_url` MUST NOT resolve to private, loopback, link-local, or other
  forbidden network ranges. Implementations MUST apply SSRF protections.
- `oracle_public_key_id` MUST be non-empty.
- `source_asset_id` and `destination_asset_id` MUST be exact, non-empty
  identifiers. A verifier MUST NOT substitute a symbol or a different chain.
- `source_asset_id` MUST NOT equal `destination_asset_id` for a swap-style
  action unless the verifier explicitly supports that action type.
- `subject_chain_id` MUST be a positive integer.
- `max_attestation_age` MUST be an integer greater than or equal to 1. A missing
  value is malformed; there is no implicit default.
- `stale_cache_fallback_permitted`, when present, MUST be a JSON boolean. Its
  absence means `false`.
- Unknown fields MUST be preserved by parsers according to
  `spec/constraints.md` §3.2. Verifiers MUST NOT let unknown fields weaken the
  required checks above.

## 4. The `environment.price_integrity` Constraint

### Purpose

Require a cryptographically signed, unexpired, asset-bound price-integrity
attestation before an agent may proceed to Layer 3 fulfillment.

The allowed positive verdicts are exactly:

```text
PASS
CAUTION
```

`DANGER`, `BLOCK`, an unknown verdict, or an absent verdict is negative. The
constraint does not convert `CAUTION` into unconditional financial approval;
it only states that the receipt is within the allowed price-integrity set. Any
position sizing or action right-sizing remains a separate policy decision.

### 4.1 Attestation Object Format

The response from `attestation_url` MUST contain, either directly or in a
response-specific data field, a signed `OracleSafetyCheck` v2 object. The
response MAY include unsigned wrapper fields (for example `success`, `data`,
`wellKnown`, `verify`, or `note`), but the verifier MUST extract and verify
the attestation object itself rather than signing the whole HTTP response.

The attestation envelope contains at least:

| Field | Type | Description |
|---|---|---|
| `uid` | bytes32 hex string | Recomputed EIP-712 typed-data hash. |
| `schemaVersion` | integer | MUST be `2`. |
| `attester` | Ethereum address | Recovered EIP-712 signer and registry public key value. |
| `signedAt` | ISO 8601 string | Human-readable signing time. |
| `validForSeconds` | positive integer | Issuer-declared receipt lifetime. |
| `validUntil` | Unix seconds | Convenience copy of signed `data.validUntil`; verifier MUST use the signed value. |
| `signature` | hex EIP-712 signature | Signature over the typed `OracleSafetyCheck` message. |
| `data` | object | The 26 signed `OracleSafetyCheck` v2 fields. |
| `eip712` | object | Published domain/type descriptors for independent verification. |

The signed `data` object contains these 26 fields:

```text
verdict, sourceAssetId, destinationAssetId, subjectChainId, action,
tradeAmountUsd, consensusPrice, maxDeviationBps, manipulationRiskBps,
participantCount, requiredParticipantCount, coverageStatus,
independenceStatus, sourceGroupCount, crossProviderAgreementBps,
maxStablecoinDepegBps, maxDataAgeSeconds, recommendedMaxPositionUsd,
reasonCodesHash, requestHash, evaluationScope, evaluatedAssetIdsHash,
providerObservationsHash, validUntil, checkedAt, schemaVersion
```

Only the `data` object is covered by the EIP-712 typed message. The top-level
`signedAt`, `validForSeconds`, `verifyUrl`, `wellKnown`, and other convenience
fields are not authoritative and MUST NOT override signed values.

The verifier MUST treat the signed `data` values as authoritative for asset
binding, verdict, timestamps, and integrity evidence.

### 4.2 Key Discovery

The verifier MUST derive the issuer origin from the HTTPS origin of
`attestation_url`. It MUST reject a cross-origin redirect and MUST NOT use an
unsigned response field such as `wellKnown` or `issuer` to replace the trust
root. It then fetches the issuer's RFC 8615 document:

```text
{origin(attestation_url)}/.well-known/oracle-keys.json
```

For the Insight reference implementation, the relevant entry has the shape
(the `public_key` is the EIP-712 recovered attester address):

```json
{
  "key_id": "insight-oracle-safety-v2",
  "public_key": "0x...attester-address...",
  "algorithm": "EIP-712/secp256k1"
}
```

The verifier MUST:

1. locate the entry whose `key_id` equals the constraint's
   `oracle_public_key_id`;
2. require the receipt's `attester` to equal the published `public_key`;
3. verify the EIP-712 signature using the published domain and type descriptors;
4. recompute `uid` from the signed typed data and compare it exactly.

A missing, inactive, malformed, or mismatched key MUST fail closed. The
verifier MUST NOT silently trust the attester address supplied by the receipt
without the registry binding.

### 4.3 Validation Algorithm

The following algorithm MUST run before L3 creation. The verifier MUST repeat
it independently at L3 acceptance time.

1. Validate the constraint schema and all required fields.
2. Validate the URL scheme and apply SSRF protections.
3. Fetch the attestation response without treating an HTTP error as a pass.
4. Extract the signed `OracleSafetyCheck` v2 object.
5. Validate `schemaVersion == 2` and required structural fields.
6. Fetch the issuer's key registry and resolve `oracle_public_key_id`.
7. Verify `attester` to registry key binding.
8. Verify the EIP-712 signature.
9. Recompute and compare `uid`.
10. Compare signed `sourceAssetId`, `destinationAssetId`, and
    `subjectChainId` to the constraint's exact values.
11. Reject if the signed `verdict` is not `PASS` or `CAUTION`.
12. Reject if `now >= validUntil`.
13. Reject if `now - data.checkedAt > max_attestation_age`.
14. If every check passes, mark `environment.price_integrity` satisfied.

The agent MUST stop at the first failed `environment.*` member and MUST NOT
create L3. A verifier accepting L3 MUST evaluate every environment member to
completion and record every resulting violation, so a caller can distinguish
missing, expired, tampered, asset-mismatched, and negative receipts.

### 4.4 Output and Diagnostics

A verifier SHOULD include the constraint type in the checked list when it
passes. On failure, the violation SHOULD identify the first applicable reason
and the receipt identifier when available.

Recommended reason codes:

```text
price_integrity_missing
price_integrity_fetch_failed
price_integrity_schema_invalid
price_integrity_key_unavailable
price_integrity_signature_invalid
price_integrity_uid_mismatch
price_integrity_asset_mismatch
price_integrity_chain_mismatch
price_integrity_expired
price_integrity_stale
price_integrity_negative_verdict
```

Reason codes are diagnostic. None of them permits execution after failure.

### 4.5 Example

```json
{
  "type": "environment.price_integrity",
  "attestation_url": "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample",
  "oracle_public_key_id": "insight-oracle-safety-v2",
  "source_asset_id": "eip155:1/slip44:60",
  "destination_asset_id": "eip155:1/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "subject_chain_id": 1,
  "max_attestation_age": 600
}
```

A matching signed receipt with `verdict: "PASS"` satisfies this constraint.
A matching signed receipt with `verdict: "CAUTION"` also satisfies this
constraint, subject to any separate policy that right-sizes the action.

## 5. Validation Algorithm Integration

### 5.1 Integration with `constraints.md`

This constraint follows the common input/output model in
`spec/constraints.md` §5.1–§5.3. The constraint is evaluated against the
external signed attestation and does not change the SD-JWT delegation chain.

### 5.2 Execution Order

`environment.*` checks MUST occur before ordinary checkout and payment
constraint evaluation for L3 creation. If any environment member fails, an
agent MUST halt and MUST NOT create L3. At L3 acceptance, the verifier MUST
complete all environment checks for diagnostic completeness before returning a
rejection.

### 5.3 Strictness Interaction

An implementation MUST NOT use permissive unknown-constraint behavior to turn a
recognized `environment.price_integrity` failure into a pass. An unsupported
or malformed `environment.price_integrity` constraint is rejected. Network,
key-registry, signature, freshness, and negative-verdict failures are all
fail-closed.

### 5.4 Composition with Siblings

The following is a valid composition:

```text
environment.market_state(XNYS == OPEN)
AND environment.price_integrity(AAPL/USD feed == PASS or CAUTION)
AND environment.wallet_state(source wallet condition == pass)
```

All present members MUST pass independently. A market-open receipt does not
prove that a price is trustworthy, and a price-integrity receipt does not prove
that the venue is open.

## 6. Security Considerations

### 6.1 Replay and Staleness

`validUntil` and `max_attestation_age` are independent freshness checks. A
provider's long TTL MUST NOT override the mandate's explicit age bound. A
receipt outside either window MUST fail closed.

### 6.2 Endpoint Substitution and Key Binding

The URL alone is not a trust root. The verifier MUST bind the constraint's
`oracle_public_key_id` and the recovered `attester` to the expected key entry
from the registry at the attestation endpoint's origin. A redirect to a
different issuer or key domain MUST NOT silently change the trust root.

### 6.3 Asset and Chain Substitution

A valid signature over a different asset pair is not a valid receipt for this
constraint. Exact source, destination, and chain comparisons are mandatory.

### 6.4 Oracle Claims Versus Verification

Signature recovery, schema, key binding, and freshness are independently
verifiable properties. Claims such as provider participation, quorum, and
independence remain claims made by the issuer. The receipt makes those claims
attributable and refutable; it does not turn them into a third-party endorsement.

### 6.5 SSRF and Network Failure

Implementations MUST enforce HTTPS and reject private or local network targets.
They MUST apply a strict request timeout, MUST NOT follow more than one redirect,
and MUST reject a redirect that changes the attestation endpoint origin. Any
fetch, parse, key lookup, or verification failure MUST produce a violation, not
a pass. A stale key-cache fallback defaults to disabled.

### 6.6 Key Registry Caching and Rotation

Verifiers MAY cache a successfully fetched key registry and SHOULD respect the
issuer's `Cache-Control` directive. The receipt cache and key-registry cache are
independent. When `stale_cache_fallback_permitted` is absent or `false`, a
fresh key-registry fetch failure MUST produce a violation; verifiers MUST NOT
fall back to a hard-coded key. When the field is `true`, a verifier MAY use an
expired cache only as a last resort after a fresh-fetch failure and only for a
key entry previously fetched from the same attestation endpoint origin. Strict
payment deployments MUST NOT enable this fallback.

If the requested `oracle_public_key_id` is absent from a cached registry, the
verifier MUST refresh the registry once before rejecting the receipt. Issuers
SHOULD publish old and new keys together during rotation for at least the
maximum lifetime of receipts signed by the old key plus the verifier cache TTL.
Key rotation and caching MUST NOT bypass `validUntil` or
`max_attestation_age`.

### 6.7 Provider Neutrality

The type is provider-neutral. The Insight endpoints in §7 are a reference
implementation, not an exclusive issuer and not a bidirectional exclusivity
requirement.

### 6.8 Algorithm and Versioning

For `OracleSafetyCheck` schema version 2, the EIP-712/secp256k1 profile
identified by the published `algorithm` value is mandatory. Verifiers MUST
reject an unknown algorithm, unsupported schema version, or missing type
descriptor; they MUST NOT silently downgrade to another verification method.
A future wire profile MUST use an explicit schema/version identifier and a
published key-registry entry before it can be accepted by conforming verifiers.

## 7. Reference Implementation

### 7.1 Insight

Insight (`https://www.oracleinsight.xyz`) provides:

- `OracleSafetyCheck` v2 with 26 signed EIP-712 fields;
- quorum gate requiring at least 3 participating providers;
- v2.1 independence gate requiring at least 2 distinct non-derived operator
  groups, with TWAP excluded from the independence count;
- 600-second validity window;
- key/schema document:
  `GET https://www.oracleinsight.xyz/.well-known/oracle-keys.json`;
- verification schema and endpoint:
  `GET https://www.oracleinsight.xyz/api/v1/safety/attestation/verify`;
- live signed sample:
  `GET https://www.oracleinsight.xyz/api/v1/safety/attestation/sample`.

For interoperable market-state receipt verification, the companion reference
material supplied with this proposal includes:

- live receipt demo: `https://headlessoracle.com/v5/demo?mic=XCOI`;
- RFC 8615 key registry: `https://headlessoracle.com/.well-known/oracle-keys.json`;
- canonical payload specification: `https://headlessoracle.com/v5/keys`;
- exchange coverage: `https://headlessoracle.com/v5/exchanges`;
- OpenAPI: `https://headlessoracle.com/openapi.json`;
- zero-dependency verifier SDK: `@headlessoracle/verify`;
- SMA receipt format: `https://github.com/LembaGang/sma-protocol`;
- reference verifier: `https://github.com/headlessoracle/demo-agent`;
- pre-trade safety recipe: `https://github.com/LembaGang/agent-pretrade-safety-standard`.

These links are informative interoperability references for the sibling
`environment.market_state` receipt. They do not make this proposal dependent
on Headless Oracle or any other particular provider.

The combined market-state + price-integrity envelope is implemented in the
Insight repository as a prototype. The prototype includes live XCOI receipt
verification and deliberate expired/tampered failure demonstrations. Its
deployment URL is not claimed by this specification until deployed.

### 7.2 Conformance Boundary

This proposal registers the receipt shape and verification obligations. It does
not require the target repository to copy Insight's TypeScript implementation.
SDK and standalone conformance vectors are follow-up integration work after the
working group accepts the normative field names and algorithm boundary.

## 8. Conformance Test Vectors

A conforming implementation SHOULD cover at least these cases:

| Vector | Expected result |
|---|---|
| Matching ETH/USDC receipt, PASS, fresh, valid signature | PASS |
| Matching ETH/USDC receipt, CAUTION, fresh, valid signature | PASS at this constraint layer |
| Receipt verdict DANGER or BLOCK | BLOCK |
| Signed payload modified after signing | BLOCK (`uid_mismatch` or `signature_invalid`) |
| Receipt signed for a different asset pair | BLOCK (`asset_mismatch`) |
| Receipt signed for a different chain | BLOCK (`chain_mismatch`) |
| Receipt outside `validUntil` | BLOCK (`expired`) |
| Receipt older than `max_attestation_age` | BLOCK (`stale`) |
| Key registry unavailable or key id mismatched | BLOCK (`key_unavailable`) |
| Attestation endpoint unavailable | BLOCK (`fetch_failed`) |

No test vector may use a fabricated signature as evidence of a passing path.

## 9. Open Questions

1. Whether the repository should add `environment.price_integrity` to a
   repository-wide registry in `spec/constraints.md` immediately or after the
   standalone sibling proposals stabilize.
2. Whether the family should standardize a common subject-field vocabulary
   across market, price, and wallet attestations while preserving each type's
   wire-specific binding fields.
3. Whether a future SDK release should expose a typed verifier interface for
   all `environment.*` members or keep type-specific verifier modules.

## 10. Changelog

| Version | Date | Change |
|---|---|---|
| 0.2-draft | 2026-08-21 | Initial `environment.price_integrity` sibling proposal, modeled on PR #9 and PR #22; Insight listed as reference implementation. |

## Appendix A: Attestation Test Vectors

A conforming implementation SHOULD include vectors for each of the following
cases. A passing vector MUST use a genuinely signed receipt; a fabricated
signature MUST NOT be used to demonstrate a passing path.

| Vector | Expected result |
|---|---|
| Matching ETH/USDC receipt, `PASS`, fresh, valid signature | Satisfied |
| Matching ETH/USDC receipt, `CAUTION`, fresh, valid signature | Satisfied at this constraint layer |
| Receipt verdict `DANGER` or `BLOCK` | Violated |
| Signed payload modified after signing | Violated (`uid_mismatch` or `signature_invalid`) |
| Receipt signed for a different asset pair | Violated (`asset_mismatch`) |
| Receipt signed for a different chain | Violated (`chain_mismatch`) |
| Receipt outside `validUntil` | Violated (`expired`) |
| Receipt older than `max_attestation_age` | Violated (`stale`) |
| Key registry unavailable or key id mismatched | Violated (`key_unavailable`) |
| Attestation endpoint unavailable | Violated (`fetch_failed`) |

## Appendix B: Failure Mode Quick Reference

| Failure | Required behavior |
|---|---|
| Missing attestation | Fail closed; do not create or accept L3. |
| Network or HTTP error | Fail closed; record `price_integrity_fetch_failed`. |
| Malformed JSON/schema | Fail closed. |
| Key registry unavailable | Fail closed; stale fallback is disabled by default. |
| Key id or attester mismatch | Fail closed. |
| EIP-712 signature or UID failure | Fail closed. |
| Asset or chain mismatch | Fail closed. |
| Expired or stale receipt | Fail closed. |
| `DANGER`, `BLOCK`, or unknown verdict | Fail closed. |

## Appendix C: Register Discipline

### C.1 Normative and descriptive register

Uppercase RFC 2119 keywords in this document are normative. Descriptive
sentences, examples, provider references, and implementation notes are
informative unless they contain an uppercase normative keyword.

### C.2 Rules for the `environment.*` family

1. A verifier MUST treat a missing, malformed, unverifiable, stale, expired, or
   negative price-integrity attestation as a violation.
2. A reference implementation listing MUST NOT be interpreted as provider
   exclusivity or endorsement.
3. Future `environment.*` constraint types MUST declare their field scope,
   subject binding, freshness rule, trust-root mechanism, and failure behavior.
4. Family-wide rules MUST remain portable across different attestation wire
   formats; type-specific rules belong in the relevant sibling document.

### C.3 Relationship to the main specification

This appendix does not replace `spec/constraints.md` §5.3 or the repository-wide
constraint registry. It records the discipline used by this standalone sibling
proposal while the working group decides the final registry and SDK integration.

## Appendix D: Implementation Status

This document captures the status of implementations of the
`environment.price_integrity` constraint.

**Insight** (`https://www.oracleinsight.xyz`) provides the reference
implementation for the attestation surface:

- `OracleSafetyCheck` v2 EIP-712 receipts;
- published schema and verifier endpoints;
- RFC 8615 `.well-known/oracle-keys.json` key discovery;
- quorum and operator-independence gates;
- 600-second receipt validity;
- independent tests for signature recovery, UID binding, freshness, asset
  binding, verdict handling, and fail-closed composition.

The reference implementation listing is informative and does not grant
provider exclusivity or constitute an endorsement. The combined envelope
prototype is implemented in Insight but is not claimed as a deployed public
compliance endpoint by this initial draft. Per RFC 6982 conventions, an
implementation-status appendix is intended as informative draft material and
may be removed by an RFC Editor before final publication.
