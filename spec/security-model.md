# Verifiable Intent — Security Model and Threat Analysis

**Version**: 0.1-draft  
**Status**: Draft  
**Date**: 2026-02-18  
**Authors**: Verifiable Intent Working Group

## Abstract

This document provides a practical security analysis of the Verifiable Intent (VI) layered credential format. It identifies trust boundaries, describes key management requirements, catalogs common attack patterns with their mitigations, and provides an implementation checklist for developers building VI-compatible systems. This document is primarily analytical — it explains *why* the normative rules in the companion specification documents exist and what attacks they prevent.

For the normative credential format, see [credential-format.md](credential-format.md). For constraint type definitions and validation rules, see [constraints.md](constraints.md). For the architecture overview and trust model, see the [Specification Overview](README.md).

### Companion Documents

| Document | Description |
|----------|-------------|
| [Specification Overview](README.md) | Architecture, trust model, design goals |
| [credential-format.md](credential-format.md) | Normative credential format, claim tables, and serialization |
| [constraints.md](constraints.md) | Constraint type definitions and validation rules |
| [security-model.md](security-model.md) | This document |
| [design-rationale.md](design-rationale.md) | Why SD-JWT, relationship to OpenID4VP/FIDO2/SCA, algorithm choice |
| [glossary.md](../protocol-landscape/glossary.md) | Full glossary with protocol-specific mappings |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

This document is primarily analytical. RFC 2119 keywords appear sparingly — only where this document introduces requirements not already covered by companion specifications.

---

## 2. Trust Boundaries

VI's delegation chain creates three trust boundaries. Each boundary represents a point where compromise has distinct consequences and requires distinct defenses.

### 2.1 Layer 1 — Issuer to User

The Issuer (a financial institution or payment network) creates and signs a verifiable credential binding the user's public key via `cnf.jwk`. This credential is then provisioned into a Credential Provider's wallet (e.g., digital wallet provider). This is the root of the entire chain.

**What the Issuer controls**: Which users receive credentials, what identity claims are included (`email`), card identification (`pan_last_four`, `scheme`), and the user's public key binding via `cnf.jwk`.

**Compromise impact**: A compromised Issuer signing key allows issuance of arbitrary L1 credentials for any user. All downstream layers become untrustworthy. This is the highest-impact compromise in VI.

**Blast radius limitation**: L1 credentials have a finite `exp` (RECOMMENDED ~1 year per [credential-format.md](credential-format.md) §7). After key rotation, new credentials are signed with the new key. Outstanding L1s remain valid until expiry. VI v0.1 does not define its own credential revocation protocol (see §6.1), but Issuers — as payment networks or financial institutions — retain independent transaction-level controls (card cancellation, account freezes, real-time fraud screening) that can neutralize a compromised L1 regardless of its `exp`.

### 2.2 Layer 2 — User to Agent

The user creates a KB-SD-JWT or KB-SD-JWT+KB containing mandates with constraints (Autonomous mode) or final values (Immediate mode). In Autonomous mode, the checkout mandate and payment mandate each include `cnf.jwk` (with an embedded `kid`) binding the agent's public key, delegating authority to act within specified limits.

**What the user controls**: Which agent key is authorized, what products may be purchased (`mandate.checkout.line_items`), spending limits (`mandate.payment.amount_range`, `mandate.payment.budget`), allowed merchants (`mandate.checkout.allowed_merchants`, `mandate.payment.allowed_payees`), recurrence terms (`mandate.payment.recurrence`, `mandate.payment.agent_recurrence`), and all other constraint types defined in [constraints.md](constraints.md) §4.

**Compromise impact**: A compromised user key allows creation of arbitrary L2 mandates — any agent could be delegated any authority, up to the limits of the L1 credential. The attacker effectively becomes the user.

**Blast radius limitation**: Autonomous L2 lifetime MUST NOT exceed L1 `exp`; RECOMMENDED range 24h–30d for consumer use cases ([credential-format.md](credential-format.md) §7). Immediate L2 lifetime is RECOMMENDED ~15 minutes. However, an attacker with the user's private key can mint new L2 credentials that bind an attacker-controlled agent key via `cnf.jwk`, then produce valid L3 credentials with that key. This means user key compromise is full account takeover for the lifetime of the L1 credential — the attacker does not need any existing agent's private key.

### 2.3 Layer 3 — Agent to Merchant

The agent creates KB-SD-JWTs (L3a and L3b) proving it holds the key delegated in L2 and presenting the fulfillment details (specific checkout and payment parameters).

**What the agent controls**: Product selection (within `mandate.checkout.line_items` constraints), timing of purchase, which merchant to approach (within `mandate.checkout.allowed_merchants` / `mandate.payment.allowed_payees` constraints).

**Compromise impact**: A compromised agent key allows the attacker to create L3 credentials within the constraints of the existing L2. The attacker cannot exceed the delegated authority.

**Blast radius limitation**: L3 lifetime is RECOMMENDED ~5 minutes ([credential-format.md](credential-format.md) §7). This is the shortest-lived credential in the chain, limiting the window for replay or misuse.

### 2.4 What VI Does Not Protect

VI provides **authorization verification** — cryptographic proof that an agent acted within delegated authority. It does not provide:

- **Transport security** — VI credentials travel over application-layer protocols; TLS or equivalent is assumed but not specified.
- **User authentication** — VI binds a key, not a person. Biometric/PIN verification of the key holder is an implementation concern and varies by deployment model (see §3.5).
- **Agent behavioral attestation** — A constrained agent that operates within its limits but leaks timing data, browsing patterns, or user intent through side channels is not detectable by VI. The `agent_attestation` extension point ([README.md](README.md) §9.2) is reserved for future behavioral attestation schemes.
- **Dispute resolution** — VI provides cryptographic evidence that facilitates dispute resolution (see §2.5) but does not define the dispute choreography — chargeback routing, liability assignment, and arbitration are payment-network-specific concerns.

### 2.5 Dispute Evidence

VI's layered delegation chain produces a self-contained evidence package that any dispute investigator can independently verify. When a transaction is disputed, the full credential chain (L1, L2, and — in Autonomous mode — L3) can be presented using the full-chain verification pattern described in the [Specification Overview](README.md) §10.4.

**Evidence provided by the VI chain**:

| Evidence Element | Source Layer | What It Proves |
|-----------------|-------------|----------------|
| Issuer signature | L1 | The user's identity was vouched for by a known issuer (bank/network) |
| User key signature (L1 `cnf.jwk`) | L2 | The user explicitly authorized this delegation |
| Constraint bindings | L2 mandates | The exact authority the user granted (line items, amount range, allowed merchants, payees) |
| Agent key signature | L3 | The specific agent that executed the transaction |
| `checkout_hash` / `transaction_id` | L3a/L3b payment/checkout mandates | The payment authorization was bound to a specific checkout via cross-reference |
| `conditional_transaction_id` | L2 payment mandate | The L2 checkout and payment mandates were bound at delegation time (Autonomous mode) |
| Timestamps (`iat`, `exp`) | All layers | When each credential was issued and its validity window |
| `nonce` / `aud` | L2, L3 | The credential was issued for a specific transaction context and recipient |

**Verification procedure**: A dispute investigator receives all layers of the credential chain and performs the same verification steps defined in the [Specification Overview](README.md) §5.3 — signature verification at each layer, `cnf.jwk` chain validation, constraint checking against fulfillment values, and checkout-payment integrity verification. If all checks pass, the investigator has cryptographic proof that the agent acted within the authority delegated by the user.

**What VI does NOT provide for disputes**: VI does not define how disputes are initiated, routed between parties, escalated, or resolved. It does not assign liability, specify chargeback codes, or prescribe arbitration procedures. These are payment-network-specific concerns that vary by jurisdiction, card network rules, and merchant agreements. VI's contribution is strictly evidentiary — it provides tamper-evident, independently verifiable evidence of the delegation chain and the constraints under which a transaction was authorized.

---

## 3. Key Management

Key management is the most critical implementation concern for VI deployments. The delegation chain is only as strong as the weakest key in the chain.

### 3.1 JWKS Endpoint Security

Verifiers resolve the Issuer's public key via the `iss` claim and `kid` header ([credential-format.md](credential-format.md) §3.2). The JWKS endpoint is the root of trust for all L1 verification.

**Risks**:
- DNS hijacking or BGP manipulation could redirect verifiers to a rogue JWKS endpoint serving an attacker's public key, causing acceptance of forged L1 credentials.
- A compromised CDN serving the JWKS endpoint has the same effect.
- If the endpoint goes down, verifiers cannot validate any L1 credentials.

**Recommendations**:
- JWKS endpoints SHOULD be served over TLS with certificate pinning where feasible.
- Verifiers SHOULD cache JWKS responses with a TTL no longer than 24 hours to survive transient outages without accepting stale keys indefinitely.
- Issuers SHOULD monitor their JWKS endpoints for unauthorized key additions.

### 3.2 Key Rotation

When an Issuer rotates its signing key, a race condition exists: L1 credentials signed with the old key remain valid until `exp`, but if the old key is removed from the JWKS endpoint prematurely, verifiers will reject valid credentials.

**Recommendations**:
- Issuers MUST maintain retired signing keys in their JWKS endpoint for at least the maximum L1 `exp` duration after rotation.
- Each L1 MUST include a `kid` header to enable unambiguous key lookup ([credential-format.md](credential-format.md) §3.2).
- In the event of key compromise, removing the key from JWKS is the VI-layer revocation mechanism: it invalidates all outstanding L1 credentials signed with that key, favoring safety over availability. Issuers may additionally leverage their existing infrastructure controls (card-level blocks, account suspension, network-level decline rules) to mitigate exposure while key rotation proceeds.

### 3.3 Agent Key Provisioning

VI binds an agent key via the L2 mandate's `cnf.jwk` but does not specify how that key is generated, communicated to the user's L2 construction environment, or stored. This provisioning step is a critical trust boundary: if the user's system binds an attacker's key instead of the legitimate agent's key, the attacker gains delegated authority.

**Recommendations**:
- Agent platforms SHOULD generate key pairs inside a Trusted Execution Environment (TEE) or hardware security module where available.
- The agent's public key SHOULD be communicated to the user's L2 construction system through an authenticated channel (e.g., a signed agent platform manifest).
- Agent platforms SHOULD generate fresh key pairs per delegation session to limit the impact of key compromise. The reference implementation uses fixed deterministic keys suitable only for testing.

> **Terminal delegation**: L3 credentials MUST NOT contain a `cnf` claim in the payload. The agent proves key possession via the header `kid` parameter, which verifiers resolve against L2 `cnf.jwk` (matching against the embedded `kid`). This prevents agents from sub-delegating authority to unauthorized third parties — the delegation chain terminates at L3.

### 3.4 User Key Management

The user's private key signs L2 mandates and is the authority for all delegations. Its compromise is equivalent to full account takeover within VI.

**Recommendations**:
- In on-device deployments, user keys SHOULD be generated and stored in a platform Secure Enclave or equivalent hardware-backed keystore.
- L2 construction implementations SHOULD require user confirmation before signing L2 mandates (e.g., biometric or PIN for on-device deployments, authenticated session for server-custodial deployments).
- User keys SHOULD NOT be exportable or backed up in plaintext.

### 3.5 Deployment Models

The user's private key may be managed in several deployment configurations, each with different security properties:

**On-device model.** The user's private key is generated and stored in the device's Secure Enclave or hardware-backed keystore. L2 construction happens entirely on the user's device. This model provides the strongest key isolation guarantees — the private key never leaves hardware-protected storage. Signing requires biometric or PIN authentication.

**Server-custodial model.** A commerce platform or agent service holds the user's private key in a server-side HSM or KMS. L2 construction happens server-side when the user authorizes a purchase through the platform's interface. This model simplifies deployment (no client-side cryptographic libraries required) but requires trust in the platform's key management. The platform MUST authenticate the user before signing L2 mandates on their behalf.

**Hybrid model.** The private key remains on the user's device (Secure Enclave), but L2 construction is orchestrated by a server. The server assembles the mandate payload, sends it to the user's device for signing, and receives the signed KB-SD-JWT. This model combines on-device key isolation with server-side mandate assembly.

The VI credential format and verification procedures are identical across all three models. The delegation chain (L1 `cnf.jwk` → L2 signature → L2 mandate `cnf.jwk` → L3 signature) works the same way regardless of where the private key is stored or where L2 is assembled. Verifiers cannot and need not distinguish between deployment models.

---

## 4. Common Attack Patterns

This section describes attacks that implementers should understand and test against. For each attack: what happens, how VI defends against it, and what verifiers must check.

### 4.1 Credential Replay

**Attack**: An attacker captures a valid L3 credential and re-presents it to the same or different merchant.

**Defense**: The `nonce` claim binds the credential to a specific transaction context. The `aud` claim binds it to a specific merchant. Short L3 lifetime (~5 minutes) limits the replay window. See the [Specification Overview](README.md) §11 (Security Considerations).

**What verifiers must check**: Verify `nonce` has not been seen before within the credential's validity window. Verify `aud` matches the verifier's own identity. Verify `exp` has not passed (with clock skew tolerance per [credential-format.md](credential-format.md) §7).

### 4.2 Cross-Merchant Replay and Budget Enforcement

**Attack**: In the base model, each L2 mandate pair (checkout + payment) is expected to produce exactly one L3a + L3b pair (see [credential-format.md](credential-format.md) §8.2). When `mandate.payment.agent_recurrence` is present, multiple L3 pairs are explicitly authorized within bounds. However, without stateful tracking, a compromised agent could generate excessive L3 pairs, either violating the one-per-pair rule (base model) or exceeding the bounds (multi-transaction model).

**Why per-L3 defenses are insufficient**:

| Existing Defense | Why It Doesn't Help |
|------------------|---------------------|
| `nonce` uniqueness | Prevents replay of the *same* L3, not generation of *new* L3s from the same mandate pair |
| `aud` binding | The agent controls the L3 `aud` value; it is not constrained by L2 |
| Short L3 lifetime | Limits the replay window for a single L3 but not sequential generation of new ones |
| `sd_hash` binding | Prevents L2 substitution, not creation of multiple L3s referencing the same L2 |
| `mandate.payment.amount_range` | Checked per-L3, not accumulated across L3s from the same mandate pair |

**Defense**: Transaction count and budget enforcement cannot be done cryptographically within VI alone — they require stateful tracking by the payment network.

**What payment networks must enforce**:

Payment networks MUST track L3a issuance and cumulative spend against each L2 mandate pair. The L3a `sd_hash` binds a particular selective presentation of L2, not a presentation-independent accounting identity. For example, selecting a different allowed merchant changes the merchant disclosure and therefore the L3a `sd_hash`, even when the payment mandate and its cumulative budget are unchanged.

After verifying the credential chain and its presentation binding, the network MUST resolve the presented payment mandate to the same authenticated accounting record for that issued L2 mandate pair, regardless of which allowed merchant is disclosed. It MUST NOT use the L3a `sd_hash` alone as the key for cumulative spend or occurrence counts. A new presentation, nonce, or agent signature MUST NOT create a fresh allowance for the same mandate pair.

The mapping to an accounting record is network-managed state; this specification does not define a new wire identifier or a canonical hash construction for it. The mapping MUST be based on verified authority, not an untrusted caller-supplied identifier. Networks MUST distinguish separate mandate pairs within an L2, and MUST define whether reissuance or renewal continues an existing allowance or creates a separately authorized allowance. If a network cannot establish the required association, it MUST reject an authorization that depends on that accounting state.

When a payment network receives an L3a for authorization, it MUST:

1. Verify the L3a presentation binding, then look up the authenticated accounting record for its L2 mandate pair as described above.
2. Determine the transaction model:
   - **Base model** (no `mandate.payment.agent_recurrence`): Verify the mandate pair has not been fulfilled. Reject if already used.
   - **Multi-transaction model** (`mandate.payment.agent_recurrence` present): Check occurrence count and cumulative budget.
3. For multi-transaction mandates, extract and enforce:
   - `mandate.payment.agent_recurrence.max_occurrences` (if present): Reject if occurrence count would exceed this
   - `mandate.payment.budget.max`: Reject if `prior_total + this_L3a.amount > budget.max`
   - Date range (`start_date` to `end_date`): Reject if current date outside range
4. Verify per-transaction `mandate.payment.amount_range` constraint: `min <= this_L3a.amount <= max`
5. Record the authorized amount and increment occurrence count.

> **Note**: This requirement applies only to Autonomous mode, where L3 credentials are generated by an agent without real-time user confirmation. In Immediate mode, the user directly confirms each transaction, providing a natural transaction-count bound.

### 4.3 Constraint Stripping

**Attack**: An attacker modifies an L2 mandate to remove or weaken constraints (e.g., raising the budget limit or removing merchant restrictions), expanding the agent's delegated authority.

**Defense**: The L2 KB-SD-JWT or KB-SD-JWT+KB signature covers the entire payload including all mandates and their constraints. Any modification invalidates the signature. See [constraints.md](constraints.md) §7.5.

**What verifiers must check**: Verify the L2 signature before inspecting constraint values. A valid signature guarantees the constraints are the ones the user originally set.

### 4.4 Checkout-Payment Mismatch

**Attack**: An agent creates a valid payment authorization but pairs it with a different checkout — for example, authorizing payment for an expensive item while the checkout contains a cheap substitute (or vice versa).

**Defense**: The `checkout_hash` / `transaction_id` mechanism creates a SHA-256 binding between checkout and payment mandates by hashing the `checkout_jwt` string. The checkout mandate carries this hash as `checkout_hash` and the payment mandate carries it as `transaction_id`. In Autonomous mode, the cross-reference between L3a (`transaction_id`) and L3b (`checkout_hash`) ensures the split credentials refer to the same transaction. See [credential-format.md](credential-format.md) §6.2.

**What verifiers must check**: Recompute the hash as `B64U(SHA-256(ASCII(checkout_jwt)))` and verify it matches `checkout_hash` on the checkout mandate and `transaction_id` on the payment mandate. In Autonomous mode, verify that L3a `transaction_id` equals L3b `checkout_hash`.

### 4.5 Algorithm Confusion

**Attack**: A common JWT vulnerability where the attacker changes the `alg` header to `none` (disabling signature verification) or to `HS256` (tricking the verifier into using the public key as an HMAC secret).

**Defense**: VI requires ES256 with P-256 exclusively. The reference implementation hardcodes ECDSA P-256 rather than selecting algorithms from the JWT header.

**What verifiers must check**: Reject any JWT with an `alg` value other than `ES256`. Do not use general-purpose JWT libraries in their default configuration — explicitly whitelist `ES256` only.

### 4.6 Clock Skew Exploitation

**Attack**: An attacker exploits the clock skew tolerance (RECOMMENDED 300 seconds per [credential-format.md](credential-format.md) §7) to use expired credentials. For an L3 with a 5-minute lifetime, a 300-second tolerance effectively triples the usable window.

**Defense**: The skew tolerance is a RECOMMENDED value, not a fixed requirement. Implementers can choose tighter tolerances based on their deployment's clock synchronization guarantees.

**What verifiers must check**: Enforce `exp` and `iat` checks at every layer. High-security deployments SHOULD use tighter clock skew (e.g., 60 seconds) and require NTP synchronization.

### 4.7 Disclosure Withholding

**Attack**: An attacker presents a subset of disclosures to a verifier — for example, disclosing the checkout mandate but withholding the payment mandate, or disclosing identity claims while hiding constraint mandates.

**Defense**: The `delegate_payload` structure reveals disclosure hashes for all mandates, so verifiers can detect that undisclosed mandates exist. In the split L3 architecture, each L3 carries only the disclosures relevant to its audience, providing a natural disclosure boundary.

**What verifiers must check**: Inspect `delegate_payload` to determine the expected number of mandates. Require disclosure of all mandates relevant to the transaction context. In Autonomous mode, the payment network receives L3a (payment + merchant disclosures) and the merchant receives L3b (checkout disclosures).

### 4.8 Type Confusion

**Attack**: A verifier uses positional indexing in `delegate_payload` to identify mandate types (e.g., "first = checkout, second = payment"). An attacker reorders mandates to cause the verifier to apply checkout validation rules to a payment mandate or vice versa.

**Defense**: Each mandate includes a `vct` (Verifiable Credential Type) claim that explicitly identifies its type. See [credential-format.md](credential-format.md) §10.

**What verifiers must check**: Always identify mandate types by `vct` value, never by position. Reject mandates with missing or unrecognized `vct` values.

Additionally, each credential layer uses a `typ` header to signal its role in the delegation chain: L1 uses `sd+jwt`, L2 uses `kb-sd-jwt` (Immediate) or `kb-sd-jwt+kb` (Autonomous), and L3 uses `kb-sd-jwt`. An attacker who presents a credential with an unexpected `typ` (e.g., submitting an L3 as if it were an L2) may bypass layer-specific validation logic. Verifiers MUST validate the `typ` header at each layer against expected values, in addition to checking `vct` on mandates.

### 4.9 Split-Agent Attack

**Attack**: Different agent keys are bound in the checkout and payment mandates of the same L2, allowing two different agents to independently control checkout selection and payment authorization.

**Defense**: The `cnf.jwk` in both mandates MUST be identical. See [credential-format.md](credential-format.md) §4.6.

**What verifiers must check**: Compare `cnf.jwk` across all mandates in the same L2. If they differ, reject the credential.

---

## 5. Implementation Checklist

A concrete list of security-relevant implementation requirements. Use this as a review checklist when building or auditing a VI implementation.

### 5.1 Cryptographic Requirements

- [ ] Use ES256 (ECDSA with P-256) exclusively. Reject all other `alg` values.
- [ ] Generate disclosure salts with at least 128 bits of cryptographic randomness (per [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)).
- [ ] Use base64url encoding without padding ([RFC 4648] §5). SHOULD reject padded input during verification to prevent canonicalization mismatches.
- [ ] Normalize ECDSA signatures to low-S form, or accept both `(r, s)` and `(r, n-s)` consistently. ECDSA has a known malleability where both forms are valid.
- [ ] Reject JSON payloads with duplicate claim names. Different parsers handle duplicates differently (first-wins vs. last-wins), which can cause divergent verification results.

### 5.2 Verification Requirements

- [ ] Verify signatures at every layer before inspecting claims.
- [ ] For production verification, always supply the Issuer public key (or JWKS-resolved key) so L1 signature verification is enforced. Signature-skip modes are test-only.
- [ ] Check `exp` and `iat` at every layer with consistent clock skew tolerance.
- [ ] Verify `sd_hash` binds each layer to its parent ([credential-format.md](credential-format.md) §6.1).
- [ ] Verify `cnf` chain: L1 binds user key, L2 checkout and payment mandates bind agent key via `cnf.jwk` with embedded `kid` (Autonomous). L3 header `kid` matches L2 `cnf.jwk.kid`; verifiers resolve the agent's public key from L2 `cnf.jwk`.
- [ ] Verify `cnf` is identical across all L2 mandates (checkout and payment): `cnf.jwk` (including its embedded `kid`) must match. Reject if they differ (split-agent attack — see §4.9, [credential-format.md](credential-format.md) §4.6).
- [ ] Identify mandates by `vct`, never by position in `delegate_payload`.
- [ ] Verify `checkout_hash` (on checkout mandate) and `transaction_id` (on payment mandate) when both mandates are disclosed ([credential-format.md](credential-format.md) §6.2). In Autonomous mode, verify `transaction_id == checkout_hash` cross-reference between L3a and L3b.
- [ ] Check L2 constraints against L3 fulfillment values using the validation algorithm in [constraints.md](constraints.md) §5.
- [ ] Implement nonce deduplication with a sliding window at least as long as the maximum L3 lifetime plus clock skew tolerance.
- [ ] Enforce transaction model rules (see §4.2):
  - **Base model**: Track fulfilled mandate pairs per L2; reject duplicate L3s for the same pair
  - **Multi-transaction model** (`mandate.payment.agent_recurrence` present): Track occurrence count, cumulative spend, and date range; enforce `max_occurrences`, `mandate.payment.budget.max`, and temporal bounds

### 5.3 Key Management Requirements

- [ ] Cache JWKS responses with TTL ≤ 24 hours. Handle endpoint unavailability gracefully.
- [ ] Maintain retired Issuer keys in JWKS for at least the maximum L1 lifetime after rotation — except for compromised keys, which MUST be removed immediately (see §3.2).
- [ ] Use hardware-backed key storage for user keys and agent keys where available (see §3.5).
- [ ] Do not use deterministic or fixed keys outside of testing environments.

### 5.4 Hash Computation

- [ ] Compute `checkout_hash` / `transaction_id` as `B64U(SHA-256(ASCII(checkout_jwt)))` — a simple SHA-256 of the checkout JWT string. No JCS canonicalization or salt is required. Checkout mandates carry this value as `checkout_hash`; payment mandates carry it as `transaction_id`.
- [ ] In Autonomous mode, verify that L3a `transaction_id` equals L3b `checkout_hash` — this cross-reference binds the split L3 credentials to the same transaction.
- [ ] Verify `conditional_transaction_id` in L2 `mandate.payment.reference` constraint matches the hash of the checkout disclosure string.

---

## 6. Known Limitations

The following are known gaps in VI v0.1. They are documented here for transparency and to guide future work.

### 6.1 Revocation

VI v0.1 does not define a credential-layer revocation protocol. However, multiple mitigations operate at different levels:

**Built-in mitigations**:
- **Layered lifetimes**: L3 ~5 minutes, L2 Immediate ~15 minutes, L2 Autonomous MUST NOT exceed L1 `exp` (RECOMMENDED 24h–30d for consumer use cases), L1 ~1 year. The shortest-lived credentials (where compromise is most likely) expire fastest.
- **JWKS key removal**: For L1 signing key compromise, the Issuer SHOULD remove the key from its JWKS endpoint, which invalidates all credentials signed with that key.

**Payment network mitigations**: L1 validity enables the VI delegation chain but does not bypass normal payment authorization. Issuers — as payment networks or financial institutions — retain their existing real-time controls: card-level cancellation, account suspension, fraud screening, and network-level decline rules. These mechanisms can prevent transactions against a compromised L1 independently of VI credential status.

**Viable mechanisms for future VI versions**:

- **Token Status List ([RFC 9701])** — A lightweight, JWT-native mechanism for publishing credential status. The Issuer maintains a compressed bitstring where each position corresponds to a credential; verifiers fetch the status list by reference and check the relevant bit. Well-suited to VI because it operates within the existing JWT ecosystem.
- **Short-lived credentials with refresh** — Issues L1 credentials with short lifetimes (hours to days) and refreshes them automatically. This increases issuance load on the Issuer but reduces the revocation window significantly.
- **Certificate Revocation Lists (CRLs) / OCSP** — Established PKI mechanisms that could be adapted for VI. CRLs publish a list of revoked credential identifiers; OCSP provides real-time status queries. These carry heavier infrastructure requirements but are well-understood and widely deployed.

**Interim guidance**: Issuers SHOULD document their JWKS key rotation schedule and publish rotation procedures. Deployments that require tighter VI-layer control over L1 validity SHOULD use shorter L1 lifetimes (hours to days rather than ~1 year).

**Roadmap**: A future version of VI will define credential status signaling as a standard mechanism. Implementers are encouraged to prototype with the approaches listed above to inform the design.

### 6.2 `sub` Claim Linkability

The `sub` claim in L1 is always visible (not selectively disclosable) and persists for the credential's lifetime (~1 year). A verifier receiving multiple transactions can link them to the same user via `sub`. The payment network always sees `payment_instrument`. Future versions should consider pairwise pseudonymous identifiers.

### 6.3 Constrained but Malicious Agents

VI verifies that an agent operated *within* its constraints. It does not verify *how* the agent behaved — an agent that stays within budget and buys the right products can still leak user intent data through timing, browsing patterns, or side channels. The `agent_attestation` extension point ([README.md](README.md) §9.2) is reserved for future behavioral attestation schemes, but v0.1 provides no mechanism to detect agent misbehavior within authorized bounds.

### 6.4 Open-Ended Recurrence

The `mandate.payment.recurrence` and `mandate.payment.agent_recurrence` constraints define recurring payment terms. For `mandate.payment.recurrence` (merchant-managed subscriptions), a constraint with `frequency` but no `end_date` or `number` authorizes indefinite recurring charges. For `mandate.payment.agent_recurrence` (agent-managed recurring purchases), the `end_date` field is REQUIRED, preventing open-ended authorization.

L2 construction implementations SHOULD set explicit bounds (`end_date` and/or `number`) on `mandate.payment.recurrence` constraints to prevent indefinite subscriptions. Verifiers SHOULD warn when these fields are absent, but v0.1 does not enforce this as a hard requirement.

### 6.5 PERMISSIVE Mode Default

The default strictness mode for constraint validation is PERMISSIVE, which silently skips unknown constraint types ([constraints.md](constraints.md) §5.4). This means a constraint type introduced in a future version will be ignored by current verifiers. Payment networks processing autonomous transactions SHOULD use STRICT mode to avoid this gap.

### 6.6 Checkout Object Verification

In v0.1, `checkout_jwt` structure and signing details are implementation-defined (see [credential-format.md §6.3](credential-format.md#63-checkout_jwt-checkout-object-representation)). The normative integrity mechanism is the `checkout_hash` / `transaction_id` binding: both fields MUST equal `B64U(SHA-256(ASCII(checkout_jwt)))` for the same checkout JWT string. Implementers SHOULD verify the merchant's signature on `checkout_jwt` where possible. A future version of VI will define a normative `checkout_jwt` schema and make signature verification a MUST-level requirement.

### 6.7 L2 Lifetime Considerations

Autonomous L2 lifetime MUST NOT exceed L1 `exp`. Within that bound, implementations
SHOULD select the shortest duration appropriate for the use case. The following
factors guide lifetime selection:

1. **Consumer awareness.** Users may not track the exact expiration of delegated
   authority. A RECOMMENDED default of 30 days for consumer use cases aligns
   with common billing cycle expectations while limiting exposure.

2. **Use-case-appropriate duration.** One-time delegated purchases (e.g., "buy
   this racket") warrant 24–72 hours. Price-watching agents monitoring deals
   may need up to 30 days. Subscription setup (`mandate.payment.recurrence`) should
   match the billing cycle. Implementations SHOULD document their default
   lifetime and the rationale.

3. **TOCTOU window reduction.** The interval between L2 issuance and L3
   fulfillment is a Time-of-Check-to-Time-of-Use gap: user intent may change,
   products may become unavailable, or prices may shift. Shorter L2 lifetimes
   reduce this window.

4. **Key compromise blast radius.** If the agent's private key is compromised,
   the attacker can create valid L3 credentials until the L2 expires. Shorter
   L2 lifetimes bound the attacker's window of opportunity.

5. **Revocation lag backstop.** VI v0.1 does not define credential-layer
   revocation (see §6.1). L2 expiration is the primary mechanism for
   time-bounding delegated authority in the absence of revocation.

---

## 7. References

### Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.

- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.

- **[RFC 7515]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web
  Signature (JWS)", RFC 7515, May 2015.

- **[RFC 7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.

- **[RFC 7518]** Jones, M., "JSON Web Algorithms (JWA)", RFC 7518,
  May 2015.

- **[RFC 7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web
  Token (JWT)", RFC 7519, May 2015.

- **[RFC 7800]** Jones, M., Bradley, J., and H. Tschofenig, "Proof-of-
  Possession Key Semantics for JSON Web Tokens (JWTs)", RFC 7800,
  April 2016.

- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in
  RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

- **[RFC 8259]** Bray, T., "The JavaScript Object Notation (JSON) Data
  Interchange Format", RFC 8259, December 2017.

- **[FIPS 180-4]** National Institute of Standards and Technology, "Secure
  Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

- **[RFC 9901]** Fett, D., Yasuda, K., and B. Campbell, "Selective Disclosure
  for JSON Web Tokens (SD-JWT)", RFC 9901, November 2025.

- **[README.md]** Verifiable Intent Working Group, "Verifiable Intent —
  Specification Overview", Version 0.1-draft, 2026.

- **[credential-format.md]** Verifiable Intent Working Group, "Verifiable
  Intent — Credential Format Specification", Version 0.1-draft, 2026.

- **[constraints.md]** Verifiable Intent Working Group, "Verifiable Intent —
  Constraint Type Definitions and Validation Rules", Version 0.1-draft,
  2026.

### Informative References

- **[RFC 9701]** Looker, T. and P. Grassi, "Token Status List",
  RFC 9701, November 2025.

- **[NIST SP 800-57]** Barker, E., "Recommendation for Key Management",
  NIST Special Publication 800-57 Part 1 Revision 5, May 2020.
