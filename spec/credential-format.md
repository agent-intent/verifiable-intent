# Verifiable Intent (VI) — Credential Format Specification

**Version**: 0.1-draft
**Status**: Draft
**Date**: 2026-02-18
**Authors**: Verifiable Intent Working Group

## Abstract

This document specifies the normative credential format, claim tables, and
serialization rules for the Verifiable Intent (VI) layered credential system.
For architecture overview and trust model, see [README.md](README.md). For
constraint type definitions and validation rules, see [constraints.md](constraints.md).

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

- JSON structures are represented in JSON [RFC 8259] notation.
- Base64url encoding refers to the encoding defined in [RFC 4648], Section 5,
  without padding characters.
- `B64U(x)` denotes the base64url encoding of the byte string `x`.
- `SHA-256(x)` denotes the SHA-256 hash [FIPS 180-4] of the byte string `x`.
- `ASCII(x)` denotes the ASCII encoding of the string `x`.
- SD-JWT notation follows [RFC 9901].

---

## 2. Overview of Credential Layers

VI uses three credential layers, each building on the previous through
cryptographic key binding:

| Layer | Type | Signed By | Lifetime | Purpose |
|-------|------|-----------|----------|---------|
| L1 | SD-JWT (`sd+jwt`) | Issuer | ~1 year | Binds user identity and public key |
| L2 Immediate | KB-SD-JWT (`kb-sd-jwt`) | User Public Key | ~15 minutes | Final transaction values |
| L2 Autonomous | KB-SD-JWT+KB (`kb-sd-jwt+kb`) | User Public Key | 24 hours – 30 days | Constraints + agent key binding |
| L3a | KB-SD-JWT (`kb-sd-jwt`) | Agent Key | ~5 minutes | Final payment values for network |
| L3b | KB-SD-JWT (`kb-sd-jwt`) | Agent Key | ~5 minutes | Final checkout values for merchant |

**`typ` values by mode:**

| Layer / Mode | `typ` Value | Rationale |
|--------------|-------------|-----------|
| L1 | `"sd+jwt"` | Standard SD-JWT root credential. |
| L2 Immediate | `"kb-sd-jwt"` | Standard KB-SD-JWT — no further key binding. |
| L2 Autonomous | `"kb-sd-jwt+kb"` | Signals that this KB-SD-JWT delegates to another key (the agent's) via mandate `cnf` claims. |
| L3a, L3b | `"kb-sd-jwt"` | Terminal KB-SD-JWT — no further delegation permitted. |

---

## 3. Layer 1 — Credential Provider SD-JWT

### 3.1 Overview

Layer 1 is the foundation of the VI credential chain. It is issued and signed by the
**Issuer** (a financial institution or payment network) and provisioned into a
**Credential Provider's** wallet (e.g., a digital wallet provider). The Issuer signs
the L1 SD-JWT, binding the user's identity to a public key. The Credential Provider
hosts and presents the credential on the user's behalf.

L1 does **not** contain an `sd_hash` claim — it is the root of the delegation chain.

### 3.2 JWT Header

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `alg` | string | REQUIRED | Signing algorithm. MUST be `"ES256"`. |
| `typ` | string | REQUIRED | MUST be `"sd+jwt"`. |
| `kid` | string | REQUIRED | Key identifier for the Issuer's signing key. Used to resolve the correct key from the Issuer's JWKS endpoint. |

### 3.3 JWT Payload — Always-Visible Claims

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | REQUIRED | Issuer identifier URI. Identifies the financial institution or payment network that signed the L1. MUST be a stable, dereferenceable URI. |
| `sub` | string | REQUIRED | Subject identifier. An opaque, stable identifier for the user within the Issuer's system. |
| `iat` | integer | REQUIRED | Issued-at time (Unix timestamp). |
| `exp` | integer | REQUIRED | Expiration time (Unix timestamp). SHOULD be set to no more than 1 year from `iat`. |
| `vct` | string | REQUIRED | Verifiable Credential Type URI. An opaque type identifier per [RFC 9901] §3.2.2.2 — not required to be a dereferenceable endpoint. Identifies the credential profile and its expected claim schema. Implementations using the Mastercard reference profile MUST use `"https://credentials.mastercard.com/card"`. See §10 for the VCT Registry. MUST be an always-visible claim (not selectively disclosable). |
| `cnf` | object | REQUIRED | Confirmation claim per [RFC 7800]. MUST contain `cnf.jwk` with the user's public key as a JWK. |
| `pan_last_four` | string | REQUIRED | Last four digits of the card PAN. Always visible to enable card identification without disclosing the full PAN. |
| `scheme` | string | REQUIRED | Card network scheme identifier (e.g., `"mastercard"`, `"visa"`). Always visible. |
| `card_id` | string | OPTIONAL | Opaque card-level identifier assigned by the Issuer. Always visible when present. Enables card-level tracking across credential reissuance without exposing the full PAN. |
| `_sd_alg` | string | REQUIRED | Hash algorithm for selective disclosures. MUST be `"sha-256"`. |
| `_sd` | array | REQUIRED | Array of SD-JWT disclosure hashes for selectively disclosable claims. |

> **Profile-specific claims:** The claims `pan_last_four`, `scheme`, and `card_id` are defined by the Mastercard reference profile (`vct: "https://credentials.mastercard.com/card"`). Other credential profiles MAY define different required and optional claims appropriate to their payment instrument type. The structural claims (`iss`, `sub`, `iat`, `exp`, `vct`, `cnf`, `_sd_alg`, `_sd`) are required regardless of profile.

### 3.4 JWT Payload — Selectively Disclosable Claims

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | OPTIONAL | User's email address. Selectively disclosable. Disclosed only when needed for user identity verification. |

### 3.5 Processing Rules

1. The Issuer MUST sign L1 using ES256 with a key published in its JWKS endpoint.
2. Verifiers MUST resolve the Issuer's public key using the `kid` header parameter against the Issuer's JWKS endpoint.
3. Verifiers MUST verify the ES256 signature over the L1 JWT.
4. Verifiers MUST reject L1 credentials with `exp` in the past (subject to clock skew tolerance of 300 seconds).
5. Verifiers MUST reject L1 credentials where `vct` is absent or not a well-formed URI.
6. L1 MUST NOT contain an `sd_hash` claim.

### 3.6 Example L1 Payload (Decoded)

```json
{
  "iss": "https://issuer.mastercard.com",
  "sub": "user-8a3f9c21",
  "iat": 1700000000,
  "exp": 1731536000,
  "vct": "https://credentials.mastercard.com/card",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  },
  "pan_last_four": "1234",
  "scheme": "mastercard",
  "card_id": "card-mc-8842",
  "_sd_alg": "sha-256",
  "_sd": ["<hash-of-email-disclosure>"]
}
```

---

## 4. Layer 2 — User KB-SD-JWT / KB-SD-JWT+KB

### 4.1 Overview

Layer 2 is created and signed by the user (or an authorized system holding the
user's private key) using the key bound in L1 `cnf.jwk`. It expresses the user's
purchase intent either as final values (Immediate mode) or as constraints for
agent delegation (Autonomous mode).

L2 contains an `sd_hash` binding it to the serialized L1.

### 4.2 JWT Header

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `alg` | string | REQUIRED | MUST be `"ES256"`. |
| `typ` | string | REQUIRED | MUST be `"kb-sd-jwt"` (Immediate mode) or `"kb-sd-jwt+kb"` (Autonomous mode). |
| `kid` | string | REQUIRED | User's key identifier from the corresponding L1 cnf.jwk.kid. Verifiers resolve the L2 signing key directly from L1 cnf.jwk.|


### 4.3 JWT Payload — Always-Visible Claims

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `nonce` | string | REQUIRED | Cryptographically random nonce. Prevents replay attacks. |
| `iss` | string | REQUIRED | Credential Provider identifier URI. Identifies the wallet or credential provider that signed the L2. MUST be a stable, dereferenceable URI. |
| `aud` | string | REQUIRED | Intended audience URI. MUST identify the agent or verifier. |
| `iat` | integer | REQUIRED | Issued-at time (Unix timestamp). |
| `exp` | integer | REQUIRED | Expiration time. Immediate mode: SHOULD be no more than 15 minutes from `iat`. Autonomous mode: SHOULD be no more than 30 days from `iat`; SHOULD use the shortest duration appropriate for the use case. |
| `sd_hash` | string | REQUIRED | Base64url-encoded SHA-256 hash of the serialized L1 SD-JWT string: `B64U(SHA-256(ASCII(serialized_L1)))`. |
| `delegate_payload` | array | REQUIRED | Array of SD-JWT disclosure references (`{"...": "<hash>"}`) pointing to the selectively disclosable mandate claims. |
| `_sd_alg` | string | REQUIRED | MUST be `"sha-256"`. |
| `_sd` | array | REQUIRED | Array of SD-JWT disclosure hashes for selectively disclosable claims. |

### 4.4 Immediate Mode — Mandate Claims

#### 4.4.1 Immediate Checkout Mandate (`vct: "mandate.checkout"`)

The checkout mandate describes what is being purchased. In Immediate mode, the
user has already confirmed the final checkout contents.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.checkout"`. |
| `checkout_jwt` | string | REQUIRED | Merchant-signed JWT representing the finalized checkout contents. |
| `checkout_hash` | string | REQUIRED | `B64U(SHA-256(ASCII(checkout_jwt)))`. Binds the checkout mandate to the payment mandate. MUST equal `transaction_id` in the corresponding payment mandate. |

**MUST NOT contain:**
- `cnf` claim (no delegation in Immediate mode)
- `constraints` array (values are final)

#### 4.4.2 Immediate Payment Mandate (`vct: "mandate.payment"`)

The payment mandate describes how the purchase is funded. In Immediate mode,
all values are final and confirmed by the user.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.payment"`. |
| `payment_instrument` | object | REQUIRED | Payment instrument descriptor. See `payment_instrument` object structure below. |
| `currency` | string | REQUIRED | ISO 4217 currency code (e.g., `"USD"`). |
| `amount` | integer | REQUIRED | Transaction amount as an integer in minor units per ISO 4217 (e.g., `27999` = $279.99). |
| `payee` | object | REQUIRED | Merchant/payee descriptor. See `payee` object structure below. |
| `transaction_id` | string | REQUIRED | MUST equal `checkout_hash` from the corresponding checkout mandate: `B64U(SHA-256(ASCII(checkout_jwt)))`. |

**`payment_instrument` object structure:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | Instrument type identifier (e.g., `"mastercard.srcDigitalCard"`). |
| `id` | string | REQUIRED | Instrument instance identifier (e.g., a token UUID). |
| `description` | string | OPTIONAL | Human-readable descriptor (e.g., `"Mastercard **** 1234"`). |

**`payee` object structure:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | OPTIONAL | Merchant identifier. When present, used as the primary key for payee matching in constraint validation. |
| `name` | string | REQUIRED | Merchant display name. |
| `website` | string | REQUIRED | Merchant URL. Used for merchant identification when `id` is absent. |

**MUST NOT contain:**
- `cnf` claim (no delegation in Immediate mode)
- `constraints` array (values are final)

### 4.5 Autonomous Mode — Mandate Claims

#### 4.5.1 Autonomous Checkout Mandate (`vct: "mandate.checkout.open"`)

The checkout mandate in Autonomous mode contains constraints on what the agent
is permitted to purchase, and binds the agent's key for L3 delegation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.checkout.open"`. |
| `cnf` | object | REQUIRED | Confirmation claim containing `cnf.jwk` with the agent's public key and `cnf.kid` with a key identifier. Structure identical to L1 `cnf` (see §3.3) plus `kid`. MUST match the `cnf` in the payment mandate of the same mandate pair. |
| `constraints` | array | REQUIRED | Array of constraint objects bounding the agent's purchasing authority. MUST contain at least one constraint. See [constraints.md](constraints.md) for registered types. |
| `prompt_summary` | string | OPTIONAL | Human-readable description of the user's delegated intent. |

**Nested selective disclosures (Autonomous mode):**

Individual entries within `allowed_merchants` and `line_items` constraints are
themselves selectively disclosable. Each entry is a separate SD-JWT disclosure,
referenced by hash from the constraint object. This allows the agent to disclose
only the selected merchant or items to the verifier.

#### 4.5.2 Autonomous Payment Mandate (`vct: "mandate.payment.open"`)

The payment mandate in Autonomous mode contains constraints on payment parameters
and binds the agent's key for L3 delegation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.payment.open"`. |
| `cnf` | object | REQUIRED | Confirmation claim containing `cnf.jwk` with the agent's public key and `cnf.kid` with a key identifier. MUST match the `cnf` in the checkout mandate of the same mandate pair. |
| `payment_instrument` | object | REQUIRED | Payment instrument descriptor. See §4.4.2 for structure. |
| `constraints` | array | REQUIRED | Array of constraint objects bounding the agent's payment authority. MUST contain at least one constraint. |
| `risk_data` | object | OPTIONAL | A map of relevant risk signals collected by the credential provider at time of mandate creation |

> **Note**: Recurrence terms (subscription setup, agent-managed recurring purchases) are
> expressed as constraint types (`payment.recurrence`, `payment.agent_recurrence`) within
> the `constraints` array. See [constraints.md](constraints.md) §4.6 and §4.7 for schemas.

#### 4.5.3 Payment Reference Constraint (`payment.reference`)

The Autonomous payment mandate MUST include a `payment.reference` constraint
with a `conditional_transaction_id` that binds the payment mandate to its
corresponding checkout mandate at the L2 disclosure level:

```json
{
  "type": "payment.reference",
  "conditional_transaction_id": "<hash-of-checkout-mandate-disclosure>"
}
```

The `conditional_transaction_id` is the disclosure hash of the checkout mandate —
the same hash that appears in the L2 `delegate_payload` array referencing the
checkout mandate disclosure. Computed as `B64U(SHA-256(ASCII(checkout_disclosure_b64)))`.
See [constraints.md §4.8](constraints.md#48-paymentreference--checkout-payment-cross-reference) for the full definition and validation algorithm.

> **Distinction from `checkout_hash`/`transaction_id`:** The `conditional_transaction_id`
> operates at the L2 disclosure level (binding payment mandate to checkout mandate
> within the L2 SD-JWT structure). In contrast, `checkout_hash` and `transaction_id`
> operate at the L3 level, computed as `B64U(SHA-256(ASCII(checkout_jwt)))` to bind
> L3a and L3b to the same merchant checkout session. These are fundamentally different
> values serving different binding purposes.

> **Note**: Constraint type definitions, value schemas, and machine-enforceability
> designations for all registered `mandate.checkout.*` and `payment.*` types are
> specified in [constraints.md](constraints.md). Machine-enforceable constraints
> (amount range, allowed payee, merchant, line items) MUST be verified by verifiers;
> descriptive fields (product description, brand, color, size) are informational
> and not subject to automated verification.

### 4.6 `cnf` Claim Presence Rules

Mode is inferred from VCT values in L2 mandates: open VCTs (`mandate.checkout.open`, `mandate.payment.open`) indicate Autonomous mode; final VCTs (`mandate.checkout`, `mandate.payment`) indicate Immediate mode. The `cnf` presence rules below are then enforced as structural requirements consistent with the inferred mode:

| Layer / Mode | `cnf` Claim | Requirement |
|-------------|------------|-------------|
| L2 Immediate mandates | Absent | MUST NOT contain `cnf`. No delegation occurs; the user directly confirms final values. |
| L2 Autonomous mandates | Present | MUST contain `cnf.jwk` with the agent's public key and `cnf.kid` with a key identifier. Both checkout and payment mandates in a pair MUST contain identical `cnf` values (`jwk` and `kid`). |
| L3 payloads (all) | Absent | MUST NOT contain `cnf`. Terminal delegation — no further key binding is permitted. The agent proves key possession via the `kid` header parameter, which verifiers resolve against L2 `cnf.kid` and `cnf.jwk`. |

### 4.7 Processing Rules — L2 Verification

1. Verifiers MUST verify the ES256 signature on L2 against the key in L1 `cnf.jwk`.
2. Verifiers MUST verify `sd_hash` equals `B64U(SHA-256(ASCII(serialized_L1)))`.
3. Verifiers MUST check L2 `typ` header:
   - `"kb-sd-jwt"` for Immediate mode
   - `"kb-sd-jwt+kb"` for Autonomous mode
4. Verifiers MUST reject L2 credentials with `exp` in the past (clock skew tolerance: 300 seconds recommended). Verifiers MUST also reject L2 where `iat` exceeds current time + clock skew tolerance.
5. In Immediate mode: verifiers MUST reject any L2 mandate containing a `cnf` claim.
6. In Autonomous mode: verifiers MUST reject any L2 mandate missing a `cnf.jwk` claim.
7. Verifiers MUST reject L2 credentials containing orphaned mandates (a checkout with no matching payment or vice versa).
8. Verifiers MUST reject L2 credentials with duplicate mandates sharing the same pair identifier.

---

## 5. Layer 3 — Agent KB-SD-JWTs (Autonomous Mode Only)

### 5.1 Overview

Layer 3 is created and signed by the agent using the key bound in L2 mandate
`cnf.jwk`. In Autonomous mode, the agent produces two separate KB-SD-JWT
credentials:

- **L3a** (payment mandate) — presented to the payment network
- **L3b** (checkout mandate) — presented to the merchant

Each L3 includes a selective `sd_hash` binding it to the L2 base JWT plus the
disclosures relevant to that L3's recipient. Neither L3 credential contains a `cnf`
claim (terminal delegation — no further key binding is permitted).

### 5.2 JWT Header (L3a and L3b)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `alg` | string | REQUIRED | MUST be `"ES256"`. |
| `typ` | string | REQUIRED | MUST be `"kb-sd-jwt"`. |
| `kid` | string | REQUIRED | Key identifier. MUST match `cnf.kid` in the Layer 2 mandates. Verifiers resolve the agent's public key from L2 `cnf.jwk` by matching this `kid` value, rather than trusting a self-asserted key in the L3 header. |

### 5.3 JWT Payload — Always-Visible Claims (L3a and L3b)

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `nonce` | string | REQUIRED | Cryptographically random nonce. MUST be distinct from the L2 nonce. |
| `aud` | string | REQUIRED | Intended audience URI. L3a: payment network URI. L3b: merchant URI. |
| `iat` | integer | REQUIRED | Issued-at time (Unix timestamp). |
| `exp` | integer | REQUIRED | Expiration time. RECOMMENDED: 5 minutes from `iat`. MUST NOT exceed 1 hour from `iat`. |
| `sd_hash` | string | REQUIRED | Selective `sd_hash` binding to L2. See §5.4. |
| `delegate_payload` | array | REQUIRED | Array of SD-JWT disclosure references pointing to the selectively disclosable mandate claims. |
| `_sd_alg` | string | REQUIRED | MUST be `"sha-256"`. |
| `_sd` | array | REQUIRED | Array of SD-JWT disclosure hashes for selectively disclosable claims. |

### 5.4 Selective `sd_hash` for L3

Layer 3 `sd_hash` binds each credential to a recipient-specific view of L2.
The agent constructs each recipient-specific L2 presentation using
`build_selective_presentation()` before hashing:

- **L3a `sd_hash`**: `B64U(SHA-256(ASCII(L2_base_jwt + "~" + payment_disclosure + "~" + merchant_disclosure + "~")))` — binds to the L2 presentation containing the payment mandate and merchant disclosures.
- **L3b `sd_hash`**: `B64U(SHA-256(ASCII(L2_base_jwt + "~" + checkout_disclosure + "~" + item_disclosure + "~")))` — binds to the L2 presentation containing the checkout mandate and item disclosures.

This selective binding preserves the privacy boundary: L3a does not require
checkout disclosures, and L3b does not require payment disclosures. Verifiers
recompute `sd_hash` using the same selective approach per L3 type.

### 5.5 Final Checkout Mandate — L3b (`vct: "mandate.checkout"`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.checkout"`. |
| `checkout_jwt` | string | REQUIRED | Merchant-signed JWT representing the finalized checkout. See §6.3 for `checkout_jwt` schema guidance. |
| `checkout_hash` | string | REQUIRED | `B64U(SHA-256(ASCII(checkout_jwt)))`. MUST equal `transaction_id` in L3a. |
| `line_items` | array | OPTIONAL | Array of purchased line items as selected from L2 constraints. |
| `prompt_summary` | string | OPTIONAL | Human-readable summary of the agent's purchase selection. |

**MUST NOT contain:**
- `cnf` claim (no further delegation from the agent)
- `constraints` array (values are final)

### 5.6 Final Payment Mandate — L3a (`vct: "mandate.payment"`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vct` | string | REQUIRED | MUST be `"mandate.payment"`. |
| `payment_instrument` | object | REQUIRED | Payment instrument descriptor. See §4.4.2 for structure. |
| `payment_amount` | object | REQUIRED | Transaction amount object containing `currency` (ISO 4217 code, e.g., `"USD"`) and `amount` (integer minor units per ISO 4217, e.g., `27999` = $279.99). MUST satisfy the `payment.amount` constraint range from L2. |
| `payee` | object | REQUIRED | Merchant/payee descriptor. See §4.4.2 for `payee` object structure. |
| `transaction_id` | string | REQUIRED | MUST equal `checkout_hash` in L3b: `B64U(SHA-256(ASCII(checkout_jwt)))`. |
| `selected_merchant` | object | OPTIONAL | Selectively disclosable. The selected merchant, disclosed from the L2 `allowed_merchant` constraint. |

**MUST NOT contain:**
- `cnf` claim (no further delegation from the agent — terminal delegation)
- `constraints` array (values are final)

> **Amount format note:** Monetary amounts are represented as a `payment_amount`
> object containing `currency` (ISO 4217 code) and `amount` (integer minor
> units per ISO 4217), ensuring consistent format throughout the delegation chain.

### 5.7 Processing Rules — L3 Verification

1. Verifiers MUST resolve the agent's public key from L2 mandate `cnf.jwk` by matching the L3 header `kid` against L2 `cnf.kid`.
2. Verifiers MUST verify the ES256 signature on L3 against the resolved key from L2 `cnf.jwk`.
3. Verifiers MUST verify L3 `typ` header is `"kb-sd-jwt"`.
4. Verifiers MUST verify L3 `sd_hash` against the selective L2 presentation (see §5.4).
5. Verifiers MUST reject any L3 payload containing a `cnf` claim.
6. Verifiers MUST reject L3 credentials with `exp` in the past (clock skew tolerance: 300 seconds recommended). Verifiers MUST also reject L3 where `iat` exceeds current time + clock skew tolerance.
7. Verifiers MUST verify that L3 final values satisfy all disclosed L2 constraints. Machine-enforceable constraints MUST be verified; descriptive fields are informational.
8. Payment networks MUST enforce one L3a + L3b pair per L2 mandate pair (see [security-model.md §4.2](security-model.md#42-cross-merchant-replay)).
9. Payment networks MUST track cumulative L3 spend per L2 and reject L3s that exceed L2 spending constraints.
10. When both L3a and L3b are available: verifiers MUST verify `L3a.transaction_id == L3b.checkout_hash`.

---

## 6. Hash Binding Mechanisms

### 6.1 `sd_hash` Computation

`sd_hash` binds each layer to the serialized form of the previous layer,
preventing substitution or tampering.

1. Layer 2 `sd_hash` MUST equal
   `B64U(SHA-256(ASCII(serialized_L1)))`, where `serialized_L1` is the complete
   SD-JWT string as received (base JWT + `~` + disclosures + trailing `~`).

   > **Note on partial disclosure**: The L2 signer computes `sd_hash` over the 
   > L1 presentation they actually received. This may include only a subset of 
   > L1's selectively disclosable claims — the L2 signer cannot and need not 
   > hash claims that were never disclosed to them. The principle: `sd_hash` 
   > binds to "the serialized form as received by the signer," not "all possible 
   > L1 disclosures that exist."

3. Layer 3 `sd_hash` MUST equal
   `B64U(SHA-256(ASCII(layer2_selective_presentation)))`, where
   `layer2_selective_presentation` includes only the disclosures intended for
   that Layer 3's recipient (see §5.4):
   - L3a's `sd_hash` binds to the L2 presentation containing the payment
     mandate disclosures.
   - L3b's `sd_hash` binds to the L2 presentation containing the checkout
     mandate disclosures.
   - The agent constructs each recipient-specific L2 view using
     `build_selective_presentation()` before hashing.

### 6.2 `checkout_hash` / `transaction_id` Binding

The `checkout_hash` / `transaction_id` mechanism binds checkout and payment
mandates to the same transaction:

```
hash = B64U(SHA-256(ASCII(checkout_jwt)))
```

- Checkout mandates carry this value as `checkout_hash`.
- Payment mandates carry the same value as `transaction_id`.

In Autonomous mode:
- L3b `checkout_hash` and L3a `transaction_id` MUST be equal.
- The L2 payment mandate carries a `payment.reference` constraint with
  `conditional_transaction_id` as a pre-commitment before the checkout JWT exists.

Verifiers MUST recompute the hash from the disclosed `checkout_jwt` and compare
it to both `checkout_hash` and `transaction_id`. Any mismatch MUST cause rejection.

### 6.3 `checkout_jwt` — Checkout Object Representation

The `checkout_jwt` field in a checkout mandate carries the merchant's representation
of the shopping checkout contents. In v0.1, the schema, signing algorithm, and
verification procedure for `checkout_jwt` are **implementation-defined**.

**SHOULD-level guidance:**

1. `checkout_jwt` SHOULD be signed as a JWS ([RFC 7515]) using the merchant's
   private key, with the merchant's public key discoverable via a published JWKS
   endpoint.
2. The `checkout_jwt` payload SHOULD include: item identifiers (e.g., SKUs),
   quantities, unit prices, currency, and a merchant identifier.
3. Verifiers that have access to the merchant's public key SHOULD verify the
   `checkout_jwt` signature before accepting the checkout mandate.

**Conditional requirement — `allowed_merchant` enforcement:**

When the L2 checkout mandate contains an `allowed_merchant` constraint, the `checkout_jwt` payload MUST include a machine-readable merchant identifier (`id` field matching the merchant object schema). Without it, verifiers cannot populate `fulfillment.merchant` and the allowlist constraint cannot be enforced. Implementations that issue `allowed_merchant` constraints MUST ensure their `checkout_jwt` schema provides this field.

**Practical role in Immediate mode:** In Immediate mode, the agent creates the `checkout_jwt` representing the cart contents during the checkout interaction. The merchant has the opportunity to record the checkout session details at this point. When L2 is later presented to the merchant with the checkout mandate disclosed, the merchant validates the `checkout_jwt` contents against its own catalog and checkout records — confirming that the items, quantities, and prices represent a valid order. If the `checkout_jwt` is merchant-signed (per the SHOULD guidance above), the merchant can also verify its own signature for additional integrity assurance. The user's L2 signature proves they authorized this specific checkout. See the [Specification Overview §7](README.md#7-credential-lifecycle) for the full Immediate mode flow.

In Autonomous mode, the same validation applies at L3b: the agent creates a `checkout_jwt` and embeds it in the L3b checkout mandate, which is presented to the merchant for content validation against its records.

**Relationship to `checkout_hash` / `transaction_id`:** The binding (§6.2) is normative in v0.1 — `checkout_hash` (on checkout mandates) and `transaction_id` (on payment mandates) cryptographically bind both mandates to the same `checkout_jwt`. Unlike v1's `cartHash` (which bound to the mandate object), these fields bind directly to the `checkout_jwt` content, providing a tighter integrity guarantee.

**Roadmap:** A future version of VI will define: (a) normative `checkout_jwt` JWT envelope requirements (required headers/claims, signing algorithm) while remaining agnostic to the checkout content schema, (b) merchant key discovery via JWKS, and (c) `checkout_jwt` signature verification as a MUST-level requirement.

---

## 7. Credential Lifetime

| Credential | Recommended Lifetime | Maximum Lifetime | Notes |
|------------|---------------------|-----------------|-------|
| Layer 1 | 1 year | 1 year | Long-lived root credential. |
| Layer 2 (Immediate) | 15 minutes | 15 minutes | User-present confirmation; short-lived. |
| Layer 2 (Autonomous) | 24 hours – 30 days | MUST NOT exceed L1 `exp` | RECOMMENDED default: 30 days for consumer use cases. Use the shortest duration appropriate for the use case. A one-time delegated purchase may need only 24 hours; a price-watching agent may need 30 days. When an autonomous mandate expires before the agent fulfills it, the implementation SHOULD prompt the user to re-authorize. Implementations SHOULD prefer the shortest duration that satisfies the use case. |
| Layer 3a, L3b | 5 minutes | 1 hour | Short-lived to limit replay window. RECOMMENDED: 5 minutes. |

---

## 8. Mandate Pairing

### 8.1 Mandate Pair Definition

Each L2 credential contains one or more **mandate pairs** — each pair consisting
of exactly one checkout mandate and one payment mandate, linked by a pair identifier:

- **Immediate mode**: pair identifier is `checkout_hash` (present on both mandates as
  `checkout_hash` and `transaction_id`).
- **Autonomous mode**: pair identifier is `conditional_transaction_id` in the
  `payment.reference` constraint of the payment mandate.

V0.1 supports multiple mandate pairs within a single L2, enabling multi-merchant
purchases (each pair targets a different merchant). **Split-tender** — where a
single checkout is funded by multiple payment instruments — requires cross-chain
coordination between mandate pairs and will be addressed in a future version.

### 8.2 Pairing Rules

Implementations MUST group checkout and payment mandates into pairs by matching
their pair identifier. The pairing algorithm works as follows:

- **Immediate mode**: For each checkout mandate, compute
  `B64U(SHA-256(ASCII(checkout_jwt)))`. The payment mandate whose
  `transaction_id` equals this hash is the pair partner.
- **Autonomous mode**: For each payment mandate, extract
  `conditional_transaction_id` from its `payment.reference` constraint. The
  checkout mandate whose disclosure hash equals this value is the pair partner.

Verifiers MUST:

1. Reject L2 credentials containing orphaned mandates (a checkout with no matching
   payment, or vice versa).
2. Reject L2 credentials with duplicate mandates sharing the same pair identifier.
3. In Autonomous mode, enforce one L3a + L3b pair per L2 mandate pair.

### 8.3 Multi-Transaction Extension (Planned)

In v0.1, one mandate pair always maps to exactly one L3 pair. A planned extension
for **multi-transaction mandate pairs** will allow a single mandate pair to authorize
multiple L3 fulfillments within defined bounds (e.g., transaction count cap,
cumulative spend cap, validity window).

---

## 9. Selective Disclosure Structure

### 9.1 `delegate_payload` Structure

Mandates are delivered as selectively disclosable entries within the
`delegate_payload` array. Each entry is a disclosure reference:

```json
{
  "delegate_payload": [
    {"...": "<hash-of-checkout-mandate-disclosure>"},
    {"...": "<hash-of-payment-mandate-disclosure>"}
  ]
}
```

The actual mandate objects are carried in SD-JWT disclosures and are not visible
in the base JWT payload. Verifiers reconstruct the mandate objects from the
provided disclosures.

### 9.2 Nested Disclosures (Autonomous Mode)

In Autonomous mode, individual entries within `allowed_merchants` and `line_items`
constraints are themselves selectively disclosable. Each entry is a separate
SD-JWT disclosure, referenced by hash from the constraint object. This allows the
agent to disclose only the selected merchant or items to each verifier.

---

## 10. VCT Registry

The following VCT values are defined for VI v0.1:

| VCT Value | Description |
|-----------|-------------|
| `https://credentials.mastercard.com/card` | L1 payment credential (Mastercard reference profile) |
| `mandate.checkout.open` | Checkout mandate — open/unfulfilled (L2 Autonomous) |
| `mandate.checkout` | Checkout mandate — final (L2 Immediate, L3b) |
| `mandate.payment.open` | Payment mandate — open/unfulfilled (L2 Autonomous) |
| `mandate.payment` | Payment mandate — final (L2 Immediate, L3a) |

Implementations MUST reject mandates with unrecognized or malformed VCT values.

> **Note:** VCT values are opaque type identifiers per [RFC 9901] §3.2.2.2. They uniquely identify a credential type but are not required to be dereferenceable URLs. The L1 VCT (`https://credentials.mastercard.com/card`) is the Mastercard reference profile identifier; actual credential providers define and publish their own VCT URIs.

---

## 11. Examples

### 11.1 Immediate Mode — Full Example

#### L2 Immediate KB-SD-JWT (Decoded Payload)

```json
{
  "nonce": "a3f9c21b8e4d7f2a",
  "aud": "https://network.mastercard.com/vi/authorize",
  "iat": 1700100000,
  "exp": 1700100900,
  "sd_hash": "B64U(SHA-256(serialized_L1))",
  "_sd_alg": "sha-256",
  "_sd": [
    "<hash-of-checkout-mandate-disclosure>",
    "<hash-of-payment-mandate-disclosure>"
  ],
  "delegate_payload": [
    {"...": "<hash-of-checkout-mandate-disclosure>"},
    {"...": "<hash-of-payment-mandate-disclosure>"}
  ]
}
```

#### Checkout Mandate Disclosure (Immediate)

```json
{
  "vct": "mandate.checkout",
  "checkout_jwt": "<merchant-signed-jwt>",
  "checkout_hash": "abc123def456..."
}
```

#### Payment Mandate Disclosure (Immediate)

```json
{
  "vct": "mandate.payment",
  "payment_instrument": {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234"
  },
  "currency": "USD",
  "amount": 27999,
  "payee": {
    "name": "AudioShop Inc.",
    "website": "https://audioshop.example.com"
  },
  "transaction_id": "abc123def456..."
}
```

### 11.2 Autonomous Mode — Full Example

#### L2 Autonomous KB-SD-JWT+KB (Decoded Payload)

```json
{
  "nonce": "b7e2f4a9c1d3e8b2",
  "aud": "https://network.mastercard.com/vi/authorize",
  "iat": 1700100000,
  "exp": 1700186400,
  "_sd_alg": "sha-256",
  "sd_hash": "B64U(SHA-256(serialized_L1))",
  "_sd": [
    "<hash-of-checkout-constraint-mandate-disclosure>",
    "<hash-of-payment-constraint-mandate-disclosure>"
  ],
  "delegate_payload": [
    {"...": "<hash-of-checkout-constraint-mandate-disclosure>"},
    {"...": "<hash-of-payment-constraint-mandate-disclosure>"}
  ]
}
```

#### Checkout Constraint Mandate Disclosure (Autonomous L2)

```json
{
  "vct": "mandate.checkout.open",
  "cnf": {
    "kid": "agent-key-1",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "agent-public-key-x-component",
      "y": "agent-public-key-y-component"
    }
  },
  "constraints": [
    {
      "type": "mandate.checkout.allowed_merchant",
      "allowed_merchants": [
        {"...": "<hash-of-audioshop-disclosure>"},
        {"...": "<hash-of-soundstore-disclosure>"}
      ]
    },
    {
      "type": "mandate.checkout.line_items",
      "items": [
        {"...": "<hash-of-headphones-item-disclosure>"}
      ]
    }
  ],
  "prompt_summary": "Buy wireless headphones under $300 from approved merchants"
}
```

#### Payment Constraint Mandate Disclosure (Autonomous L2)

```json
{
  "vct": "mandate.payment.open",
  "cnf": {
    "kid": "agent-key-1",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "agent-public-key-x-component",
      "y": "agent-public-key-y-component"
    }
  },
  "payment_instrument": {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234"
  },
  "constraints": [
    {
      "type": "payment.amount",
      "currency": "USD",
      "min": 0,
      "max": 30000
    },
    {
      "type": "payment.allowed_payee",
      "allowed_payees": [
        { "name": "AudioShop Inc.", "website": "https://audioshop.example.com" },
        { "name": "SoundStore", "website": "https://soundstore.example.com" }
      ]
    },
    {
      "type": "payment.reference",
      "conditional_transaction_id": "checkout-ref-9f3a2b1c"
    }
  ]
}
```

#### L3a — Final Payment Mandate (Autonomous, to payment network)

JWT header:
```json
{
  "alg": "ES256",
  "typ": "kb-sd-jwt",
  "kid": "agent-key-1"
}
```

JWT payload (always-visible):
```json
{
  "nonce": "c9d1e2f3a4b5c6d7",
  "aud": "https://network.mastercard.com/vi/authorize",
  "iat": 1700200000,
  "exp": 1700200300,
  "sd_hash": "B64U(SHA-256(L2_base+payment_disclosure+merchant_disclosure))",
  "_sd_alg": "sha-256",
  "_sd": [
    "<hash-of-payment-mandate-disclosure>",
    "<hash-of-selected-merchant-disclosure>"
  ],
  "delegate_payload": [
    {"...": "<hash-of-payment-mandate-disclosure>"},
    {"...": "<hash-of-selected-merchant-disclosure>"}
  ]
}
```

Payment mandate disclosure (L3a):
```json
{
  "vct": "mandate.payment",
  "payment_instrument": {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234"
  },
  "currency": "USD",
  "amount": 27999,
  "payee": {
    "name": "AudioShop Inc.",
    "website": "https://audioshop.example.com"
  },
  "transaction_id": "abc123def456..."
}
```

#### L3b — Final Checkout Mandate (Autonomous, to merchant)

JWT header:
```json
{
  "alg": "ES256",
  "typ": "kb-sd-jwt",
  "kid": "agent-key-1"
}
```

JWT payload (always-visible):
```json
{
  "nonce": "d8e2f4a5b6c7d8e9",
  "aud": "https://audioshop.example.com/checkout",
  "iat": 1700200000,
  "exp": 1700200300,
  "sd_hash": "B64U(SHA-256(L2_base+checkout_disclosure+item_disclosure))",
  "_sd_alg": "sha-256",
  "_sd": [
    "<hash-of-checkout-mandate-disclosure>",
    "<hash-of-selected-items-disclosure>"
  ],
  "delegate_payload": [
    {"...": "<hash-of-checkout-mandate-disclosure>"},
    {"...": "<hash-of-selected-items-disclosure>"}
  ]
}
```

Checkout mandate disclosure (L3b):
```json
{
  "vct": "mandate.checkout",
  "checkout_jwt": "<merchant-signed-jwt>",
  "checkout_hash": "abc123def456...",
  "line_items": [
    {
      "sku": "WH-1000XM5",
      "name": "Sony WH-1000XM5 Wireless Headphones",
      "quantity": 1,
      "unit_price": 27999,
      "currency": "USD"
    }
  ]
}
```

---

## 12. Algorithm Requirements

Implementations MUST support ES256 (ECDSA using the P-256 curve and SHA-256)
as defined in [RFC 7518] Section 3.4. The `_sd_alg` claim MUST be `"sha-256"`.

Future versions of this specification MAY define additional algorithms
(e.g., EdDSA with Ed25519).

---

## 13. Conformance Summary

### 13.1 Issuer (L1) Conformance

A conformant Issuer implementation:

1. MUST set `alg` header to `"ES256"` and `typ` header to `"sd+jwt"`.
2. MUST include `cnf.jwk` containing the user's public key.
3. MUST include `vct` as an always-visible (non-selectively-disclosable) claim.
   Implementations using the Mastercard reference profile MUST use
   `"https://credentials.mastercard.com/card"`.
4. MUST include all always-visible claims required by the credential's VCT profile. For the Mastercard reference profile, this means `pan_last_four` and `scheme` as REQUIRED always-visible claims, and `card_id` as an OPTIONAL always-visible claim.
5. MUST support selective disclosure for `email` and other identity claims.
6. MUST publish a JWKS endpoint for verifier key discovery.
7. MUST NOT include `sd_hash` in L1 (root credential).
8. SHOULD set L1 `exp` to no more than 1 year from `iat`.

### 13.2 L2 Construction Conformance

A conformant L2 construction implementation:

1. MUST sign L2 with the key bound in L1 `cnf.jwk`.
2. MUST compute `sd_hash` as `B64U(SHA-256(ASCII(serialized_L1)))`.
3. MUST set `typ` to `"kb-sd-jwt"` (Immediate) or `"kb-sd-jwt+kb"` (Autonomous).
4. In Immediate mode: mandates MUST contain final values and MUST NOT contain `cnf` claims.
5. In Autonomous mode: mandates MUST contain `cnf.jwk` binding the agent's key and `cnf.kid` with the key identifier, and MUST contain at least one constraint.
6. In Immediate mode: MUST compute `checkout_hash` and include it in the checkout mandate and as `transaction_id` in the payment mandate.
7. In Autonomous mode: MUST include a `payment.reference` constraint with `conditional_transaction_id` in the payment mandate.
8. MUST use VCT values exactly as defined in the VCT Registry (§10).

### 13.3 Agent (L3) Conformance

A conformant Agent implementation:

1. MUST create two KB-SD-JWTs (L3a, L3b) signed by the key bound in L2 mandate `cnf.jwk`.
2. MUST set `typ` to `"kb-sd-jwt"` in both L3a and L3b.
3. MUST include a `kid` parameter in each L3 JWT header matching L2 `cnf.kid`. MUST NOT include a `jwk` parameter in L3 headers.
4. MUST NOT include a `cnf` claim in L3 payloads.
5. MUST compute selective `sd_hash` for each L3 per §5.4.
6. MUST represent `amount` as an integer in minor units in L3a final mandates.
7. MUST produce final values satisfying all L2 constraints.
8. MUST ensure `L3a.transaction_id == L3b.checkout_hash`.
9. RECOMMENDED: set L3 `exp` to 5 minutes from `iat`. MUST NOT exceed 1 hour.

### 13.4 Verifier Conformance

A conformant Verifier implementation:

1. MUST verify ES256 signatures at every layer.
2. In production: MUST verify L1 against the Issuer's JWKS-resolved key. Skipping L1 signature verification is acceptable only in controlled test environments.
3. MUST verify `typ` headers at each layer per §2.
4. MUST verify the delegation chain (L1 `cnf` → L2 signer; L2 mandate `cnf` → L3 signer).
5. MUST verify `sd_hash` bindings between adjacent layers.
6. MUST check `exp` at all layers (clock skew tolerance: 300 seconds recommended).
7. In Autonomous mode: MUST resolve the agent's public key from L2 mandate `cnf.jwk` by matching L3 header `kid` against L2 `cnf.kid`. MUST NOT trust a self-asserted `jwk` in L3 headers.
8. In Autonomous mode: MUST reject any L3 payload containing a `cnf` claim.
9. When both checkout and payment mandates are disclosed: MUST verify `checkout_hash == transaction_id`.
10. MUST check L3 values against disclosed L2 constraints. Machine-enforceable constraints MUST be verified; descriptive fields are informational.
11. When receiving partial L2 disclosures: MUST still verify structural chain (signatures, `sd_hash`, key delegation). At least one mandate disclosure is REQUIRED in Autonomous mode to extract the agent delegation key.
12. MUST verify L3a `amount` is an integer in minor units before comparing against L2 constraints.

---

## 14. References

### Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.
- **[RFC 7515]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature
  (JWS)", RFC 7515, May 2015.
- **[RFC 7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.
- **[RFC 7518]** Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, May 2015.
- **[RFC 7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
  (JWT)", RFC 7519, May 2015.
- **[RFC 7800]** Jones, M., Bradley, J., and H. Tschofenig, "Proof-of-Possession
  Key Semantics for JSON Web Tokens (JWTs)", RFC 7800, April 2016.
- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC 8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
  Interchange Format", STD 90, RFC 8259, December 2017.
- **[FIPS 180-4]** National Institute of Standards and Technology, "Secure Hash
  Standard (SHS)", FIPS PUB 180-4, August 2015.
- **[RFC 9901]** Fett, D., Yasuda, K., and B. Campbell, "Selective Disclosure
  for JSON Web Tokens (SD-JWT)", RFC 9901, November 2025.

### Informative References

- **[FIDO2]** FIDO Alliance, "FIDO2: Web Authentication (WebAuthn)", 2019.
- **[W3C-VC]** Sporny, M., Noble, G., Longley, D., Burnett, D., and B. Zundel,
  "Verifiable Credentials Data Model v2.0", W3C Recommendation.
