# Tenzro Decentralized Identity Protocol (TDIP)

> **Spec version**: Based on the Tenzro Decentralized Identity Protocol (TDIP)
> as published at <https://github.com/tenzro/tenzro-network/blob/main/TDIP.md>
> as of 2 May 2026. TDIP details may change; statements in this document are
> bounded by that version.

## Summary

The Tenzro Decentralized Identity Protocol (TDIP) is a unified W3C-DID-method
specification (`did:tenzro`) covering both human and machine (AI agent)
identities, with first-class delegation primitives. TDIP defines:

- **Identity types**: Human and Machine, distinguished by DID structure
  (`did:tenzro:human:*` vs `did:tenzro:machine:*`).
- **DelegationScope**: A structural ceiling attached to a Machine identity,
  declared at registration time, bounding what the agent is authorized to do
  (max-transaction-value, max-daily-spend, allowed-operations,
  allowed-payment-protocols, allowed-chains, time-bound).
- **Runtime SpendingPolicy**: A separate, mutable per-day spending cap
  attached to a Machine identity at runtime, dialled by the controller without
  re-issuing the delegation.
- **Verifiable Credentials**: W3C-VC-compatible credentials anchored in the
  TDIP registry for KYC tier, issuer attestations, and cross-organization
  delegation chains.

VI and TDIP address adjacent layers of the same problem. TDIP supplies the
identity primitives, registry, and on-chain enforcement hooks for delegated
agent authority. VI supplies a concrete, portable, off-protocol credential
format with selective disclosure and machine-checkable constraints.

This page describes how a VI credential chain maps onto TDIP's primitives,
why each layer interlocks, and what an integration looks like in practice.

---

## The Core Relationship

TDIP, like AP2, defines an authorization model architecturally — the
controller of a Human identity grants a Machine identity authority bounded by
a `DelegationScope`. TDIP records this binding on-chain in the Tenzro Ledger
identity registry, and exposes `enforce_operation` for runtime checking.

What TDIP does **not** specify is the off-chain credential format that
attests, in a portable way, to:

- The user's intent for a particular purchase or action.
- Selective disclosure to different roles (merchant sees cart, network sees
  payment).
- Per-action constraint signing that can be verified without on-chain
  resolution at every step.

VI fills exactly that gap. A VI credential chain (L1 issuer → L2 user mandate
→ L3a payment / L3b checkout) rides alongside the on-chain TDIP binding,
giving each party in a TDIP-rooted commerce flow the off-protocol evidence
they need without a registry round-trip.

---

## Mapping Table

| VI Layer | TDIP Equivalent | Notes |
| :--- | :--- | :--- |
| L1: Issuer credential (binds user public key via `cnf.jwk`) | TDIP Verifiable Credential issued by an issuer DID, anchored to a `did:tenzro:human:` identity | TDIP issuer credentials live in the on-chain registry; VI L1 is the off-chain SD-JWT carrier of the same binding |
| L2: User mandate with constraints | TDIP `DelegationScope` for the bound `did:tenzro:machine:` | VI L2 is the per-purchase intent; DelegationScope is the long-lived ceiling. Both must permit the operation |
| L3a: Agent payment fulfillment | The on-chain payment transaction broadcast by the agent, signed with the machine identity's controller key | The VI L3a record is the off-chain notary that the agent stayed within L2 + TDIP DelegationScope at execution time |
| L3b: Agent checkout fulfillment | A merchant-facing receipt referencing the same machine identity | The VI L3b record is the merchant's portable proof that the buyer agent was authorized |
| Runtime enforcement | TDIP `SpendingPolicy::check` called at execution time | Independent of VI; VI's L3 record SHOULD reference whether the runtime policy passed |

---

## What VI Adds to a TDIP-Rooted Flow

Any TDIP-bound agent that carries VI credentials gains three properties on
top of TDIP's existing identity primitives:

**Off-chain verifiability.** A merchant or PSP can verify the user's intent
without a Tenzro Ledger RPC round-trip. The L1 SD-JWT, the L2 user mandate
with constraints, and the L3 fulfillment are all locally verifiable from
their signatures alone.

**Selective disclosure to commerce roles.** TDIP's W3C VCs support selective
disclosure but the underlying machinery is JSON-LD-based; VI's SD-JWT format
is a more compact carrier that fits naturally into existing agentic-commerce
protocols (UCP/AP2 mandates, ACP extensions). Merchants see cart details;
payment networks see payment details; neither sees the other's data.

**Per-purchase constraint enforcement.** TDIP's `DelegationScope` is a
long-lived ceiling; VI's L2 constraints (e.g. `AllowedMerchantConstraint`,
`PaymentAmountConstraint`, `CheckoutLineItemsConstraint`) are per-purchase
intent. The two compose: a TDIP-bound agent's payment is permitted iff it
passes BOTH the L2 constraints AND `DelegationScope::enforce_operation`.

---

## Integration Points

VI rides on top of TDIP without changes to TDIP's on-chain registry or
DelegationScope schema. The integration surfaces:

### Identity binding

The `cnf.jwk` field of the VI L1 credential SHOULD bind to the same Ed25519
public key registered as the TDIP human identity's controller key. Verifiers
can independently confirm by resolving the user's `did:tenzro:human:` DID
and comparing the JWK.

### Agent identity binding

The VI L2 mandate's `aud` field (the audience for which the mandate is
issued) SHOULD be a `did:tenzro:machine:` DID URI. Verifiers MUST resolve
this DID against the TDIP registry, confirm the resolved Machine identity's
`controller_did` equals the L2 mandate's issuer's `did:tenzro:human:`, and
confirm the operation passes both the L2 constraints AND the resolved
`DelegationScope`.

### Runtime enforcement composition

At payment-broadcast time, the agent SHOULD:

1. Verify the VI chain (L1 → L2 → L3a) produces a valid signed delegation.
2. Call `DelegationScope::enforce_operation` against the operation about to
   be broadcast.
3. Call `SpendingPolicy::check` against the same operation.

All three must pass. The reference implementation in
`crates/tenzro-payments/src/identity_binding.rs` (`IdentityPaymentBinder`)
performs (2) and (3); a VI-aware integration adds (1) ahead of it.

### Cross-protocol carrier

When a TDIP-bound agent is also operating under UCP/AP2 (for the checkout
flow) or ACP (for the seller-PSP flow), VI credentials ride in those
protocols' extension mechanisms (UCP's `dev.ucp.shopping.ap2_mandate`,
ACP's extension fields) **without** changing TDIP's wire format. TDIP and VI
are orthogonal; UCP/ACP and VI are orthogonal; TDIP and UCP/ACP are
orthogonal.

---

## Why TDIP and VI Both Exist

A reasonable question: if TDIP already supplies on-chain delegation, why also
carry VI credentials?

The answer is the same as for UCP/AP2: not every party in a flow can or
should make a registry round-trip for every action. A merchant in a
TDIP-rooted purchase needs evidence that the buyer agent was authorized, but
the merchant may not have RPC access to the Tenzro Ledger or may want a
locally-verifiable record for audit. VI gives the merchant exactly that — a
signed credential chain that proves authorization without registry
dependency.

Symmetrically, TDIP gives VI a registry-anchored root of trust that doesn't
exist if VI is used standalone. A pure-VI flow without an underlying registry
relies on the L1 issuer for revocation and authority assertions; TDIP
supplies an on-chain registry that revokes promptly and cascades to all
controlled machines.

---

## References

- [VI Specification](../spec/README.md) — architecture, trust model,
  conformance requirements
- [Credential Format](../spec/credential-format.md) — L1/L2/L3 structure,
  selective disclosure, integrity bindings
- [Cross-Protocol Glossary](glossary.md) — VI terminology mapped to UCP/ACP
  equivalents
- [TDIP Specification](https://github.com/tenzro/tenzro-network/blob/main/TDIP.md)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- Reference implementation:
  [`tenzro/tenzro-network`](https://github.com/tenzro/tenzro-network) —
  `crates/tenzro-identity` (TDIP),
  `crates/tenzro-payments::identity_binding` (runtime enforcement)
