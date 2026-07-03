# Cross-Protocol Terminology Glossary

This glossary maps Verifiable Intent (VI) terminology to equivalent concepts in
protocol-specific ecosystems. VI's core specification uses protocol-agnostic
terms; this document maps terminology for implementers working with a specific
protocol.

> **Protocol versions**: Based on the Universal Commerce Protocol (UCP) specification
> as of 23 January 2026, the Agent Payments Protocol (AP2) version 0.2.0 ("V2",
> 28 April 2026), and the Agentic Commerce Protocol (ACP) specification as of
> 30 January 2026. Mappings reflect these versions; "no equivalent" statements are
> bounded by these dates. AP2 V2 introduced the Human-Not-Present model with Open
> Checkout/Open Payment Mandates, SD-JWT disclosures, and `cnf`-based agent key
> binding — natively defining much of the delegation mechanism VI was positioned
> to fill. Rows below that still read "no equivalent" against pre-V2 AP2 are
> bounded by the noted date and may now have an AP2 V2 analogue.

**How to read the tables:** Each row starts with the canonical VI term as
defined in [`spec/README.md`](../spec/README.md). The definition column
captures the VI-specific meaning. Protocol columns show the closest equivalent
term (or "---" when no direct mapping exists). The notes column flags semantic
differences.

---

## Roles

| VI Term | Definition | UCP / AP2 Equivalent | ACP Equivalent | Notes |
|---------|-----------|----------------------|----------------|-------|
| **Credential Provider** | Trusted third party issuing Layer 1 SD-JWTs; binds user identity to a public key. Scoped to identity binding only (unlike AP2 CP, which also manages payment credentials and tokenization) | CP (UCP) / CP (AP2) | --- | Same role in UCP and AP2. No ACP equivalent; buyer identity is managed by the agent platform |
| **User** | End-user (the delegating principal) who creates Layer 2 mandates expressing purchase intent. "The user creates L2" refers to any authorized system holding the user's private key — see [security-model.md §3.5](../spec/security-model.md#35-deployment-models) | User | Buyer | Same concept across all three protocols |
| **Agent** | AI software acting on behalf of the user; creates Layer 3 mandates in Autonomous mode | Platform (UCP) / UA+SA (AP2) | AI Agent | UCP Platform encompasses both the user-facing and shopping agent roles. AP2 distinguishes UA (direct user interface) from SA (delegated shopping). ACP's "AI Agent" maps directly. VI uses a single "Agent" role covering all |
| **Merchant** | Entity selling goods/services; creates signed checkout JWTs; receives checkout mandate disclosures | Business (UCP) / ME (AP2) | Seller | UCP uses "Business" as the seller-side participant. ACP uses "Seller." AP2 also defines a separate Merchant Payment Processor (MPP) role; VI treats payment processing as an implementation detail outside the credential chain |
| **Payment Network** | Routes and settles payments; verifies the full VI credential chain; arbiter for disputes | PSP (UCP) / Network and Issuer (AP2) | Payment Service Provider (PSP) | UCP and ACP both use PSP (Payment Service Provider) as the payment-processing role. AP2 bundles network and issuer into one conceptual role. VI addresses them as a single verification endpoint |
| **Verifier** | Any party validating a VI credential chain (merchants and payment networks are primary verifiers) | --- | --- | No explicit equivalent in any protocol. AP2 implies verification responsibilities per role. ACP distributes verification across seller and PSP roles. None names a generic "Verifier" role |
| --- | --- | Merchant Payment Processor (MPP) | --- | AP2-only role. Constructs transaction authorization messages. No direct VI equivalent; VI credentials are protocol-layer artifacts consumed by whatever entity performs authorization. No ACP equivalent; sellers process payments through their chosen PSP |
| --- | --- | Payment Agent | --- | AP2-only role. Proposed AP2 role for payment method selection and validation. Not a required AP2 participant. No VI or ACP equivalent |

---

## Credentials and Layers

| VI Term | Definition | UCP / AP2 Equivalent | ACP Equivalent | Notes |
|---------|-----------|----------------------|----------------|-------|
| **Layer 1 (L1)** | Credential Provider SD-JWT binding user identity to a public key via `cnf.jwk`. Long-lived (~1 year) | --- | --- | No equivalent in any protocol. AP2 assumes identity binding happens outside the VDC framework. ACP has no identity credential layer. L1 is a VI-specific contribution |
| **Layer 2 (L2), Immediate** | User KB-SD-JWT with finalized checkout and payment mandates (`vct: "mandate.checkout.1"`, `vct: "mandate.payment.1"`). No `cnf` in mandates (no further delegation). Human present | Checkout mandate / `ap2.checkout_mandate` (UCP) / Cart Mandate VDC (AP2) | Checkout session at `ready_for_payment` | UCP's checkout mandate extension wraps AP2 Cart Mandates in UCP checkout sessions. AP2 Cart Mandate bundles cart details + payment request + merchant signature. ACP maps to the checkout session reaching `ready_for_payment`, where the buyer confirms final values before CompleteCheckout. VI L2 Immediate separates checkout and payment into distinct selectively-disclosable mandates |
| **Layer 2 (L2), Autonomous** | User KB-SD-JWT with constraint-bearing mandates (`vct: "mandate.checkout.open.1"`, `vct: "mandate.payment.open.1"`) and `cnf.jwk` binding the agent's key. Human not present | Pre-checkout delegation (UCP) / Open Checkout + Open Payment Mandate (AP2 V2) | --- | AP2 V2's **Open Checkout Mandate** + **Open Payment Mandate** are the structural twin of VI L2 Autonomous: same VCT strings (`mandate.checkout.open.1` / `mandate.payment.open.1`), same `cnf` agent-key binding, same `constraints[]` array, and the same `payment.reference.conditional_transaction_id` ("Digest of the associated Open Checkout Mandate"). AP2's **Intent Mandate** is a separate, higher-level human-present artifact (natural-language description + merchant/SKU lists), not this constraint credential. UCP has no formal pre-checkout delegation credential. No ACP equivalent. VI L2 Autonomous carries typed constraints (quantitative constraints are machine-enforceable; qualitative constraints are informational) |
| **Layer 3 (L3a / L3b)** | Split Agent KB-SD-JWTs proving constraint satisfaction with finalized values. L3a (payment mandate) → payment network; L3b (checkout mandate) → merchant. Cross-referenced via `transaction_id` == `checkout_hash`. Short-lived (~5 min). Autonomous mode only | --- | --- | No equivalent in any protocol. AP2 assumes the agent's fulfillment is captured in the Cart Mandate after the agent shops. ACP has no agent fulfillment credential. L3 is a VI-specific contribution providing an auditable link between user constraints and agent actions |
| **Checkout Mandate** | Selectively disclosable claim (`vct: "mandate.checkout.open.1"` Autonomous L2, `vct: "mandate.checkout.1"` Immediate L2 / L3b) describing allowed products (Autonomous) or finalized checkout (Immediate) | `line_items[]` in checkout (UCP) / Cart Mandate VDC (AP2) | `line_items[]` in checkout session | UCP models cart contents as `line_items[]` within checkout sessions. AP2 Cart Mandate includes payment details; VI checkout mandate is purely about products. ACP uses `line_items[]` in checkout sessions with a similar purpose. AP2 Intent Mandate `skus` field maps loosely to VI `mandate.checkout.line_items` constraint |
| **Payment Mandate** | Selectively disclosable claim (`vct: "mandate.payment.open.1"` Autonomous L2, `vct: "mandate.payment.1"` Immediate L2 / L3a) describing allowed or final payment parameters | `payment.instruments` (UCP) / Payment Mandate VDC (AP2) | `payment_data` in CompleteCheckout + SPT `allowance` | UCP exposes payment instruments through the checkout session. ACP splits this across `payment_data` (in CompleteCheckout) and SPT `allowance` (for delegated execution). VI adds selective disclosure enforcement (merchant sees checkout, not payment; network sees payment, not checkout). AP2 shares the full Payment Mandate with the network |
| **SD-JWT** | Credential format (IETF RFC 9901) with native selective disclosure | --- | --- | AP2 leaves VDC format abstract; UCP inherits this via the AP2 Mandates Extension. ACP uses SPTs (opaque bearer tokens) for delegated payment execution rather than a structured credential format. VI provides a concrete SD-JWT implementation |
| **KB-SD-JWT** | SD-JWT with Key Binding (`typ: "kb-sd-jwt"`); proves the presenter holds the private key bound in the previous layer's `cnf` claim. Used for L2 Immediate, L3a, and L3b | --- | --- | No equivalent in UCP or AP2. AP2's `user_authorization` JWT serves a similar proof-of-possession purpose but is structurally different. ACP's SPTs are bearer tokens without key-binding proof |
| **KB-SD-JWT+KB** | KB-SD-JWT with onward key binding (`typ: "kb-sd-jwt+kb"`); extends KB-SD-JWT by including `cnf.jwk` in mandate payloads to delegate authority to the next layer. Used for L2 Autonomous only | --- | --- | The `+kb` suffix signals that the credential carries key binding for further delegation. No equivalent in other protocols |

---

## Flows and Modes

| VI Term | Definition | UCP / AP2 Equivalent | ACP Equivalent | Notes |
|---------|-----------|----------------------|----------------|-------|
| **Immediate Mode** | 2-layer flow (L1 + L2). User confirms final values directly. No agent delegation | User-confirmed checkout (UCP) / Human-Present transaction (AP2) | Buyer-confirmed checkout | Same conceptual flow across all three protocols. UCP models this as the user confirming checkout session contents. ACP models this as a buyer-confirmed checkout where the session reaches `ready_for_payment` before CompleteCheckout. AP2 defines detailed step-by-step interactions between UA/SA, ME, CP, MPP. VI focuses on the credential artifacts produced at each step |
| **Autonomous Mode** | 3-layer flow (L1 + L2 + L3). User sets constraints; agent acts independently within bounds | Agent-driven checkout (UCP) / Human-Not-Present transaction (AP2) | Agent-driven checkout | UCP models this as the agent managing the checkout session end-to-end. ACP models this as the agent creating and completing the session independently, with SPT constraining payment execution. AP2 V2's Human-Not-Present flow is approval of **Open Checkout/Open Payment Mandates** (the Intent Mandate is the upstream human-present intent object). VI adds L3 as an auditable fulfillment layer and typed constraints (quantitative are machine-enforceable; qualitative are informational) |
| **Delegation Chain** | Cryptographic chain linking Credential Provider -> User -> Agent via `cnf` claims at each layer | Implicit platform delegation (UCP) / Agent key delegation (AP2) | SPT `allowance` (loosely) | UCP delegates implicitly through platform identity; AP2 describes delegation conceptually. ACP's SPT scopes agent authority via amount/merchant/expiry, but constraints are set by the agent, not the buyer — a key semantic difference from VI's user-set constraints. VI implements delegation as a verifiable chain: L1 `cnf.jwk` = user key, L2 mandate `cnf.jwk` = agent key, L3 header `jwk` = agent key proof |
| **Fallback to Immediate** | Merchant forces user confirmation when Intent Mandate is insufficient, converting to Immediate flow | `requires_escalation` status (UCP) / Merchant-forced confirmation (AP2) | `authentication_required` / `requires_escalation` state | Same concept across all three protocols. UCP uses the `requires_escalation` checkout status. ACP uses `authentication_required` or `requires_escalation` checkout states to signal that the seller forces buyer interaction. AP2 spec describes this as merchant requesting SA to bring user back into session |

---

## Integrity Mechanisms

| VI Term | Definition | UCP / AP2 Equivalent | ACP Equivalent | Notes |
|---------|-----------|----------------------|----------------|-------|
| **`sd_hash`** | SHA-256 hash binding each layer to the previous layer. In the split L3 architecture, each L3 computes `sd_hash` over the L2 base JWT plus only its relevant disclosures (selective binding) | --- | --- | Novel to VI. No equivalent in any protocol. ACP handles integrity at the protocol/session layer rather than the credential layer. Prevents layer substitution attacks by cryptographically chaining the credential sequence. Selective per-L3 binding preserves the privacy boundary between L3a and L3b |
| **`checkout_hash`** | SHA-256 hash of the `checkout_jwt` string: `B64U(SHA-256(ASCII(checkout_jwt)))`. Binds the payment mandate to a specific checkout mandate | --- | --- | VI-specific. UCP's `merchant_authorization` provides session-level integrity via JWS detached-content signatures, but not per-mandate cryptographic binding. ACP associates checkout and payment via `checkout_session_id` reference rather than cryptographic binding. Prevents checkout-payment mismatch. In Immediate mode, appears in L2 payment mandate. In Autonomous mode, L3a carries this as `transaction_id` and L3b carries it as `checkout_hash` |
| **`cnf` claim** | RFC 7800 confirmation claim binding a JWT to a cryptographic key. Used at L1 (`cnf.jwk` = user key) and L2 mandates (`cnf.jwk` = agent key, Autonomous only) | `user_authorization` (partial) | --- | AP2's `user_authorization` is a JWT proving user consent; VI's `cnf` binds keys at the mandate level, enabling verifiable delegation chains. ACP's SPTs are bearer tokens without key-binding proof. The `cnf` mechanism is standard (RFC 7800); its application inside SD-JWT mandates is defined by VI |
| **Simple SHA-256 hashing** | VI uses simple SHA-256 of existing JWT/disclosure strings for all binding computations (no JCS/RFC 8785 canonical serialization) | --- | --- | VI-specific. No equivalent in any protocol. Simpler than canonical serialization because hash inputs are existing JWT strings rather than re-serialized JSON objects |
| **`delegate_payload`** | Array of SD-JWT disclosure references (`{"...": "<hash>"}`) in L2/L3 payloads pointing to mandate disclosures | --- | --- | Novel structural mechanism. No equivalent in any protocol. AP2 mandates are standalone JSON objects. VI embeds mandates as selectively-disclosable elements within a signed envelope |

---

## Constraint Types

All five registered VI constraint types and their closest UCP, AP2, and ACP
equivalents. VI constraints appear in L2 mandate `constraints` arrays
(Autonomous mode). None of UCP, AP2, or ACP defines a formal constraint system;
the equivalents below are informal parameters or structural analogues.
`payment.paymentMethod` and `payment.order` have been eliminated —
`payment_instrument` is now a top-level mandate field, and execution mode is
conveyed by the L2 `typ` header.

| VI Constraint Type | Purpose | UCP / AP2 Equivalent | ACP Equivalent | Notes |
|--------------------|---------|----------------------|----------------|-------|
| **`mandate.checkout.line_items`** | Restrict which products the agent may purchase (structured items with `id`, `acceptable_items` as SD refs, `quantity`) | `line_items[]` in checkout (UCP) / `IntentMandate.skus` (AP2) | `line_items[]` in checkout session | UCP models checkout contents as `line_items[]` within checkout sessions. AP2's `skus` field is a flat list of allowed SKUs (or null). ACP's `line_items[]` describes what was purchased, not what may be purchased — a post-hoc record rather than a pre-authorization constraint. VI `mandate.checkout.line_items` adds structured item references with selective disclosure |
| **`mandate.checkout.allowed_merchants`** | Restrict which merchants the agent may transact with (selectively disclosable merchant list in checkout mandate) | Business URL (UCP) / `IntentMandate.merchants` (AP2) | Seller URL / SPT `allowance.merchant_id` | Merchant allowlist in the checkout mandate with individually disclosable merchant entries. UCP identifies the Business by URL. ACP scopes SPT to a specific merchant via `allowance.merchant_id`, but the constraint is set by the agent, not the buyer |
| **`mandate.payment.allowed_payees`** | Restrict which payees the agent may transact with (in payment mandate) | Business URL (UCP) / `IntentMandate.merchants` (AP2) | Seller URL / SPT `allowance.merchant_id` | Renamed from `payment.payee`. Payee allowlist in the payment mandate, complementing `mandate.checkout.allowed_merchants` in the checkout mandate. VI adds selective disclosure so individual payee identities can be hidden |
| **`mandate.payment.amount_range`** | Constrain the transaction amount to a min/max range (`currency` + integer minor units) | --- | SPT `allowance.max_amount` | Renamed from `mandate.payment.budget`. Neither UCP nor AP2 defines an explicit amount constraint. ACP's SPT `allowance.max_amount` caps charge amount but is set by the agent, not the buyer. VI uses integer minor units and supports min/max range. Cryptographically enforceable and user-set |
| **`mandate.payment.reference`** | Cryptographically bind payment mandate to checkout mandate via `conditional_transaction_id` | --- | --- | Defined by VI. No equivalent in any protocol. Appears only in Autonomous L2 payment mandates. Simplified from dual-hash to single `conditional_transaction_id`. Deferred binding because the checkout doesn't exist yet when L2 is created |

Recurrence mapping note: recurrence is expressed in VI via the
`mandate.payment.recurrence` and `mandate.payment.agent_recurrence` constraint
types (not a top-level mandate field). VI uses ISO 20022 frequency codes
(e.g. `MNTH`, `WEEK`, `YEAR`). Note this **differs** from AP2 V2, whose Open
Payment Mandate `agent_recurrence` uses a named enum
(`ON_DEMAND`, `DAILY`, `WEEKLY`, `BIWEEKLY`, `MONTHLY`, `QUARTERLY`, `ANNUALLY`);
only `ON_DEMAND` overlaps. Implementations bridging VI and AP2 V2 must map
between the two vocabularies.

---

## Additional UCP / AP2 Terms Without VI Equivalents

| UCP / AP2 Term | Definition | Why No VI Equivalent |
|----------------|-----------|---------------------|
| **`merchant_authorization`** (UCP) | JWS detached-content signature where Business signs checkout session contents | VI defines a `checkout_jwt` concept for merchant-side integrity at the credential level (implementation-defined in v0.1 with SHOULD-level guidance). Both address merchant authorization but at different protocol layers |
| **`/.well-known/ucp`** (UCP) | Protocol discovery endpoint for UCP capabilities | VI is transport-agnostic but can be advertised through UCP discovery |
| **`dev.ucp.shopping.checkout`** (UCP) | UCP checkout session management extension | VI credentials attach at specific checkout states but don't model the session lifecycle |
| **`dev.ucp.shopping.ap2_mandate`** (UCP) | UCP's AP2 Mandates Extension, the integration point for VI credentials in UCP | VI credentials flow through this extension when used within UCP |
| **Checkout status lifecycle** (UCP) | State machine: `incomplete`, `ready_for_payment`, `requires_escalation`, `completed`, etc. | VI credentials attach at specific states but don't model the lifecycle |
| **Transport bindings** (UCP) | UCP defines HTTP REST endpoints and JSON schemas for agent-business communication | VI is transport-agnostic. VI credentials can be carried in UCP REST payloads, A2A messages, or any other transport |
| **Risk Payload** (AP2) | Container for risk-related signals (fraud scores, device fingerprints, behavioral data) attached to VDCs | Outside VI scope. VI focuses on intent verification, not risk assessment. Risk payloads can be carried alongside VI credentials |
| **3DS2 Challenge** (AP2) | Step-up authentication challenge from issuer during transaction authorization | Outside VI scope. VI credentials are pre-authorization artifacts. 3DS2 happens during payment execution |
| **A2A (Agent-to-Agent)** (AP2) | Google's open protocol for inter-agent communication; AP2 extends it with payment-specific message types | VI is transport-agnostic. VI credentials can be carried in A2A messages, REST APIs, or any other transport |
| **MCP (Model Context Protocol)** | Protocol for AI model/agent interaction with external resources | VI is framework-agnostic. Agent platforms using MCP can issue/verify VI credentials through MCP tools |
| **Dynamic Linking** (AP2) | SCA requirement to bind authentication to specific transaction details | VI's `checkout_hash` and constraint system achieve a similar outcome (binding authorization to specific transaction parameters) but are not a direct implementation of regulatory Dynamic Linking |
| **Verifiable Presentation (VP)** | W3C concept: presentation of VDCs with holder binding proof | VI's KB-SD-JWT with selective disclosure serves the same function as a VP but uses SD-JWT mechanics rather than W3C VP envelopes |

---

## Additional ACP Terms Without VI Equivalents

| ACP Term | Definition | Why No VI Equivalent |
|----------|-----------|---------------------|
| **Shared Payment Token (SPT)** | Scoped payment token returned by PSP via `delegate_payment`. Contains `allowance` constraints (max_amount, currency, merchant_id, expires_at). Format: `spt_...` | Payment-rails authorization. VI handles user-to-agent delegation proof, not payment execution. SPTs and VI credentials are complementary |
| **Payment Handler** | Pluggable payment method abstraction (`dev.acp.tokenized.card`, `dev.acp.seller_backed.saved_card`, etc.) declared in `capabilities.payment.handlers[]` | Payment method abstraction. VI is payment-method-agnostic; it references credentials via `payment_instrument` regardless of underlying handler type |
| **Checkout State Machine** | 11-state lifecycle for checkout sessions: `incomplete`, `not_ready_for_payment`, `requires_escalation`, `authentication_required`, `ready_for_payment`, `pending_approval`, `in_progress`, `complete_in_progress`, `completed`, `canceled`, `expired` | Session lifecycle management. VI credentials attach at specific states but don't model the state machine |
| **Capability Negotiation** | Agent and seller exchange supported capabilities (payment handlers, extensions, interventions) during session creation | Protocol feature negotiation. VI declares itself via ACP's extension mechanism but does not model the negotiation lifecycle |
| **3DS Authentication** | `authentication_required` state with `authentication_metadata` (acquirer details, directory server, flow preference) and `authentication_result` | Step-up authentication during payment execution. VI credentials are pre-authorization artifacts |
| **Intent Trace** | Tracking agent actions from intent expression through purchase completion | Observability concern. VI provides a cryptographic audit trail (L1->L2->L3 chain) but does not define a trace format |
| **Affiliate Attribution** | Tracking referral and attribution data for commerce transactions | Marketing concern outside intent verification scope |
| **Risk Signals** | Fraud assessment data (`card_testing` scores, `checks_performed` values) submitted with `delegate_payment` | Risk assessment is orthogonal to intent verification. Risk signals can be carried alongside VI credentials |
| **Extensions Framework** | Composable extension system with JSONPath schema composition, lifecycle states (draft/experimental/stable/deprecated/retired), and reverse-domain naming for third-party extensions | VI is designed to be carried via ACP's extension framework but does not define its own extension system |
| **Discount Extension** | Discount code support with applied/rejected discount details, allocation methods (`each`/`across`), and priority-based stacking | Pricing adjustments are seller-side concerns. VI captures the final amount after discounts are applied |

---

## References

- [VI Specification: Overview](../spec/README.md)
- [VI Specification: Credential Format](../spec/credential-format.md)
- [VI Specification: Constraints](../spec/constraints.md)
- [Protocol Ecosystem](protocols.md) — how VI sits alongside UCP and ACP
- [AP2 Specification](https://github.com/google-agentic-commerce/AP2)
- [AP2 Glossary](https://github.com/google-agentic-commerce/AP2/blob/main/docs/glossary.md)
- [UCP Specification](https://github.com/Universal-Commerce-Protocol/ucp)
- [ACP Specification](https://www.agenticcommerce.dev/)
- [ACP GitHub Repository](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)
