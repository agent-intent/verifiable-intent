# Protocol Ecosystem

How Verifiable Intent (VI) sits alongside existing agentic commerce protocols.

> **Protocol versions**: Based on the Universal Commerce Protocol (UCP) specification
> as of 23 January 2026, the Agent Payments Protocol (AP2) version 0.2.0 ("V2",
> 28 April 2026), and the Agentic Commerce Protocol (ACP) specification as of
> 30 January 2026. Protocol details may change; statements about what each protocol
> "does not define" or "leaves open" are bounded by these versions. Note: AP2 V2
> (0.2.0) added an SD-JWT-based Human-Not-Present model with Open Checkout/Open
> Payment Mandates and `cnf` agent key binding, narrowing several gaps earlier
> attributed to AP2 0.1.0.

---

## The Core Relationship

VI is a portable, independently verifiable record of what a user authorized an
agent to do, and proof that the agent stayed within those bounds. It does not
handle transmission. Protocols like the Universal Commerce Protocol (UCP) and the
Agentic Commerce Protocol (ACP) define how agents create checkout sessions,
exchange payment credentials, and complete purchases. VI handles a different
concern: authorization proof.

VI rides alongside whatever protocol is already in use, adding a verifiable
trust layer without requiring changes to the underlying transport.

---

## What VI Adds to Any Protocol

Any protocol that carries VI credentials gains three properties:

**Cryptographic delegation chains.** A user's authorization for an agent to act
is recorded as a signed credential chain that each party can independently verify
the disclosures relevant to its role, regardless of platform or session context.

**User-signed constraints.** The user's intent (what to buy, how much to spend,
which merchants are acceptable) is encoded in machine-enforceable constraints
signed by the user's own key. Verifiers can confirm the agent acted within those
constraints without trusting the agent's self-report.

**Role-scoped selective disclosure.** Merchants see cart details; payment
networks see payment details. Neither sees the other's data, and this boundary
is enforced at the credential level, not by architectural convention.

---

## Universal Commerce Protocol (UCP)

UCP is a concrete checkout protocol aligned with Google's Agent Payments
Protocol (AP2), translating AP2's abstract framework into API endpoints, a
checkout lifecycle, and explicit roles. AP2 defines Verifiable
Digital Credentials (VDCs) as a trust mechanism in agentic payment flows, but
deliberately leaves the credential format implementation-defined.

VI provides a concrete implementation for that VDC layer. Its SD-JWT format
supplies the cryptographic delegation chains, selective disclosure, and
constraint enforcement that AP2 describes architecturally but does not
prescribe. In Autonomous mode, VI's split L3 architecture (L3a payment
mandate to the network, L3b checkout mandate to the merchant) maps naturally
to UCP's separation of checkout and payment flows. UCP's AP2 Mandates Extension
(`dev.ucp.shopping.ap2_mandate`) already defines placement for credential data
in the checkout flow; VI credentials can be carried in those fields without
changes to UCP's core endpoints.

AP2 leaves the VDC format open; VI provides a concrete option.
Detailed adoption architecture can be developed through coordination with UCP and
AP2's maintainers. For term-by-term mappings between VI layers and UCP/AP2
concepts (checkout mandates, VDCs, payment instruments), see the
[Cross-Protocol Glossary](glossary.md).

---

## Agentic Commerce Protocol (ACP)

ACP is a REST-based checkout and payment delegation protocol. Agents create
checkout sessions with sellers, delegate payment credentials to Shared Payment
Tokens (SPTs) via PSPs, and progress through a multi-state checkout lifecycle.

ACP's SPTs and VI credentials address different layers of the same problem.
SPTs authorize payment execution: a scoped token issued and enforced by the PSP.
VI credentials prove user authorization: a signed record that any party can
verify independently. SPTs ensure the payment rails won't process more than the
agent requested; VI provides cryptographic evidence that the agent acted within
the authority the user delegated. Both are useful in an integrated system.

ACP's extension mechanism provides a natural carrier for VI credentials. An
agent that supports VI declares it through capability negotiation. Sellers and
PSPs that support VI verify the credential chain. Parties that don't support VI
ignore the extension fields, and the checkout proceeds on standard ACP
mechanics.

Detailed adoption design can be developed through coordination with ACP's
maintainers. For how VI concepts map to ACP-specific terms (SPTs, payment
handlers, checkout states), see the [Cross-Protocol Glossary](glossary.md).

---

## References

- [VI Specification](../spec/README.md) — architecture, trust model,
  conformance requirements
- [Credential Format](../spec/credential-format.md) — L1/L2/L3 structure,
  selective disclosure, integrity bindings
- [Cross-Protocol Glossary](glossary.md) — VI terminology mapped to UCP and
  ACP equivalents
- [Agent Payments Protocol (AP2) Specification](https://github.com/google-agentic-commerce/AP2)
- [Universal Commerce Protocol (UCP) Specification](https://github.com/Universal-Commerce-Protocol/ucp)
- [Agentic Commerce Protocol (ACP)](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)
