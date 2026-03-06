# Verifiable Intent (VI)

**Open specification for cryptographic agent authorization in commerce.**

Visit **[verifiableintent.dev](https://verifiableintent.dev)** for full documentation.

**Status**: Draft (v0.1). Maintained by Mastercard; open to multi-stakeholder contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

Verifiable Intent defines a layered SD-JWT credential format that creates a
tamper-evident chain providing cryptographic evidence that an AI agent's actions
were within the scope delegated by a human user.

## The Problem

When a human delegates a purchase to an AI agent, no party in the transaction
can verify that the agent's actions actually reflect the user's wishes. The
agent might select the wrong product, overspend, or transact with an
unapproved merchant. Today's payment infrastructure assumes human presence at
the point of transaction — AI agents break that assumption, and without a
mechanism to bind agent actions to user intent, every stakeholder carries
unquantifiable risk:

| Stakeholder | Risk |
|-------------|------|
| **User** | Agent overspends, selects wrong products, or transacts with untrusted merchants |
| **Merchant** | Increased chargebacks from unauthorized agent transactions; no proof that agent was authorized |
| **Payment Network** | Dispute liability is ambiguous — who authorized the transaction? |
| **Credential Provider** | Credential misuse by agents operating outside user-granted scope |
| **Agent Platform** | Liability for agent actions without provable authorization chain |

## What VI Does

VI creates a cryptographic delegation chain from credential provider to user
to agent using SD-JWT credentials. Each layer binds the next through key
confirmation claims ([RFC 7800](https://www.rfc-editor.org/rfc/rfc7800)),
and selective disclosure ensures each party sees only the claims relevant to
its role. User-defined constraints (amount range, allowed line items, approved
merchants) are cryptographically bound. Machine-enforceable constraints (amount,
payee, merchant) are verified at execution time; descriptive fields (product
name, brand, color, size) provide informational context.

**In scope:** Layered SD-JWT credential format, delegation chain (credential
provider → user → agent), constraint vocabulary for purchase transactions,
selective disclosure policies per role, verification procedures, checkout-payment
integrity binding (cryptographic proof that the payment mandate references the
same checkout the user approved).

**Out of scope:** Transport protocols, key management/provisioning, credential
provider enrollment, agent platform APIs, dispute resolution, regulatory
compliance mapping (PCI DSS, PSD2, etc.).

> **Note:** Regulatory references (PSD2, SCA) in this specification are informational only. This specification does not make compliance claims and is not legal advice.

Each layer contains one or more **mandates** — signed claims expressing a
specific aspect of purchase intent (e.g., checkout details or payment parameters).

## Two Execution Modes

| | Immediate | Autonomous |
|---|---|---|
| **Layers** | 2 (L1 + L2) | 3 (L1 + L2 + L3) |
| **User role** | Reviews and confirms final values | Sets constraints; agent acts independently |
| **Agent role** | Forwarding only | Selects products, creates checkout, builds L3a + L3b |
| **Delegation** | No `cnf` in mandates — no delegation | `cnf.jwk` binds agent's key |
| **Use cases** | User-confirmed purchases, re-orders, one-click buy | Delegated shopping, automated replenishment, price-watching agents |
| **Example** | "Buy these 3 tennis balls for $5.99" | "Buy me a racket and some balls under $300 from Tennis Warehouse" |

**When to use which mode:** Use *Immediate* when the user is present and can
review exact checkout contents and payment details before authorizing — the agent
facilitates but does not decide. Use *Autonomous* when the user sets boundaries
and delegates the decision; the user may not be present at transaction time.

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1 — SD-JWT                         │
│              Credential Provider → User                     │
│                                                             │
│  Identity claims (email), pan_last_four, scheme             │
│  cnf.jwk = User Device Key                                  │
│  Lifetime: ~1 year                                          │
│  Signed by: Credential Provider private key                 │
└───────────────────────────┬─────────────────────────────────┘
                            │ L2 signed by key in L1 cnf.jwk
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 2 — KB-SD-JWT                      │
│                  User → Agent / Verifier                    │
│                                                             │
│  IMMEDIATE MODE             │  AUTONOMOUS MODE              │
│  ─────────────              │  ───────────────              │
│  Final checkout (checkout_jwt)│ Checkout constraints + cnf.jwk│
│  Final payment values       │  Payment constraints + cnf.jwk│
│  NO cnf in mandates         │  cnf.jwk = Agent Key          │
│  Lifetime: ~15 minutes      │  Lifetime: 24 hours – 30 days │
│  Signed by: User Device Key │  Signed by: User Device Key   │
└─────────────────────────────┼───────────────────────────────┘
                              │
                              │ In Autonomous mode, both the checkout mandate
                              │ and payment mandate each contain cnf.jwk binding
                              │ the same agent key. These MUST be identical
                              │ (see credential-format.md §12.7).
                              │ L3 signed by key in L2
                              │ mandate cnf.jwk
                              ▼ (Autonomous only)
┌─────────────────────────────────────────────────────────────┐
│              LAYER 3 — Split KB-SD-JWTs                     │
│               (Autonomous mode only)                        │
│                                                             │
│  L3a (Payment → Network)    │  L3b (Checkout → Merchant)    │
│  ─────────────────────────  │  ──────────────────────────   │
│  Final payment values       │  Final checkout (checkout_jwt)│
│  transaction_id             │  checkout_hash                │
│  payment_instrument         │                               │
│  header.jwk = Agent Key     │  header.jwk = Agent Key       │
│                                                             │
│  Cross-reference: L3a transaction_id == L3b checkout_hash   │
│  Lifetime: ~5 minutes                                       │
│  Signed by: Agent private key                               │
└─────────────────────────────────────────────────────────────┘
```

## Design Principles

- **Verifiable delegation** — Any party can cryptographically verify that an agent's actions trace back to explicit user authorization
- **Minimal disclosure** — Each party sees only the claims required for its role; sensitive data stays hidden from parties that don't need it
- **Constraint enforcement** — User-defined constraints (amount range, allowed line items, approved merchants/payees) are cryptographically bound; quantitative constraints are machine-enforceable, while descriptive fields provide informational context
- **Protocol agnostic** — Works across payment protocols, agent frameworks, and commerce platforms without modification
- **Standards aligned** — Built on SD-JWT, JWS, JWK, and RFC 7800; no novel cryptography
- **Incremental adoption** — Supports both human-present (Immediate) and agent-delegated (Autonomous) flows, allowing gradual migration

## Quick Start

```bash
# Install (using uv)
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Or using pip
python -m venv .venv && source .venv/bin/activate

# Recommended: upgrade pip for pyproject/hatchling editable installs
python -m pip install --upgrade pip

# Editable install (developer workflow)
pip install -e ".[dev]"

# Fallback if editable install is not supported in your environment:
# pip install ".[dev]"

# Run an example
python examples/autonomous_flow.py
```

## Examples

Each example is a standalone script — no servers, no setup:

```bash
python examples/autonomous_flow.py       # 3-layer autonomous purchase
python examples/immediate_flow.py        # 2-layer immediate purchase
python examples/selective_disclosure.py   # Role-specific credential views
python examples/constraint_checking.py    # All 5 constraint types + validation
python examples/network_validation.py     # Payment validation pipeline
```

## Tests

```bash
pytest tests/ -v
```

## Repository Structure

```
verifiable-intent/
├── spec/                   # Normative specification documents
│   ├── README.md           #   Architecture, trust model, conformance
│   ├── credential-format.md  # Credential format, claim tables, serialization
│   ├── constraints.md      #   Constraint types, validation rules
│   └── security-model.md   #   Security analysis, threats, key management
├── src/verifiable_intent/  # Python reference implementation
│   ├── crypto/             #   SD-JWT, signing, disclosure primitives
│   ├── models/             #   Credential and mandate data models
│   ├── issuance/           #   Layer 1/2/3 credential creation
│   └── verification/       #   Chain verification, constraint checking
├── examples/               # Standalone runnable examples
└── tests/                  # SDK test suite
```

## Specification

| Document | Description |
|----------|-------------|
| [spec/README.md](spec/README.md) | Architecture overview, trust model, selective disclosure, conformance requirements |
| [spec/credential-format.md](spec/credential-format.md) | Normative credential format: layer headers, payloads, disclosure formats, hash bindings |
| [spec/constraints.md](spec/constraints.md) | Constraint type definitions, validation rules, strictness modes, extensibility |
| [spec/security-model.md](spec/security-model.md) | Security analysis, threat model, attack mitigations, key management |

## License

[Apache 2.0](https://github.com/agent-intent/verifiable-intent/blob/main/LICENSE)
