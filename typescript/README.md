# Verifiable Intent — TypeScript

TypeScript implementation of the [Verifiable Intent](../README.md) credential format:
a layered SD-JWT delegation chain (Issuer → User → Agent) that produces cryptographic
proof an AI agent's commercial actions stayed within the scope a human explicitly
delegated.

This is the **TypeScript** package of the Verifiable Intent monorepo, a port of the
[`../python`](../python) reference implementation. It has **zero runtime
dependencies** and uses only Web-standard APIs — WebCrypto (`crypto.subtle`) for
ES256 and SHA-256, `crypto.getRandomValues` for salts, `TextEncoder`/`TextDecoder`
and a hand-rolled base64url codec for bytes — so it runs on **Node.js >= 20 and
in modern browsers** unchanged. The Verifiable-Intent-specific layering,
`delegate_payload` mechanism, and split-L3 logic stay byte-compatible with the
Python implementation.

> **Status:** `crypto`, `models`, `issuance`, and `verification` are implemented
> and validated byte-for-byte (issuance) and verdict-for-verdict (verification)
> against Python-generated conformance vectors
> ([`../test-vectors/vectors.json`](../test-vectors)). The vitest suite (183
> tests) replays every shared golden vector — asserting Python's exact error
> strings — plus TS-specific parity, fail-closed hardening, an isomorphic
> (Buffer-free) runtime test, and end-to-end issue→verify round-trip tests.

## Install & test

```bash
npm install
npm test          # vitest, validates against ../test-vectors
npm run build     # tsdown -> dist/ (dual ESM + CJS + .d.ts)
npm run typecheck # tsc --noEmit
npm run lint      # eslint
npm run test:isomorphic  # builds, then runs dist/ with Node's Buffer global deleted
```

## Quick start (immediate mode)

Immediate mode: the user authorizes one specific checkout — no agent delegation,
no L3. Every symbol below is exported from the package root.

```ts
import {
  CheckoutMandate,
  createLayer1,
  createLayer2Immediate,
  generateEs256Key,
  hashAscii,
  IssuerCredential,
  MandateMode,
  PaymentMandate,
  UserMandate,
  verifyChain,
} from '@verifiable-intent/core';

const now = Math.floor(Date.now() / 1000);
const issuer = await generateEs256Key(); // the card network / issuer
const user = await generateEs256Key();   // the user's wallet key

// L1: issuer credential binding the user's public key (cnf.jwk).
const l1 = await createLayer1(
  new IssuerCredential({
    iss: 'https://www.mastercard.com',
    sub: 'user-bob-001',
    iat: now,
    exp: now + 86400,
    aud: 'https://wallet.example.com',
    cnfJwk: user.publicKey,
  }),
  issuer.privateKey,
);

// L2: the user's mandate for one specific, finalized checkout.
const nonce = crypto.randomUUID(); // Web-standard global (Node >= 20 / browsers)
const mandate = new UserMandate({
  nonce,
  aud: 'https://agent.example.com',
  iat: now,
  iss: 'https://wallet.example.com',
  exp: now + 900,
  mode: MandateMode.IMMEDIATE,
  // Hashing is async (WebCrypto): await hashAscii / hashDisclosure / hashBytes.
  sdHash: await hashAscii(l1.serialize()),
  promptSummary: 'Purchase Babolat Pure Aero racket',
  // `checkoutJwt` is a merchant-signed checkout JWT; checkout_hash and
  // transaction_id are auto-computed from it by createLayer2Immediate.
  checkoutMandate: new CheckoutMandate({ vct: 'mandate.checkout.1', checkoutJwt }),
  paymentMandate: new PaymentMandate({
    vct: 'mandate.payment.1',
    paymentInstrument: { type: 'mastercard.srcDigitalCard', id: 'f199c3dd-7106-478b-9b5f-7af9ca725170' },
    payee: { id: 'merchant-uuid-1', name: 'Tennis Warehouse', website: 'https://tennis-warehouse.com' },
    currency: 'USD',
    amount: 27999, // minor units (cents)
  }),
});
const { sdJwt: l2 } = await createLayer2Immediate(mandate, user.privateKey);

// Verify the chain. Fails closed: `valid` is false with populated `errors`
// on any problem; verification never throws on malformed credentials.
const result = await verifyChain(l1, l2, {
  issuerPublicJwk: issuer.publicKey,
  l1Serialized: l1.serialize(),
  expectedL2Aud: 'https://agent.example.com',
  expectedL2Nonce: nonce,
});
if (!result.valid) {
  console.error(result.errors);
}
```

For autonomous mode (open mandates + agent delegation + split L3a/L3b), see
`test/roundtrip.test.ts` for a full end-to-end chain.

## What `verifyChain` checks

Derived from the implementation (`src/verification/chain.ts`); every failure is
fail-closed (`valid: false` + a populated `errors` list):

- **Signatures** — ES256 at every layer, each verified against the *previous*
  layer's `cnf` key: L1 against `issuerPublicJwk`, L2 against the L1 `cnf.jwk`
  (user key), L3 against the agent key from the L2 mandates' `cnf.jwk` — never a
  key named in the L3 header.
- **Headers** — `alg` pinned to ES256 and `typ` checked per layer and mode.
- **`_sd_alg`** — must be `sha-256` when present, at all layers.
- **Duplicate `_sd` digests** — rejected per RFC 9901 §7.1 at all layers.
- **Time claims** — `exp` / `iat` validated against a configurable
  `clockSkewSeconds` (default 300s); malformed time claims fail closed.
- **L1↔L2 binding** — L2 `sd_hash` must match the presented L1 serialized form;
  L1 `vct` is checked against the expected value.
- **L2 `aud` / `nonce`** — matched against caller-provided expected values.
- **Mandate pairing** — L2 `delegate_payload` disclosures are grouped into
  checkout/payment pairs with orphan, duplicate, and smuggling (duplicate
  disclosure reference) detection.
- **`card_id` cross-check** — L1 `card_id` must match each payment mandate's
  `payment_instrument.id`.
- **Per-mode mandate rules** — immediate mode requires final values and no
  `cnf`; autonomous (open) mandates must carry their pairing constraints.
- **Agent-key consistency** — the delegation `cnf.jwk` (and `kid`) must be
  identical across all mandate pairs.
- **L3 binding** — L3 `sd_hash` must match the presented L2 serialized form, and
  the L2 presentation must include the L3's own mandate-pair disclosure
  (L3-to-mandate-pair identity binding).
- **L3 restrictions** — no `cnf` claim, lifetime ≤ 1 hour, header `kid` required
  and matched when the L2 `cnf.jwk` names one.
- **L3a↔L3b cross-reference** — the payment and checkout fulfillments must
  reference each other's transaction.
- **L3 structure** — required mandate fields (vct, transaction ids, payee,
  amount, payment instrument) and L3↔L2 payment-instrument consistency.

Per-transaction **constraint evaluation** (e.g. is this fulfillment within the
mandate's allowlists and amount range?) is a separate exported function,
`checkConstraints`, run by the party evaluating a specific transaction — see the
next section.

## Constraints

Autonomous-mode mandates carry constraints. The stateless ones are enforced by
the verifier (`checkConstraints`); the stateful ones are assigned by the spec to
the payment network and are only *surfaced* by `verifyChain` (see below).

| Constraint | Key fields | Enforced by |
| --- | --- | --- |
| `mandate.checkout.allowed_merchants` | `allowed` | verifier (`checkConstraints`) |
| `mandate.checkout.line_items` | `items`, `match_mode` | verifier (`checkConstraints`) |
| `mandate.payment.allowed_payees` | `allowed` | verifier (`checkConstraints`) |
| `mandate.payment.amount_range` | `currency`, `min`, `max` | verifier (`checkConstraints`) |
| `mandate.payment.budget` | `currency`, `max`, `min` | **payment network** (stateful) |
| `mandate.payment.recurrence` | `frequency`, `start_date`, `end_date`, `number` | **payment network** (stateful) |
| `mandate.payment.agent_recurrence` | `frequency`, `start_date`, `end_date`, `max_occurrences` | **payment network** (stateful) |
| `mandate.payment.reference` | `conditional_transaction_id` | auto-injected by issuance; binding checked by the verifier |

## Network-enforced constraints

Budget and recurrence constraints are *stateful* — enforcing them requires
knowing how much has already been spent or how many installments have run — so
the spec assigns them to the payment network, and this stateless verifier parses
but never evaluates them. That means `valid: true` tells you every stateless
check passed; it does **not** mean a budget or recurrence limit is satisfied.

`verifyChain` surfaces these constraints on the result so the caller (typically
the payment network) knows what it still must enforce:

```ts
const result = await verifyChain(l1, l2, opts);
for (const ne of result.networkEnforced) {
  // ne.pairIndex  — which mandate pair it came from
  // ne.type       — e.g. 'mandate.payment.budget'
  // ne.constraint — the raw constraint object from the payment mandate
  enforceAtTheNetwork(ne); // your stateful enforcement here
}
```

`networkEnforced` is always present — an empty array when no payment mandate
carries budget/recurrence constraints.

## VerifyChainOptions highlights

- `issuerPublicJwk` — the issuer's public key; required unless
  `skipIssuerVerification` is explicitly set (test-only bypass).
- `currentTime` — Unix seconds; inject to verify fixed-timestamp credentials
  deterministically (defaults to the wall clock).
- `clockSkewSeconds` — tolerance for `exp`/`iat` checks (default 300).
- `expectedL2Aud` / `expectedL2Nonce` — bind the L2 to the intended audience and
  the nonce you issued for this flow.
- `expectedL3{Payment,Checkout}{Aud,Nonce}` — the same for each L3.
- `splitL3s` — per-pair L3a/L3b credentials plus the role-specific L2
  presentations (`l2PaymentSerialized` / `l2CheckoutSerialized`) they bind to.

## Layout

```
src/
  crypto/        ES256 signing, base64url, disclosures, SD-JWT, KB-SD-JWT
  models/        issuer credential, user mandate, agent mandate, constraints
  issuance/      createLayer1 / layer2 (immediate + autonomous) / layer3 (split)
  verification/  verifyChain (L1→L2→split-L3), integrity bindings, constraint checker
```

The build (`tsdown`) emits dual **ESM + CJS** with bundled type declarations and
no externals — the package has zero runtime dependencies. `verifyChain` accepts
a `currentTime` option so fixed-timestamp credentials can be verified
deterministically.

The conformance vectors are regenerated from the Python reference with
`python/scripts/generate_vectors.py`. License: Apache-2.0.
