# Verifiable Intent — TypeScript

TypeScript implementation of the [Verifiable Intent](../README.md) credential format:
a layered SD-JWT delegation chain (Issuer → User → Agent) that produces cryptographic
proof an AI agent's commercial actions stayed within the scope a human explicitly
delegated.

This is the **TypeScript** package of the Verifiable Intent monorepo, a port of the
[`../python`](../python) reference implementation. It is built on the
[`@sd-jwt`](https://github.com/openwallet-foundation-labs/sd-jwt-js) primitives
(`@sd-jwt/crypto-nodejs` for ES256) with the Verifiable-Intent-specific layering,
`delegate_payload` mechanism, and split-L3 logic hand-rolled to stay byte-compatible
with the Python implementation.

> **Status:** `crypto`, `models`, `issuance`, and `verification` are implemented
> and validated byte-for-byte (issuance) and verdict-for-verdict (verification)
> against Python-generated conformance vectors
> ([`../test-vectors/vectors.json`](../test-vectors)). The vitest suite (180
> tests) replays every shared golden vector — asserting Python's exact error
> strings — plus TS-specific parity, fail-closed hardening, and end-to-end
> issue→verify round-trip tests.

## Install & test

```bash
npm install
npm test          # vitest, validates against ../test-vectors
npm run build     # tsdown -> dist/ (dual ESM + CJS + .d.ts)
npm run typecheck # tsc --noEmit
npm run lint      # eslint
```

## Layout

```
src/
  crypto/        ES256 signing, base64url, disclosures, SD-JWT, KB-SD-JWT
  models/        issuer credential, user mandate, agent mandate, constraints
  issuance/      createLayer1 / layer2 (immediate + autonomous) / layer3 (split)
  verification/  verifyChain (L1→L2→split-L3), integrity bindings, constraint checker
```

The build (`tsdown`) emits dual **ESM + CJS** with bundled type declarations; the
`@sd-jwt/*` runtime deps are externalized. `verifyChain` accepts a `currentTime`
option so fixed-timestamp credentials can be verified deterministically.

The conformance vectors are regenerated from the Python reference with
`python/scripts/generate_vectors.py`. License: Apache-2.0.
