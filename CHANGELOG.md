# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `create_layer2_autonomous` now writes `UserMandate.prompt_summary` into the checkout mandate disclosure (credential-format.md §4.5.1); it was accepted but silently dropped.

## [0.1.0] - 2026-02-19

### Added

- Normative specification: architecture overview, credential format, constraint
  types, security model, design rationale
- Python reference SDK: ES256 signing, SD-JWT/KB-SD-JWT, layered credential
  issuance (L1/L2/L3), chain verification, constraint checking
- Two execution modes: Immediate (2-layer, user-present) and Autonomous
  (3-layer, agent-delegated)
- Split L3 architecture: L3a (payment mandate → payment network) and L3b
  (checkout mandate → merchant) with selective sd_hash binding
- Multi-mandate-pair L2 support with mode-specific pairing and orphan/duplicate
  detection
- Five constraint types: mandate.checkout.line_items,
  mandate.checkout.allowed_merchants, mandate.payment.allowed_payees,
  mandate.payment.amount_range, mandate.payment.reference
- Checkout-payment hash binding via checkout_hash (SHA-256 of checkout_jwt)
- Selective disclosure with role-specific presentation routing
- Strictness modes for constraint validation (PERMISSIVE / STRICT)
- Five standalone examples with assertions (autonomous flow, immediate flow,
  selective disclosure, constraint checking, network validation)
- Protocol landscape guide with cross-protocol glossary
- Community docs: CONTRIBUTING (DCO), CODE_OF_CONDUCT (Contributor Covenant),
  SECURITY (vulnerability reporting)
- MkDocs documentation site with Material theme
- CI quality gates: ruff lint/format, pytest (Python 3.10–3.13, 3 OS),
  docs build
- 268 tests across 17 test files

[0.1.0]: https://github.com/agent-intent/verifiable-intent/releases/tag/v0.1.0
