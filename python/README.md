# Verifiable Intent — Python

Reference implementation of the [Verifiable Intent](../README.md) credential format: a
layered SD-JWT delegation chain (Issuer → User → Agent) that produces cryptographic proof
an AI agent's commercial actions stayed within the scope a human explicitly delegated.

This is the **Python** package of the Verifiable Intent monorepo. A byte-compatible
TypeScript port lives in [`../typescript`](../typescript).

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from verifiable_intent import (
    IssuerCredential, create_layer1,
    UserMandate, MandateMode, create_layer2_immediate,
    verify_chain,
)
```

See [`examples/`](examples) for full Immediate and Autonomous flows, and
[`../spec`](../spec) for the normative specification.

## Develop

```bash
ruff check src/ tests/ examples/
pytest tests/ -v
```

The public API surface is locked by `tests/test_package_exports.py`. License: Apache-2.0.
