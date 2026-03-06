# How to Contribute

We would love to accept your patches and contributions to this project.

## Before You Begin

### Sign Off Your Commits (DCO)

Contributions to this project must include a
[Developer Certificate of Origin](https://developercertificate.org/) (DCO)
sign-off. This certifies that you wrote or have the right to submit the code
under the project's open-source license. You (or your employer) retain the
copyright to your contribution.

Add the sign-off by including a `Signed-off-by` line in your commit messages:

```
Signed-off-by: Your Name <your.email@example.com>
```

You can do this automatically with `git commit -s`.

### Review Our Code of Conduct

This project follows the [Verifiable Intent Code of Conduct](CODE_OF_CONDUCT.md).

## Contribution Process

### Code Reviews

All submissions, including submissions by project members, require review. We
use [GitHub pull requests](https://docs.github.com/articles/about-pull-requests)
for this purpose.

### Pull Request Requirements

- **PR titles**: Use [Conventional Commits](https://www.conventionalcommits.org/)
  format (e.g., `feat: add recurrence constraint validation`,
  `fix: correct cart hash binding in autonomous mode`). Individual commit
  messages within a PR are not required to follow this format.
- **Tests**: All code changes should include tests or demonstrate no regression
  against the existing test suite. Run `pytest` from the repo root to verify.
- **DCO sign-off**: Every commit must include a `Signed-off-by` line.

### Specification Changes

Changes to files in `spec/` define the normative standard and carry additional
requirements:

- **Rationale required**: The PR description must include a motivation section
  explaining *why* the change is needed, what problem it solves, and any
  alternatives considered.
- **SDK consistency**: Spec changes that affect claim names, validation rules, or
  credential structure should include corresponding SDK and test updates, or
  clearly note what SDK work remains.
- **Protocol-agnostic language**: The core spec (`spec/`) must not reference any
  specific transport protocol (AP2, ACP, etc.). Protocol-specific mappings
  belong in `protocol-landscape/`.

### Protocol Landscape Changes

Changes to `protocol-landscape/` should reference the specific protocol version being
targeted and validate any JSON examples against the protocol's published schema
or OpenAPI spec where available.

## Getting Started

### Prerequisites

- Python 3.10+
- pip 22+

```bash
# Verify Python version
python --version

# Clone the repo
git clone https://github.com/agent-intent/verifiable-intent.git
cd verifiable-intent

# Install with dev dependencies (includes pytest)
pip install -e ".[dev]"

# Run the test suite
pytest

# Run an example
python examples/autonomous_flow.py
```

## Reporting Issues

Use [GitHub Issues](https://github.com/agent-intent/verifiable-intent/issues)
to report bugs or request features. For security vulnerabilities, see
[SECURITY.md](SECURITY.md).
