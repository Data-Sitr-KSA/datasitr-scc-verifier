# datasitr-scc-verifier

[![CI](https://github.com/Data-Sitr-KSA/datasitr-scc-verifier/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Data-Sitr-KSA/datasitr-scc-verifier/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Data-Sitr-KSA/datasitr-scc-verifier/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Data-Sitr-KSA/datasitr-scc-verifier/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Data-Sitr-KSA/datasitr-scc-verifier/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Data-Sitr-KSA/datasitr-scc-verifier)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![Draft SCC canonical verifier](https://img.shields.io/badge/SCC_verifier-draft_canonical_form-informational)](schemas/scc-canonical-v1.json)

**Draft reference implementation for machine-checkable elements of Saudi SCC transfer documentation.**

v0.3 validates the DataSitr canonical SCC JSON form, checks that the document requires the active rule bundle, evaluates a small initial Open Policy Agent/Rego rule bundle, flags judgment-bound fields for counsel review, emits a signed draft attestation, and can verify attestations against a public key registry.

It does **not** verify the official signed SCC contract text, template selection, permitted blanks, all role-specific obligations, conflicts with additional terms, evidence references, freshness, or complete SDAIA SCC conformity. It is not ratified by SDAIA and is not legal advice.

This is an experimental reference implementation released for technical review. The intended use is transparent, reproducible checking of a canonical representation, not replacement of Saudi-licensed counsel.

## Status

- **Version:** 0.3.0-draft (pre-counsel-review)
- **Ratification:** Not yet ratified by SDAIA. Attestations carry `ratification_status: not-yet-ratified-by-sdaia`.
- **License:** Apache-2.0 for code; CC0-1.0 for schemas and test vectors.

## What v0.3 actually does (scope ratchet; read this before citing)

| Layer | What it is | v0.3 status |
|---|---|---|
| **1. Structural** | JSON Schema Draft 2020-12 validation of the SCC canonical JSON form, with `format: date` / `format: date-time` enforced via `FormatChecker`. | **Live and tested.** Regression tests cover missing clauses, bad date formats, out-of-range values, and enum violations. |
| **1b. Bundle identity** | `rule_bundle_required` must match the active verifier bundle ID. | **Live and tested.** A mismatch produces `RULE-BUNDLE-MATCH: FAIL`; semantic rules are not treated as verified under the wrong bundle. |
| **2. Semantic/judgment** | Rego rules (Open Policy Agent) encoding a small initial set of value-bound and judgment constraints. 9 rules are authored in `rules/` across 5 files. | **Live when OPA is available.** If OPA is missing, Layer 2 checks are marked `INCOMPLETE` and the overall verdict cannot be `PASS`. |
| **3. Evidence/reference/freshness** | Cross-reference integrity against TRA registers, TOMs snapshots, sub-processor lists, freshness windows, and W3C Verifiable Credentials. | **Deferred.** Not implemented in v0.3. |
| **4. Attestation** | Ed25519-signed envelope, SHA-256 rule-bundle hash, W3C VC v2 shape, self-validating against `schemas/attestation-envelope-v1.json`. | **Live.** Real signing with either an explicit `--signing-key` or an ephemeral keypair (emits a `UserWarning`). Attestations can be verified with a local public key or a validated public key registry. |

v0.3 is a floor, not a ceiling. The envelope schema, rule-bundle ID, and rule-bundle hash are versioned so future rule additions can preserve reproducibility for attestations produced under prior bundles.

## Runtime requirement: OPA binary

Layer 2 evaluation requires the [Open Policy Agent](https://www.openpolicyagent.org/) binary (v0.50 or later, v1.x recommended). Install:

- **macOS:** `brew install opa`
- **Linux:** `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x opa && sudo mv opa /usr/local/bin/`
- **Docker:** `docker run openpolicyagent/opa:latest`

If the binary is not discoverable, attestations are still emitted but Layer 2 checks are marked `INCOMPLETE`, the overall verdict is `INCOMPLETE`, and `scc-verify verify` exits non-zero. To intentionally allow this in a Layer-1-only environment, pass `--allow-incomplete-without-opa`; the emitted verdict remains `INCOMPLETE`.

Set `SCC_OPA_BIN=/path/to/opa` to use a non-PATH location.

## What this verifier does NOT do

- It does not produce legal validity. Only signatures from both parties under KSA law do that.
- It does not replace counsel. It focuses counsel work on judgment clauses.
- It does not verify the official SDAIA SCC document text or prove that only permitted blanks were modified.
- It does not select among role-specific SCC templates or verify every role-specific obligation.
- It does not detect conflicts between additional commercial terms and mandatory SCC text.
- It does not resolve evidence, reference integrity, or freshness yet.
- It does not decide commercial reasonableness. It flags those clauses.
- It does not verify counterparty good faith. Cryptographic evidence is not moral evidence.
- It is not an AI system. There is no model, no inference, no probabilistic output. It is deterministic policy-as-code.

## Standards

Every primitive is a well-reviewed standard. No novel cryptography.

- **Ed25519 signatures** (RFC 8032)
- **SHA-256 hashing** (FIPS 180-4)
- **JSON Canonicalization Scheme** (RFC 8785) for deterministic hashing
- **JSON Schema Draft 2020-12** for structural validation, with `FormatChecker` enforcing `date` / `date-time`
- **Open Policy Agent / Rego** for semantic and judgment rules
- **W3C Verifiable Credentials v2.0** for evidence and attestation envelopes
- **NIST OSCAL** referenced for TOMs structure
- **Saudi Electronic Transactions Law (Royal Decree M/18)** referenced as electronic-signature context, not as a legal-validity determination
- **Saudi PDPL (Royal Decree M/19) + Data Transfer Regulations 2024-09-01** — rule source

## Quick start

```bash
# Install the OPA binary (required for Layer 2)
brew install opa   # or see "Runtime requirement" above for Linux / Docker

# Install the verifier
pip install -e .

# Inspect the active rule bundle (useful for reviewers)
scc-verify bundle info
scc-verify bundle info --format json --verbose

# Generate a signing key (one-time, per deployment)
scc-verify keygen \
  --out ./keys/verifier.ed25519 \
  --public-out ./keys/verifier.pub.pem

# Verify an SCC document with that key
scc-verify verify \
  --scc test_vectors/known_good/ksa_to_foreign_processor_scc.json \
  --signing-key ./keys/verifier.ed25519 \
  --out attestation.json

# Or verify with an ephemeral key (produces a UserWarning; signatures
# cannot be verified after the process exits)
scc-verify verify --scc test_vectors/known_good/ksa_to_foreign_processor_scc.json

# Run the packaged test-vector corpus
scc-verify run-vectors

# Verify a signed attestation with the deployment public key
scc-verify verify-attestation \
  --attestation attestation.json \
  --public-key ./keys/verifier.pub.pem
```

### Verifying an attestation against the published key registry

```bash
scc-verify keys list --registry https://datasitr.com/.well-known/scc-verifier-keys.json
scc-verify verify-attestation --attestation attestation.json \
  --key-registry https://datasitr.com/.well-known/scc-verifier-keys.json
```

See [docs/public-key-registry.md](docs/public-key-registry.md) for the full operator and verification flow.

The emitted attestation is **self-validated against `schemas/attestation-envelope-v1.json`** before it is written. If the envelope fails its own schema, `scc-verify verify` exits non-zero and does not emit the document.

## Development

```bash
# Install dev tools
pip install -e ".[dev]"

# Quality gates (all required in CI)
ruff check scc_verifier tests
ruff format --check scc_verifier tests
mypy                                  # config in pyproject.toml
pytest -v

# CI runs the above across Python 3.11, 3.12, 3.13 on Ubuntu + macOS.
# A second CI job explicitly runs without OPA installed to lock the
# incomplete-evaluation contract.
```

## Security

See [SECURITY.md](SECURITY.md) for responsible-disclosure instructions, the in-scope / out-of-scope list, and the cryptographic primitive inventory. Never file security issues publicly.

## Python API

```python
from scc_verifier import verify, validate_schema, self_validate
import json

with open("path/to/scc.json") as f:
    scc = json.load(f)

# Layer 1 only — fast, no signing
check = validate_schema(scc)
assert check.valid, check.errors

# Full verify with a real attestation
attestation = verify(scc)            # ephemeral key (warns)
# or: attestation = verify(scc, signing_key=my_ed25519_private_key)

# Confirm the envelope is self-consistent
result = self_validate(attestation)
assert result.valid, result.errors

# Ship it
print(json.dumps(attestation.to_dict(), indent=2))
```

## Project layout

```
datasitr-scc-verifier/
├── schemas/                        # JSON Schemas (CC0)
│   ├── scc-canonical-v1.json
│   ├── attestation-envelope-v1.json
│   ├── evidence-credential-v1.json
│   └── public-key-registry-v1.json
├── rules/                          # Rego rule bundle (Apache-2.0)
│   ├── structural/
│   ├── value/
│   └── judgment/
├── test_vectors/                   # Test corpus (CC0)
│   ├── known_good/
│   │   ├── ksa_to_foreign_processor_scc.json
│   │   └── ksa_to_foreign_processor_scc.expected.json
│   ├── known_bad/
│   │   ├── structurally_malformed.json          # Layer 1 FAIL
│   │   ├── structurally_malformed.expected.json
│   │   ├── missing_governing_law.json           # Layer 2 semantic FAIL
│   │   ├── missing_governing_law.expected.json
│   │   ├── arbitration_forum_without_counsel_basis.json
│   │   └── arbitration_forum_without_counsel_basis.expected.json
│   └── judgment_required/
│       ├── needs_counsel_review.json            # Layer 2 counsel-review verdict
│       ├── needs_counsel_review.expected.json
│       ├── sensitive_onward_transfer_needs_counsel.json
│       └── sensitive_onward_transfer_needs_counsel.expected.json
├── scc_verifier/                   # Python library (Apache-2.0)
│   ├── api.py              # verify(), validate_schema(), self_validate()
│   ├── attestation_verifier.py # third-party attestation signature checks
│   ├── bundle.py           # rule-bundle hashing
│   ├── canonicalization.py # RFC 8785
│   ├── cli.py              # scc-verify
│   ├── schema_validator.py # Layer 1 with FormatChecker
│   └── signing.py          # Ed25519 keypair ops
├── docs/
│   ├── public-key-registry.md
│   └── scc-template-conformance.md
├── examples/
│   └── scc-verifier-keys.example.json
└── tests/
```

## Relationship to Data Sitr Est.

Data Sitr Est. maintains this project as an open-source public good. The reference implementation is integrated into the DataSitr privacy-preserving AI gateway product, but the verifier, schemas, rule bundle, and test vectors are all released under permissive licenses so they can be used, audited, forked, or ratified independently of any commercial DataSitr relationship. Any organization relying on DataSitr's regulatory registrations or commercial claims should verify them through the relevant Saudi authority or a direct DataSitr due-diligence channel.

## Counsel-review checklist

Before any public claim stronger than "draft canonical-form verifier", each legal rule needs a short counsel note with source citation, interpretation boundary, and expected dispute handling:

- `VAL-GOV-LAW` and `VAL-DISPUTE-FORUM`: confirm accepted KSA jurisdiction/forum language and any permitted alternatives.
- `VAL-BREACH-EXPORTER` and `VAL-BREACH-SDAIA`: confirm notification windows and triggering conditions.
- `VAL-SENSITIVE-ROUTE`: confirm sensitive-data onward-transfer conditions: third-party accession, role-template fit, additional safeguards, and transfer-risk assessment evidence.
- `JUDGE-LIAB-001`, `JUDGE-GOV-ACCESS-001`, `JUDGE-INDEM-001`: confirm these remain review flags, not automated legal decisions.

## Roadmap

- **v0.3:** evidence credentials, reference integrity for TRA/TOMs/sub-processor references, and freshness checks.
- **v0.4:** official-template conformance path: parser/extractor, mandatory-clause hashes, role-template mapping, and permitted-blank verification.
- **v1.0:** counsel-reviewed rule bundle, frozen rule IDs, signed release artifacts, and documented ratification posture.

See [docs/scc-template-conformance.md](docs/scc-template-conformance.md) for the
template-conformance path and [docs/public-key-registry.md](docs/public-key-registry.md)
for the deferred public-key registry.

## Ratification pathway

No SDAIA ratification is implied. Until any formal ratification occurs, every attestation carries `ratification_status: not-yet-ratified-by-sdaia` in its envelope. A ratified release would require formal review and co-signed rule-bundle artifacts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We actively welcome adversarial test vectors from the Saudi PDPL community.

## Disclaimer

Data Sitr Est. is not Saudi-licensed counsel. This repository is not legal advice. An attestation is a cryptographic claim about conformance to a rule bundle, not a legal opinion about the underlying transfer's lawfulness. Seek Saudi-licensed counsel for any enforcement-adjacent decision.
