# datasitr-scc-verifier

**Machine-verifiable compliance for SDAIA Standard Contractual Clauses under the Saudi Personal Data Protection Law (PDPL).**

A deterministic, transparent, cryptographically-attestable verifier that produces signed verdicts about the structural, value-bound, reference-integrity, freshness, and regulatory-anchor requirements of the SDAIA SCC template (issued 2 September 2024) and the Regulation on Personal Data Transfer Outside the Kingdom (1 September 2024).

The verifier honestly flags judgment-bound clauses (liability reasonableness, government-access warranties, etc.) as requiring human review. It does not replace Saudi-licensed counsel; it focuses counsel time on the clauses that actually require legal judgment.

This is a reference implementation. It is offered to SDAIA for ratification and to the wider Saudi data-protection community as a public good.

## Status

**Version:** 0.2.0-draft (pre-counsel-review)
**Ratification:** Not yet ratified by SDAIA. Attestations carry `ratification_status: not-yet-ratified-by-sdaia`.
**License:** Apache-2.0 for code; CC0-1.0 for schemas and test vectors.

## What v0.2 actually does (scope ratchet; read this before citing)

| Layer | What it is | v0.2 status |
|---|---|---|
| **1. Structural** | JSON Schema Draft 2020-12 validation of the SCC canonical form, with `format: date` / `format: date-time` enforced via `FormatChecker`. | **Live and tested.** 11 regression tests cover missing clauses, bad date formats, out-of-range values, enum violations. |
| **2. Semantic** | Rego rules (Open Policy Agent) encoding value-bound and judgment constraints. 9 rules authored in `rules/` across 5 files. | **Live and evaluated** via the OPA binary subprocess. All 5 shipped test vectors now produce their semantic verdicts with zero divergences. The rule registry drives evaluation; adding a new rule = adding a registry entry plus a `.rego` file. |
| **3. Evidence** | Cross-reference integrity against TRA registers, TOMs snapshots, sub-processor lists via W3C Verifiable Credentials. | **Deferred to v0.3.** |
| **4. Attestation** | Ed25519-signed envelope, SHA-256 rule-bundle hash, W3C VC v2 shape, self-validating against `schemas/attestation-envelope-v1.json`, now carries the full Layer-1+Layer-2 check set. | **Live.** Real signing with either an explicit `--signing-key` or an ephemeral keypair (emits a `UserWarning`). |

v0.2 is a floor, not a ceiling. The public envelope format, schemas, and rule-bundle-hash semantics are stable; new rules ratchet upward through v0.3 and v1.0 without breaking attestations produced under prior bundles.

## Runtime requirement: OPA binary

Layer 2 evaluation requires the [Open Policy Agent](https://www.openpolicyagent.org/) binary (v0.50 or later, v1.x recommended). Install:

- **macOS:** `brew install opa`
- **Linux:** `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x opa && sudo mv opa /usr/local/bin/`
- **Docker:** `docker run openpolicyagent/opa:latest`

If the binary is not discoverable, the verifier degrades gracefully: attestations are still emitted with Layer 1 results, and Layer 2 rule results appear as `NOT_APPLICABLE` with a skip reason. A `UserWarning` surfaces the install instructions. Set `SCC_OPA_BIN=/path/to/opa` to use a non-PATH location.

## What this verifier does NOT do

- It does not produce legal validity. Only signatures from both parties under KSA law do that.
- It does not replace counsel. It focuses counsel work on judgment clauses.
- It does not decide commercial reasonableness. It flags those clauses.
- It does not verify counterparty good faith. Cryptographic evidence is not moral evidence.
- It is not an AI system. There is no model, no inference, no probabilistic output. It is deterministic policy-as-code.

## Standards

Every primitive is a well-reviewed standard. No novel cryptography.

- **Ed25519 signatures** (RFC 8032)
- **SHA-256 hashing** (FIPS 180-4)
- **JSON Canonicalization Scheme** (RFC 8785) for deterministic hashing
- **JSON Schema Draft 2020-12** for structural validation, with `FormatChecker` enforcing `date` / `date-time`
- **Open Policy Agent / Rego** for semantic rules (rules authored; evaluator lands in v0.2)
- **W3C Verifiable Credentials v2.0** for evidence and attestation envelopes
- **NIST OSCAL** referenced for TOMs structure
- **Saudi Electronic Transactions Law (Royal Decree M/18)** recognises the electronic-signature posture
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
scc-verify keygen --out ./keys/verifier.ed25519

# Verify an SCC document with that key
scc-verify verify \
  --scc test_vectors/known_good/ksa_domestic_scc.json \
  --signing-key ./keys/verifier.ed25519 \
  --out attestation.json

# Or verify with an ephemeral key (produces a UserWarning; signatures
# cannot be verified after the process exits)
scc-verify verify --scc test_vectors/known_good/ksa_domestic_scc.json

# Run the packaged test-vector corpus
scc-verify run-vectors
```

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
# graceful-degradation contract.
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
│   └── evidence-credential-v1.json
├── rules/                          # Rego rule bundle (Apache-2.0)
│   ├── structural/
│   ├── value/
│   └── judgment/
├── test_vectors/                   # Test corpus (CC0)
│   ├── known_good/
│   │   ├── ksa_domestic_scc.json
│   │   └── ksa_domestic_scc.expected.json
│   ├── known_bad/
│   │   ├── structurally_malformed.json          # Layer 1 FAIL (v0.1)
│   │   ├── structurally_malformed.expected.json
│   │   ├── missing_governing_law.json           # Layer 2 pending
│   │   ├── missing_governing_law.expected.json
│   │   ├── sensitive_onward_transfer.json       # Layer 2 pending
│   │   └── sensitive_onward_transfer.expected.json
│   └── judgment_required/
│       ├── needs_counsel_review.json            # Layer 2 pending
│       └── needs_counsel_review.expected.json
├── scc_verifier/                   # Python library (Apache-2.0)
│   ├── api.py              # verify(), validate_schema(), self_validate()
│   ├── bundle.py           # rule-bundle hashing
│   ├── canonicalization.py # RFC 8785
│   ├── cli.py              # scc-verify
│   ├── schema_validator.py # Layer 1 with FormatChecker
│   └── signing.py          # Ed25519 keypair ops
└── tests/
```

## Relationship to Data Sitr Est.

Data Sitr Est. (SDAIA Registration #3260005651) maintains this project as an open-source public good. The reference implementation is integrated into the DataSitr privacy-preserving AI gateway product, but the verifier, schemas, rule bundle, and test vectors are all released under permissive licenses so they can be used, audited, forked, or ratified independently of any commercial DataSitr relationship.

## Ratification pathway

We are seeking SDAIA ratification of the rule bundle as an authoritative reference for Data Transfer Regulations compliance. Until ratified, every attestation carries `ratification_status: not-yet-ratified-by-sdaia` in its envelope. After ratification, the rule bundle will be co-signed by SDAIA.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We actively welcome adversarial test vectors from the Saudi PDPL community.

## Disclaimer

Data Sitr Est. is not Saudi-licensed counsel. This repository is not legal advice. An attestation is a cryptographic claim about conformance to a rule bundle, not a legal opinion about the underlying transfer's lawfulness. Seek Saudi-licensed counsel for any enforcement-adjacent decision.
