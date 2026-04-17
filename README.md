# datasitr-scc-verifier

**Machine-verifiable compliance for SDAIA Standard Contractual Clauses under the Saudi Personal Data Protection Law (PDPL).**

A deterministic, transparent, cryptographically-attestable verifier that produces signed verdicts about whether a given SCC document satisfies the structural, value-bound, reference-integrity, freshness, and regulatory-anchor requirements of the SDAIA SCC template (issued 2 September 2024) and the Regulation on Personal Data Transfer Outside the Kingdom (1 September 2024).

The verifier honestly flags judgment-bound clauses (liability reasonableness, government-access warranties, etc.) as requiring human review. It does not replace Saudi-licensed counsel; it focuses counsel time on the clauses that actually require legal judgment.

This is a reference implementation. It is offered to SDAIA for ratification and to the wider Saudi data-protection community as a public good.

## Status

**Version:** 0.1.0-draft (pre-counsel-review)
**Ratification:** Not yet ratified by SDAIA.
**License:** Apache-2.0 for code and rule bundle; CC0 for schemas and test vectors.

## What this verifier does

Given three inputs:

1. An SCC document in canonical form (JSON, conforming to `schemas/scc-canonical-v1.json`)
2. A signed rule bundle (structure: `rules/` + `schemas/` + `test_vectors/` + signed manifest)
3. An evidence bundle (TRA records, TOMs snapshots, sub-processor registry, all as signed W3C Verifiable Credentials)

It produces an Ed25519-signed attestation (`schemas/attestation-envelope-v1.json`) with:

- Per-check verdicts across 40+ machine-checkable rules
- Cryptographic evidence links for every substantive field
- Explicit `REQUIRES_HUMAN_REVIEW` flags for judgment clauses
- A rule-bundle version and hash so the verdict is reproducible forever

Every verdict is **deterministic**: the same inputs always produce the same output. A third party with the same inputs and the same rule bundle can independently reproduce any attestation.

## What this verifier does NOT do

- It does not produce legal validity. Only signatures from both parties under KSA law do that.
- It does not replace counsel. It focuses counsel work on judgment clauses.
- It does not decide commercial reasonableness. It flags those clauses.
- It does not verify counterparty good faith. Cryptographic evidence is not moral evidence.
- It is not an AI system. There is no model, no inference, no probabilistic output. It is policy-as-code.

## Standards

Every primitive is a well-reviewed standard. No novel cryptography.

- **Ed25519 signatures** (RFC 8032)
- **SHA-256 hashing** (FIPS 180-4)
- **JSON Canonicalization Scheme** (RFC 8785) for deterministic hashing
- **JSON Schema Draft 2020-12** for structural validation
- **Open Policy Agent / Rego** for semantic rules
- **W3C Verifiable Credentials v2.0** for evidence and attestation envelopes
- **NIST OSCAL** referenced for TOMs structure
- **Saudi Electronic Transactions Law (Royal Decree M/18)** recognises the electronic-signature posture
- **Saudi PDPL (Royal Decree M/19) + Data Transfer Regulations 2024-09-01** — rule source

## Quick start

```bash
# Install
pip install datasitr-scc-verifier

# Verify an SCC document
scc-verify \
  --scc path/to/scc.json \
  --bundle sdaia-scc-v0.1.bundle \
  --evidence path/to/evidence/ \
  --signing-key path/to/verifier.ed25519 \
  --out attestation.json

# Run the test vector corpus to validate the bundle
scc-verify --bundle sdaia-scc-v0.1.bundle --run-vectors
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
│   ├── reference/
│   ├── freshness/
│   ├── anchor/
│   └── judgment/
├── test_vectors/                   # Test corpus (CC0)
│   ├── known_good/
│   ├── known_bad/
│   └── judgment_required/
├── scc_verifier/                   # Python library (Apache-2.0)
├── tests/
└── docs/
```

## Relationship to Data Sitr Est.

Data Sitr Est. (SDAIA Registration #3260005651) maintains this project as an open-source public good. The reference implementation is integrated into the DataSitr privacy-preserving AI gateway product, but the verifier, schemas, rule bundle, and test vectors are all released under permissive licenses so they can be used, audited, forked, or ratified independently of any commercial DataSitr relationship.

## Ratification pathway

We are seeking SDAIA ratification of the rule bundle as an authoritative reference for Data Transfer Regulations compliance. Until ratified, every attestation carries `ratification_status: not-yet-ratified-by-sdaia` in its envelope. After ratification, the rule bundle will be co-signed by SDAIA.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We actively welcome adversarial test vectors from the Saudi PDPL community.

## Disclaimer

Data Sitr Est. is not Saudi-licensed counsel. This repository is not legal advice. An attestation is a cryptographic claim about conformance to a rule bundle, not a legal opinion about the underlying transfer's lawfulness. Seek Saudi-licensed counsel for any enforcement-adjacent decision.
