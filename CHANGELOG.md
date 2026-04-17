# Changelog

All notable changes to this project will be documented in this file. Every rule-bundle
version carries a dated identifier (`sdaia-scc-vX.Y-YYYY-MM-DD`) so historical
attestations remain reproducible.

## [0.1.0-draft] - 2026-04-17

Initial scaffold. Pre-counsel-review.

### Added
- Repository structure per DataSitr_SCC_Verifier_Design_Spec.md
- JSON Schemas (v1): SCC canonical form, attestation envelope, evidence credential
- First three Rego rules: STRUCT-001, VAL-GOV-LAW, VAL-BREACH-SDAIA
- First three test vectors: one known-good, one known-bad, one judgment-required
- Python verifier scaffolding with CLI entry point
- License posture: Apache-2.0 for code and rules, CC0-1.0 for schemas and test vectors

### Not yet included (next iterations)
- Full 40-rule catalog (target: v0.3)
- OPA/Rego evaluator integration (stubbed in v0.1)
- Evidence resolver integration with DataSitr compliance registers (target: v0.4)
- Attestation signing with Ed25519 (target: v0.2)
- Offline web verifier (target: v0.5)
- SDAIA ratification (not scheduled)

### Status
- **Not ratified by SDAIA.**
- **Not yet reviewed by Saudi-licensed counsel.**
- Attestations produced by this version carry `ratification_status: not-yet-ratified-by-sdaia`.
