# Changelog

All notable changes to this project will be documented in this file. Every
rule-bundle version carries a dated identifier (`sdaia-scc-vX.Y-YYYY-MM-DD`)
so historical attestations remain reproducible.

## [0.1.0-draft] - 2026-04-17

Initial scaffold. Pre-counsel-review.

### Added

- Repository structure per DataSitr_SCC_Verifier_Design_Spec.md
- JSON Schemas (v1): SCC canonical form, attestation envelope, evidence credential
- First 9 Rego rules: STRUCT-001, VAL-GOV-LAW, VAL-DISPUTE-FORUM, VAL-BREACH-EXPORTER,
  VAL-BREACH-SDAIA, VAL-SENSITIVE-ROUTE, JUDGE-LIAB-001, JUDGE-GOV-ACCESS-001,
  JUDGE-INDEM-001
- Test vectors: 1 known-good, 3 known-bad, 1 judgment-required, each with a
  per-vector `*.expected.json`
- Python verifier library with CLI entry point (`scc-verify`)
- License posture: Apache-2.0 for code and rules, CC0-1.0 for schemas and
  test vectors

### v0.1 correctness guarantees

These were not all in the very first commit — they land in the v0.1.0 release
commit after an external review flagged gaps in the initial scaffold:

- **Attestations are real.** Ed25519 signing is wired end-to-end; `proofValue`
  is a real base64url-encoded signature over the canonical envelope bytes.
  Ephemeral keypairs are supported for CI/demo use and emit a `UserWarning`.
- **Attestations self-validate.** `scc-verify verify` runs the emitted envelope
  through `schemas/attestation-envelope-v1.json` before writing it; the command
  exits non-zero if the envelope fails its own schema.
- **Rule-bundle hash is real.** `rule_bundle.hash` is SHA-256 of a deterministic
  manifest of schemas and Rego files; any file change invalidates the hash and
  is detectable by any third party reproducing the verification.
- **Date formats are enforced.** Layer 1 validation uses `FormatChecker()`,
  catching malformed `date` / `date-time` fields that would silently pass in
  a default `Draft202012Validator`.
- **`run-vectors` fails on divergence.** Exit code is 0 only when every
  non-pending vector matches its `v0_1_expected` outcome.
- **README matches code.** Documented CLI flags, Python API functions, and
  claimed behavior all correspond to what actually runs.

### Layer 2 scope (pending for v0.2)

The OPA/Rego evaluator is not yet wired. Test vectors that exercise semantic
rules (governing-law mismatch, Article-18 onward-transfer violation, liability
judgment flag) carry `pending_layer_2: true` in their expected files and are
skipped by `run-vectors`. They remain in the tree as the canonical regression
suite for the Layer 2 implementation.

### Layer 3 scope (pending for v0.2)

Evidence resolution (querying TRA registers, TOMs snapshots, sub-processor
lists as W3C Verifiable Credentials) is not yet implemented.

### Status

- **Not ratified by SDAIA.**
- **Not yet reviewed by Saudi-licensed counsel.**
- Attestations produced by this version carry `ratification_status: not-yet-ratified-by-sdaia`.
