# Changelog

All notable changes to this project will be documented in this file. Every
rule-bundle version carries a dated identifier (`sdaia-scc-vX.Y-YYYY-MM-DD`)
so historical attestations remain reproducible.

## [0.2.1-draft] - 2026-05-23

Public-credibility hardening pass before broad release.

### Changed

- Missing OPA no longer produces a clean-looking `PASS`. Layer 2 checks are
  marked `INCOMPLETE`, the overall verdict becomes `INCOMPLETE`, and the CLI
  exits non-zero by default.
- Added `--allow-incomplete-without-opa` for workflows that intentionally want
  to emit a Layer-1-only attestation while preserving the `INCOMPLETE` verdict.
- Added `RULE-BUNDLE-MATCH`; `rule_bundle_required` must match the active
  bundle ID or the attestation fails.
- Aligned all shipped test vectors to the active bundle ID.
- Reworded the README and package description around the actual v0.2 scope:
  canonical JSON validation, initial Rego rules, counsel-review flags, and
  signed draft attestations. Official SCC text verification, evidence,
  freshness, and reference-integrity checks remain out of scope for v0.2.

### Test suite

- 69 passing. Added regressions for missing OPA, explicit incomplete allowance,
  bundle-ID mismatch, and vector/bundle drift.
- New regressions live in `tests/test_incomplete_and_bundle_match.py`.

### Not ratified by SDAIA. Not reviewed by Saudi-licensed counsel.

No SDAIA ratification is implied. Attestations continue to carry
`ratification_status: not-yet-ratified-by-sdaia`.

---

## [0.2.0-draft] - 2026-04-18

Layer 2 goes live. OPA/Rego evaluator integrated end-to-end.

### Added

- `scc_verifier/rego_evaluator.py` — subprocess-based OPA 1.x evaluator with a
  concrete `RULE_REGISTRY` of the 9 shipped rules (STRUCT-001, VAL-GOV-LAW,
  VAL-DISPUTE-FORUM, VAL-BREACH-EXPORTER, VAL-BREACH-SDAIA, VAL-SENSITIVE-ROUTE,
  JUDGE-LIAB-001, JUDGE-GOV-ACCESS-001, JUDGE-INDEM-001). Binary discovery via
  `SCC_OPA_BIN` env var or `$PATH`; `OpaNotFoundError` carries install
  instructions when absent.
- `tests/test_rego_evaluator.py` — 8 regression tests, auto-skip when the OPA
  binary is unavailable so CI environments without OPA still pass the rest of
  the suite.
- `verify()` now calls the Rego evaluator after schema validation and emits a
  multi-check attestation. The initial 0.2.0 draft emitted Layer-1-only
  attestations with `NOT_APPLICABLE` placeholders when OPA was absent; 0.2.1
  hardens that behavior to `INCOMPLETE`.
- `README.md` updated with an OPA install section.

### Changed

- All 5 Rego rule files migrated from pre-1.0 Rego syntax to **Rego v1**
  (`import rego.v1`, `if` keyword on rule bodies, `contains` keyword on partial
  set rules, `some ... in ...` iteration).
- Test vector `*.expected.json` files now carry `v0_2_expected` matching the
  shipped semantic verdicts:
  - `known_good/ksa_domestic_scc`: `PASS_WITH_COUNSEL_ITEMS` (6 PASS + 3 REVIEW)
  - `known_bad/missing_governing_law`: `FAIL` (VAL-GOV-LAW and VAL-DISPUTE-FORUM
    fire; `pending_layer_2: true` removed)
  - `known_bad/sensitive_onward_transfer`: `FAIL` (VAL-SENSITIVE-ROUTE fires;
    `pending_layer_2: true` removed)
  - `known_bad/structurally_malformed`: `FAIL` (Layer 1 catches it; Layer 2
    skipped as `NOT_APPLICABLE`)
  - `judgment_required/needs_counsel_review`: `PASS_WITH_COUNSEL_ITEMS`
    (JUDGE-* rules flag correctly; `pending_layer_2: true` removed)
- `run-vectors` expectation priority updated to
  `v0_2_expected > verdict > v0_1_expected`.

### Test suite

- 58 passing (was 50). Layer 2 determinism, rule-registry integrity, and
  per-rule outcome regressions all covered.
- All 5 test vectors run cleanly, 0 divergences, 0 skipped.

### Known limitations carried forward

- Layer 3 (evidence resolution against TRA / TOMs / subprocessor credentials)
  still deferred to v0.3.
- Attestation chain continuity (`prev_attestation_hash` threading) still
  deferred to v0.3.
- No `.well-known/scc-verifier-keys.json` key registry yet.
- Published signed bundle archive (`bundle.json` + `MANIFEST.ed25519`) still
  deferred; v0.2 continues to compute the bundle hash over the live repo
  directory tree.

### Not ratified by SDAIA. Not yet reviewed by Saudi-licensed counsel.
Attestations produced by this version carry `ratification_status: not-yet-ratified-by-sdaia`.

---

## [0.1.0-draft] - 2026-04-17

Initial scaffold. Pre-counsel-review.

### Added

- Repository structure for the initial draft SCC verifier
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
