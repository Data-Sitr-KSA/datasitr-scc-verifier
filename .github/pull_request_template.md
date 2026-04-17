<!--
Thanks for contributing. A few checks before you submit:

1. If this PR changes a rule or adds a new rule, please link the
   governance process in CONTRIBUTING.md and attach the test vector(s)
   that demonstrate the change.
2. If this PR changes a schema, please confirm no shipped attestation
   becomes invalid under the new schema (or provide a migration path).
3. Tests must pass locally: `pytest -q` and `scc-verify run-vectors`.
-->

## What this changes

<!-- One-paragraph summary. -->

## Why

<!-- Regulatory basis, bug reference, or user-facing benefit. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New rule (governance process applies — see CONTRIBUTING.md)
- [ ] Schema change (migration notes below)
- [ ] Documentation / tooling / CI
- [ ] Dependency update

## Test coverage

- [ ] New tests added covering the change.
- [ ] `pytest -q` passes locally.
- [ ] `scc-verify run-vectors` produces 0 divergences locally.
- [ ] Ruff + mypy clean (`ruff check scc_verifier tests` + `mypy scc_verifier --ignore-missing-imports`).

## Governance (rule / schema changes only)

- [ ] Regulatory basis cited.
- [ ] Saudi-counsel review queued (required for rule-logic changes).
- [ ] Accompanying test vector that fails before + passes after.
- [ ] CHANGELOG.md entry under the unreleased / next-version section.

## Breaking change?

- [ ] Yes — this changes the attestation envelope shape or rule-bundle-hash computation and will invalidate prior attestations under this bundle.
- [ ] No.

<!--
If "yes", describe migration expectations and whether a new BUNDLE_ID
is required.
-->
