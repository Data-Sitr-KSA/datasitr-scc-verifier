# Security Policy

## Supported versions

During v0.x, only the `main` branch at its current HEAD is supported. Security fixes land on `main`; older commits are not patched separately.

Once v1.0 is released and SDAIA ratification is achieved, a supported-version policy will be published here covering the then-current major and the prior major.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Instead, report privately to:

- **Email:** `security@datasitr.com` (PGP key published at `https://datasitr.com/.well-known/security.txt`)
- **GitHub private vulnerability reporting:** https://github.com/Data-Sitr-KSA/datasitr-scc-verifier/security/advisories/new

Please include:

1. A short description of the issue and its impact.
2. Step-by-step reproduction instructions (test vector, commands, expected vs. actual behavior).
3. Affected commit or version tag.
4. Your contact details so we can coordinate a fix.

## Response expectations

- Acknowledgement within **72 hours** of a report.
- Initial severity assessment within **7 days**.
- Patch + coordinated public disclosure timeline communicated within **14 days**.
- Critical vulnerabilities get priority and may be patched before the 14-day window.

We follow responsible-disclosure practice: researchers who report privately get credited in the advisory unless they request anonymity.

## In scope

The following are in scope for vulnerability reports:

- Flaws in the `scc_verifier` Python library that produce **incorrect attestations** (false PASS on a document that should FAIL, or vice versa).
- Flaws in **signature generation or verification** (`scc_verifier/signing.py`).
- Flaws in **bundle-hash computation** that allow a file change to not be reflected in the hash.
- Flaws in **JSON-schema validation** that allow structurally-malformed documents to pass.
- Flaws in **Rego rule interpretation** that cause a rule to evaluate differently from its documented behavior.
- CVE-worthy issues in our pinned Python dependencies discovered before upstream.

## Out of scope

- Legal interpretation disagreements. The verifier encodes a specific reading of the SDAIA Data Transfer Regulations; disagreement with a rule's interpretation is a **rule-proposal** issue (file via GitHub issues), not a security issue.
- Attacks that require an attacker to already have write access to the rule bundle or repo.
- Issues in third-party dependencies that are already publicly known and have upstream patches pending.
- Denial-of-service via enormous SCC documents (the verifier has no SLA guarantees).

## Threat model and non-claims

The project's threat model is documented in the design spec on the DataSitr side (`DataSitr_SCC_Verifier_Design_Spec_v0.2.md` §9). Explicitly-out-of-scope claims:

- We do not claim non-repudiation of human intent.
- We do not claim attestations survive signing-key compromise until rotation.
- We do not claim the verifier proves the underlying transfer is lawful.

See the design spec for the full list.

## Cryptography

- All signing uses Ed25519 (RFC 8032) via the `cryptography` Python library.
- All hashing uses SHA-256 (FIPS 180-4) via the stdlib.
- All canonicalization uses RFC 8785 (JSON Canonicalization Scheme) via the `jcs` Python library.
- **Zero novel cryptography.** Reports of "interesting new crypto primitives" should assume the report is wrong before assuming the code is wrong.
