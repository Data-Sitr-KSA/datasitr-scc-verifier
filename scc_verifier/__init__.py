"""datasitr-scc-verifier — machine-verifiable compliance for SDAIA SCCs.

This is a deterministic, transparent, cryptographically-attestable verifier
that produces signed verdicts about whether a given SCC document satisfies
the structural, value-bound, reference-integrity, freshness, and
regulatory-anchor requirements of the SDAIA SCC template.

It honestly flags judgment-bound clauses (liability reasonableness,
government-access warranties, etc.) as REQUIRES_HUMAN_REVIEW. It does not
replace Saudi-licensed counsel.

Public API:
    verify()            — run verification on an SCC document
    validate_schema()   — Layer 1 structural validation (JSON Schema)
    CheckResult         — per-rule result dataclass
    Attestation         — signed verdict envelope

This is v0.1.0-draft. The Rego rule bundle is authored but the OPA
integration is stubbed; this release validates Layer 1 structural
correctness only. Layer 2 (semantic rules) lands in v0.2.
"""

from scc_verifier.api import (
    Attestation,
    CheckResult,
    Verdict,
    CheckLayer,
    CheckStatus,
)

__version__ = "0.1.0"
__all__ = [
    "Attestation",
    "CheckResult",
    "Verdict",
    "CheckLayer",
    "CheckStatus",
    "__version__",
]
