"""datasitr-scc-verifier — machine-verifiable compliance for SDAIA SCCs.

A deterministic, transparent, cryptographically-attestable verifier that
produces signed verdicts about whether a given SCC document satisfies the
structural, value-bound, reference-integrity, freshness, and
regulatory-anchor requirements of the SDAIA SCC template.

It honestly flags judgment-bound clauses (liability reasonableness,
government-access warranties, etc.) as REQUIRES_HUMAN_REVIEW. It does not
replace Saudi-licensed counsel.

Public API (stable for v0.1):
    verify(scc_document, *, signing_key=None) -> Attestation
    validate_schema(scc_document) -> SchemaValidationResult
    self_validate(attestation) -> SchemaValidationResult

Dataclasses:
    Attestation, AttestationSubject, CheckResult

Type aliases:
    Verdict, CheckLayer, CheckStatus

v0.1 scope:
    Layer 1 (JSON Schema structural validation): live and format-checked.
    Layer 2 (Rego semantic rules): authored in rules/; OPA evaluator ships in v0.2.
    Layer 3 (evidence resolution): deferred to v0.2.
    Layer 4 (Ed25519 attestation signing): live; ephemeral keypairs permitted with warning.
"""

from scc_verifier.api import (
    Attestation,
    AttestationSubject,
    CheckLayer,
    CheckResult,
    CheckStatus,
    Verdict,
    self_validate,
    validate_schema,
    verdict_from_checks,
    verify,
)
from scc_verifier.schema_validator import SchemaValidationResult

__version__ = "0.1.0"

__all__ = [
    "Attestation",
    "AttestationSubject",
    "CheckLayer",
    "CheckResult",
    "CheckStatus",
    "SchemaValidationResult",
    "Verdict",
    "self_validate",
    "validate_schema",
    "verdict_from_checks",
    "verify",
    "__version__",
]
