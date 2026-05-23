"""datasitr-scc-verifier — draft verifier for machine-checkable SCC elements.

A deterministic, transparent, cryptographically-attestable reference
implementation for DataSitr's canonical SCC JSON form. v0.3 validates the
canonical structure, checks the active rule-bundle identity, evaluates a
small initial Rego rule bundle, flags judgment-bound fields for counsel
review, emits a signed draft attestation, and verifies attestations against
local public keys or public key registries.

It does not verify the official signed contract text, template selection,
permitted blank fields, reference integrity, evidence freshness, or full
SDAIA SCC conformity.

It honestly flags judgment-bound clauses (liability reasonableness,
government-access warranties, etc.) as REQUIRES_HUMAN_REVIEW. It does not
replace Saudi-licensed counsel.

Public API (stable for v0.3):
    verify(scc_document, *, signing_key=None) -> Attestation
    validate_schema(scc_document) -> SchemaValidationResult
    self_validate(attestation) -> SchemaValidationResult

Dataclasses:
    Attestation, AttestationSubject, CheckResult

Type aliases:
    Verdict, CheckLayer, CheckStatus

v0.3 scope:
    Layer 1 (JSON Schema structural validation): live and format-checked.
    Bundle identity check: live.
    Layer 2 (Rego semantic + judgment rules): live when OPA is available.
    Layer 3 (evidence/reference/freshness resolution): deferred.
    Attestation signing: live; ephemeral keypairs permitted with warning.
"""

from scc_verifier._version import __version__
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
from scc_verifier.attestation_verifier import (
    AttestationVerificationResult,
    verify_attestation_envelope,
)
from scc_verifier.key_registry import (
    KeyNotFoundError,
    KeyRegistry,
    KeyStatusError,
    KeyWindowError,
    RegistryError,
    RegistryKey,
    find_key_for_envelope,
    load_registry,
    load_registry_from_path,
    load_registry_from_url,
)
from scc_verifier.schema_validator import SchemaValidationResult

__all__ = [
    "Attestation",
    "AttestationSubject",
    "AttestationVerificationResult",
    "CheckLayer",
    "CheckResult",
    "CheckStatus",
    "KeyNotFoundError",
    "KeyRegistry",
    "KeyStatusError",
    "KeyWindowError",
    "RegistryError",
    "RegistryKey",
    "SchemaValidationResult",
    "Verdict",
    "find_key_for_envelope",
    "load_registry",
    "load_registry_from_path",
    "load_registry_from_url",
    "self_validate",
    "validate_schema",
    "verify_attestation_envelope",
    "verdict_from_checks",
    "verify",
    "__version__",
]
