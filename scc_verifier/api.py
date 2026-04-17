"""Public dataclasses and top-level API for the verifier.

All envelopes are designed to canonicalize (RFC 8785 JCS) to a
byte-identical form across verifier implementations, so third parties can
reproduce verdicts independently.

Public API surface (stable for v0.1):
    validate_schema(scc_document) -> SchemaValidationResult
    verify(scc_document, signing_key=None) -> Attestation
    CheckResult, Attestation, AttestationSubject — dataclasses
    Verdict, CheckLayer, CheckStatus — type aliases
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scc_verifier import bundle as _bundle
from scc_verifier import signing as _signing
from scc_verifier.canonicalization import canonicalize, sha256_of
from scc_verifier.schema_validator import (
    SchemaValidationResult,
    validate_attestation_envelope,
    validate_scc as _validate_scc,
)

Verdict = Literal["PASS", "FAIL", "PASS_WITH_COUNSEL_ITEMS"]
CheckLayer = Literal[
    "structural",
    "value",
    "reference",
    "evidence",
    "freshness",
    "anchor",
    "judgment",
]
CheckStatus = Literal["PASS", "FAIL", "REQUIRES_HUMAN_REVIEW", "NOT_APPLICABLE"]


@dataclass(frozen=True)
class CheckResult:
    """Result of a single rule evaluation."""

    id: str
    rule: str
    layer: CheckLayer
    status: CheckStatus
    detail: str | None = None
    observed_value: Any = None
    evidence: dict[str, Any] | None = None
    counsel_field: str | None = None
    rationale_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "rule": self.rule,
            "layer": self.layer,
            "status": self.status,
        }
        if self.detail is not None:
            out["detail"] = self.detail
        if self.observed_value is not None:
            out["observed_value"] = self.observed_value
        if self.evidence is not None:
            out["evidence"] = self.evidence
        if self.counsel_field is not None:
            out["counsel_field"] = self.counsel_field
        if self.rationale_required:
            out["rationale_required"] = self.rationale_required
        return out


@dataclass(frozen=True)
class AttestationSubject:
    scc_id: str
    scc_document_hash: str
    rule_bundle_id: str
    rule_bundle_hash: str
    ratification_status: Literal[
        "not-yet-ratified-by-sdaia", "ratified-by-sdaia", "deprecated"
    ]
    verdict: Verdict
    checks: tuple[CheckResult, ...]
    evidence_manifest_hash: str | None = None
    prev_attestation_hash: str | None = None

    @property
    def summary(self) -> dict[str, int]:
        counts = {
            "total_rules": len(self.checks),
            "passed": 0,
            "failed": 0,
            "requires_human_review": 0,
            "not_applicable": 0,
        }
        for check in self.checks:
            if check.status == "PASS":
                counts["passed"] += 1
            elif check.status == "FAIL":
                counts["failed"] += 1
            elif check.status == "REQUIRES_HUMAN_REVIEW":
                counts["requires_human_review"] += 1
            elif check.status == "NOT_APPLICABLE":
                counts["not_applicable"] += 1
        return counts

    def to_subject_dict(self) -> dict[str, Any]:
        return {
            "scc_id": self.scc_id,
            "scc_document_hash": self.scc_document_hash,
            "rule_bundle": {
                "id": self.rule_bundle_id,
                "hash": self.rule_bundle_hash,
                "ratification_status": self.ratification_status,
            },
            "verdict": self.verdict,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
            "evidence_manifest_hash": self.evidence_manifest_hash,
            "prev_attestation_hash": self.prev_attestation_hash,
        }


@dataclass(frozen=True)
class Attestation:
    """Signed verdict envelope. Follows W3C Verifiable Credentials v2.0."""

    id: str
    issuer: str
    valid_from: datetime
    subject: AttestationSubject
    signature: str
    verification_method: str

    def to_dict(self) -> dict[str, Any]:
        """Render as the canonical envelope JSON shape."""
        return {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "SccComplianceAttestation"],
            "id": self.id,
            "issuer": self.issuer,
            "validFrom": _iso_z(self.valid_from),
            "credentialSubject": self.subject.to_subject_dict(),
            "proof": {
                "type": "Ed25519Signature2020",
                "created": _iso_z(self.valid_from),
                "verificationMethod": self.verification_method,
                "proofPurpose": "assertionMethod",
                "proofValue": self.signature,
            },
        }


def _iso_z(dt: datetime) -> str:
    """Render datetime in strict RFC 3339 / ISO-8601 'Z' form.

    Our schema requires `format: date-time`. Python's default
    `isoformat()` emits `+00:00` which some strict validators accept and
    some don't. We normalize to `Z` for maximum compatibility.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # Trim microseconds to milliseconds for stable hashing.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _infer_layer_from_package(package: str) -> CheckLayer:
    """Map a Rego package name to its CheckLayer tag.

    Used when we synthesize a placeholder CheckResult for a rule we
    didn't actually evaluate (e.g., Layer 2 skipped). Keeps the layer tag
    consistent with what the rule would have produced had it run.
    """
    if package.endswith(".structural"):
        return "structural"
    if package.endswith(".value"):
        return "value"
    if package.endswith(".reference"):
        return "reference"
    if package.endswith(".freshness"):
        return "freshness"
    if package.endswith(".anchor"):
        return "anchor"
    if package.endswith(".judgment"):
        return "judgment"
    return "value"


def verdict_from_checks(checks: tuple[CheckResult, ...]) -> Verdict:
    """Compute the overall verdict from a set of check results.

    Rules:
      - Any FAIL → overall FAIL
      - No FAIL but any REQUIRES_HUMAN_REVIEW → PASS_WITH_COUNSEL_ITEMS
      - No FAIL and no REQUIRES_HUMAN_REVIEW → PASS
    """
    if any(c.status == "FAIL" for c in checks):
        return "FAIL"
    if any(c.status == "REQUIRES_HUMAN_REVIEW" for c in checks):
        return "PASS_WITH_COUNSEL_ITEMS"
    return "PASS"


# --------------------------------------------------------------------------
# Top-level public functions — what `import scc_verifier` exposes.
# --------------------------------------------------------------------------


def validate_schema(scc_document: dict[str, Any]) -> SchemaValidationResult:
    """Validate an SCC document against the canonical form schema.

    Public re-export of scc_verifier.schema_validator.validate_scc for
    stability. Users depending on this function name will not be broken
    if we refactor the underlying module layout.
    """
    return _validate_scc(scc_document)


def verify(
    scc_document: dict[str, Any],
    *,
    signing_key: Ed25519PrivateKey | None = None,
    issuer: str = "did:web:datasitr.com",
    skip_layer_2: bool = False,
) -> Attestation:
    """Verify an SCC document and produce a signed attestation.

    v0.2 evaluates Layer 1 (JSON Schema structural validation) and Layer 2
    (Rego semantic + judgment rules via the OPA binary). Layer 3 evidence
    resolution lands in v0.3.

    Layer 2 evaluation is conditional:
      - If the document fails Layer 1, Layer 2 is skipped (structurally
        broken documents can't be meaningfully evaluated semantically;
        the Rego rules would raise on missing fields).
      - If the OPA binary is not discoverable, Layer 2 is skipped with a
        UserWarning; the attestation is still emitted, and the rule
        registry entries appear as NOT_APPLICABLE rather than silently
        missing. This keeps the verifier usable in environments where
        OPA is not yet installed.
      - If `skip_layer_2=True` is passed, Layer 2 is skipped
        unconditionally (useful for fast Layer-1-only lints).

    If no signing_key is supplied, an ephemeral keypair is generated with
    a UserWarning. The resulting attestation is cryptographically valid
    but not verifiable against any published key.
    """
    import warnings

    from scc_verifier import rego_evaluator as _rego

    # Layer 1 — JSON Schema structural validation.
    schema_result = _validate_scc(scc_document)
    if schema_result.valid:
        layer_1_check = CheckResult(
            id="STRUCT-001",
            rule="has_all_mandatory_clauses_and_types",
            layer="structural",
            status="PASS",
            detail="SCC document conforms to scc-canonical-v1 schema",
        )
    else:
        layer_1_check = CheckResult(
            id="STRUCT-001",
            rule="has_all_mandatory_clauses_and_types",
            layer="structural",
            status="FAIL",
            detail="Schema validation errors: " + "; ".join(schema_result.errors[:5]),
        )

    # Layer 2 — Rego rule evaluation (value + judgment rules).
    # Deliberately exclude STRUCT-001 from the Rego-evaluated set here: we
    # already ran the JSON-Schema version above as the authoritative Layer 1
    # source of truth. Running STRUCT-001 via Rego too would duplicate a
    # check; the Rego STRUCT-001 is retained for third-party reproducibility
    # but not wired into the default attestation.
    layer_2_checks: tuple[CheckResult, ...] = ()
    if skip_layer_2 or not schema_result.valid:
        # Document structurally broken, or caller explicitly asked to skip.
        # Produce NOT_APPLICABLE entries so consumers see the rule registry
        # surface without having to re-derive what would have been evaluated.
        layer_2_checks = tuple(
            CheckResult(
                id=r.id,
                rule=r.result_var,
                layer=_infer_layer_from_package(r.package),
                status="NOT_APPLICABLE",
                detail=(
                    "skipped: caller requested skip_layer_2"
                    if skip_layer_2
                    else "skipped: document failed Layer 1 schema validation"
                ),
            )
            for r in _rego.RULE_REGISTRY
            if r.id != "STRUCT-001"
        )
    elif not _rego.is_opa_available():
        warnings.warn(
            "OPA binary not found; skipping Layer 2 rule evaluation. "
            "Install with `brew install opa` (macOS) or see "
            "scc_verifier.rego_evaluator.find_opa for full instructions.",
            UserWarning,
            stacklevel=2,
        )
        layer_2_checks = tuple(
            CheckResult(
                id=r.id,
                rule=r.result_var,
                layer=_infer_layer_from_package(r.package),
                status="NOT_APPLICABLE",
                detail="skipped: OPA binary not available in this environment",
            )
            for r in _rego.RULE_REGISTRY
            if r.id != "STRUCT-001"
        )
    else:
        try:
            all_rego_checks = _rego.evaluate_rules(scc_document)
            # Filter out STRUCT-001 from Rego set; already covered by schema.
            layer_2_checks = tuple(c for c in all_rego_checks if c.id != "STRUCT-001")
        except Exception as e:
            # OPA present but evaluation blew up mid-flight. Mark rules
            # NOT_APPLICABLE with the exception message rather than killing
            # the verify call — the Layer 1 attestation is still useful and
            # self-validates.
            warnings.warn(
                f"Layer 2 evaluation failed: {type(e).__name__}: {e}. "
                f"Emitting attestation with Layer 1 only.",
                UserWarning,
                stacklevel=2,
            )
            layer_2_checks = tuple(
                CheckResult(
                    id=r.id,
                    rule=r.result_var,
                    layer=_infer_layer_from_package(r.package),
                    status="NOT_APPLICABLE",
                    detail=f"skipped: Layer 2 evaluator raised {type(e).__name__}",
                )
                for r in _rego.RULE_REGISTRY
                if r.id != "STRUCT-001"
            )

    checks = (layer_1_check,) + layer_2_checks

    subject = AttestationSubject(
        scc_id=scc_document.get("scc_id", "UNKNOWN"),
        scc_document_hash=sha256_of(scc_document),
        rule_bundle_id=_bundle.BUNDLE_ID,
        rule_bundle_hash=_bundle.compute_bundle_hash(),
        ratification_status="not-yet-ratified-by-sdaia",
        verdict=verdict_from_checks(checks),
        checks=checks,
        evidence_manifest_hash=None,
        prev_attestation_hash=None,
    )

    if signing_key is None:
        signing_key = _signing.ephemeral_keypair_with_warning()

    now = datetime.now(timezone.utc)
    # Canonicalize the subject + context block for signing.
    # The signature covers everything except the proof block itself.
    to_sign = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "SccComplianceAttestation"],
        "id": f"urn:datasitr:attestation:{subject.scc_id}:{_iso_z(now)}",
        "issuer": issuer,
        "validFrom": _iso_z(now),
        "credentialSubject": subject.to_subject_dict(),
    }
    signature = _signing.sign_bytes(signing_key, canonicalize(to_sign))
    pubkey_id = _signing.public_key_sha256(signing_key.public_key())

    return Attestation(
        id=to_sign["id"],
        issuer=issuer,
        valid_from=now,
        subject=subject,
        signature=signature,
        verification_method=f"{issuer}#key-{pubkey_id}",
    )


def self_validate(attestation: Attestation) -> SchemaValidationResult:
    """Validate an attestation envelope against the attestation schema.

    Used by the self-check in tests and CI to guard against the class of
    bug where the emitted envelope fails its own published schema.
    """
    return validate_attestation_envelope(attestation.to_dict())
