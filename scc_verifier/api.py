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
) -> Attestation:
    """Verify an SCC document and produce a signed attestation.

    v0.1 evaluates only Layer 1 (structural / schema validation). Layer 2
    semantic rules (Rego), Layer 3 evidence resolution, and the full
    check catalog land in v0.2.

    If no signing_key is supplied, an ephemeral keypair is generated with
    a UserWarning. The resulting attestation is cryptographically valid
    but not verifiable against any published key, since the public key
    is discarded when the process exits.
    """
    schema_result = _validate_scc(scc_document)
    if schema_result.valid:
        check = CheckResult(
            id="STRUCT-001",
            rule="has_all_mandatory_clauses_and_types",
            layer="structural",
            status="PASS",
            detail="SCC document conforms to scc-canonical-v1 schema",
        )
    else:
        check = CheckResult(
            id="STRUCT-001",
            rule="has_all_mandatory_clauses_and_types",
            layer="structural",
            status="FAIL",
            detail="Schema validation errors: " + "; ".join(schema_result.errors[:5]),
        )
    checks = (check,)

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
