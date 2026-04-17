"""Public dataclasses for the verifier. Immutable by design.

The attestation envelope is designed to canonicalize (RFC 8785 JCS) to a
byte-identical form across verifier implementations, so third parties can
reproduce verdicts independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

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


@dataclass(frozen=True)
class Attestation:
    """Signed verdict envelope. Follows W3C Verifiable Credentials v2.0."""

    id: str
    issuer: str
    valid_from: datetime
    subject: AttestationSubject
    signature: str | None = None
    verification_method: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Render as the canonical envelope JSON shape."""
        return {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "SccComplianceAttestation"],
            "id": self.id,
            "issuer": self.issuer,
            "validFrom": self.valid_from.isoformat().replace("+00:00", "Z"),
            "credentialSubject": {
                "scc_id": self.subject.scc_id,
                "scc_document_hash": self.subject.scc_document_hash,
                "rule_bundle": {
                    "id": self.subject.rule_bundle_id,
                    "hash": self.subject.rule_bundle_hash,
                    "ratification_status": self.subject.ratification_status,
                },
                "verdict": self.subject.verdict,
                "summary": self.subject.summary,
                "checks": [c.to_dict() for c in self.subject.checks],
                "evidence_manifest_hash": self.subject.evidence_manifest_hash,
                "prev_attestation_hash": self.subject.prev_attestation_hash,
            },
            "proof": _proof_dict(self),
        }


def _proof_dict(a: Attestation) -> dict[str, Any]:
    """Render the proof section. v0.1 produces an unsigned skeleton."""
    if a.signature is None:
        return {
            "type": "Ed25519Signature2020",
            "created": a.valid_from.isoformat().replace("+00:00", "Z"),
            "verificationMethod": a.verification_method or "unsigned-v0.1-draft",
            "proofPurpose": "assertionMethod",
            "proofValue": "UNSIGNED-DRAFT",
        }
    return {
        "type": "Ed25519Signature2020",
        "created": a.valid_from.isoformat().replace("+00:00", "Z"),
        "verificationMethod": a.verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": a.signature,
    }


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
