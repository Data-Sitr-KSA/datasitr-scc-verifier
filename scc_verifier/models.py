"""Shared public dataclasses and type aliases for verifier results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Verdict = Literal["PASS", "FAIL", "PASS_WITH_COUNSEL_ITEMS", "INCOMPLETE"]
CheckLayer = Literal[
    "structural",
    "value",
    "reference",
    "evidence",
    "freshness",
    "anchor",
    "judgment",
]
CheckStatus = Literal["PASS", "FAIL", "REQUIRES_HUMAN_REVIEW", "NOT_APPLICABLE", "INCOMPLETE"]


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
