"""Verdict-composition tests."""

from __future__ import annotations

from scc_verifier.api import CheckResult, verdict_from_checks


def _c(status: str, id_: str = "T-001") -> CheckResult:
    return CheckResult(id=id_, rule="test", layer="structural", status=status)  # type: ignore[arg-type]


def test_all_pass_is_pass() -> None:
    checks = (_c("PASS", "A"), _c("PASS", "B"))
    assert verdict_from_checks(checks) == "PASS"


def test_any_fail_is_fail() -> None:
    checks = (_c("PASS", "A"), _c("FAIL", "B"), _c("REQUIRES_HUMAN_REVIEW", "C"))
    assert verdict_from_checks(checks) == "FAIL"


def test_human_review_without_fail_is_pass_with_counsel_items() -> None:
    checks = (_c("PASS", "A"), _c("REQUIRES_HUMAN_REVIEW", "B"))
    assert verdict_from_checks(checks) == "PASS_WITH_COUNSEL_ITEMS"


def test_incomplete_without_fail_is_incomplete() -> None:
    checks = (_c("PASS", "A"), _c("INCOMPLETE", "B"))
    assert verdict_from_checks(checks) == "INCOMPLETE"


def test_fail_overrides_incomplete() -> None:
    checks = (_c("INCOMPLETE", "A"), _c("FAIL", "B"))
    assert verdict_from_checks(checks) == "FAIL"


def test_not_applicable_alone_is_pass() -> None:
    checks = (_c("PASS", "A"), _c("NOT_APPLICABLE", "B"))
    assert verdict_from_checks(checks) == "PASS"


def test_empty_checks_is_pass() -> None:
    assert verdict_from_checks(()) == "PASS"
