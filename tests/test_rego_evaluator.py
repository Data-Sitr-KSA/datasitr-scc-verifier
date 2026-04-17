"""Layer 2 (Rego) evaluator tests.

These tests skip automatically if the OPA binary is not available, so
CI environments without OPA still pass the rest of the suite. Add OPA
to CI to light them up.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scc_verifier import rego_evaluator
from scc_verifier.rego_evaluator import (
    OpaNotFoundError,
    RULE_REGISTRY,
    evaluate_rules,
    is_opa_available,
)


VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


opa_required = pytest.mark.skipif(
    not is_opa_available(),
    reason="OPA binary not available; install with `brew install opa`",
)


def test_rule_registry_is_non_empty() -> None:
    """Sanity: the registry must define at least the 9 v0.2 rules."""
    assert len(RULE_REGISTRY) >= 9
    ids = {r.id for r in RULE_REGISTRY}
    for expected in (
        "STRUCT-001",
        "VAL-GOV-LAW",
        "VAL-DISPUTE-FORUM",
        "VAL-BREACH-EXPORTER",
        "VAL-BREACH-SDAIA",
        "VAL-SENSITIVE-ROUTE",
        "JUDGE-LIAB-001",
        "JUDGE-GOV-ACCESS-001",
        "JUDGE-INDEM-001",
    ):
        assert expected in ids, f"rule {expected} missing from registry"


def test_find_opa_raises_with_useful_message_when_missing(monkeypatch) -> None:
    """If OPA is truly absent, the error must include install guidance.

    We simulate absence by clearing PATH and unsetting SCC_OPA_BIN; the
    real behavior of the binary-discovery code is what we're testing, not
    the availability of the tool on this specific machine.
    """
    monkeypatch.delenv("SCC_OPA_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(OpaNotFoundError) as exc:
        rego_evaluator.find_opa()
    msg = str(exc.value)
    assert "brew install opa" in msg or "openpolicyagent" in msg


@opa_required
def test_known_good_produces_pass_with_counsel_items() -> None:
    """The Saudi-domestic vector: 6 rules PASS, 3 judgment rules REVIEW."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    results = evaluate_rules(scc)
    by_id = {r.id: r for r in results}
    assert by_id["STRUCT-001"].status == "PASS"
    assert by_id["VAL-GOV-LAW"].status == "PASS"
    assert by_id["VAL-DISPUTE-FORUM"].status == "PASS"
    assert by_id["VAL-BREACH-EXPORTER"].status == "PASS"
    assert by_id["VAL-BREACH-SDAIA"].status == "PASS"
    assert by_id["VAL-SENSITIVE-ROUTE"].status == "PASS"
    assert by_id["JUDGE-LIAB-001"].status == "REQUIRES_HUMAN_REVIEW"
    assert by_id["JUDGE-GOV-ACCESS-001"].status == "REQUIRES_HUMAN_REVIEW"
    assert by_id["JUDGE-INDEM-001"].status == "REQUIRES_HUMAN_REVIEW"


@opa_required
def test_foreign_governing_law_fires_fail() -> None:
    """Non-KSA governing law + non-KSA dispute forum must both FAIL."""
    scc = _load(VECTORS / "known_bad" / "missing_governing_law.json")
    results = evaluate_rules(scc)
    by_id = {r.id: r for r in results}
    assert by_id["VAL-GOV-LAW"].status == "FAIL"
    assert by_id["VAL-DISPUTE-FORUM"].status == "FAIL"
    assert by_id["VAL-GOV-LAW"].observed_value == "State of California"


@opa_required
def test_sensitive_plus_onward_transfer_fires_fail() -> None:
    """Article 18 sensitive data + onward_transfers.permitted=true → FAIL."""
    scc = _load(VECTORS / "known_bad" / "sensitive_onward_transfer.json")
    results = evaluate_rules(scc)
    by_id = {r.id: r for r in results}
    assert by_id["VAL-SENSITIVE-ROUTE"].status == "FAIL"


@opa_required
def test_judgment_rules_flag_counsel_fields() -> None:
    """JUDGE-* results must populate counsel_field and rationale_required."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    results = evaluate_rules(scc)
    by_id = {r.id: r for r in results}
    liab = by_id["JUDGE-LIAB-001"]
    assert liab.counsel_field == "liability.cap_amount_sar"
    assert liab.rationale_required is True


@opa_required
def test_evaluate_rules_is_deterministic() -> None:
    """Same input + same rules → byte-identical CheckResult tuple.

    This is the property that makes reproducibility claims honest.
    """
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    a = evaluate_rules(scc)
    b = evaluate_rules(scc)
    assert a == b


@opa_required
def test_breach_windows_catch_out_of_range() -> None:
    """Mutate the exporter window to 48 hours (over the 24h bound) → FAIL."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["breach_notification"]["exporter_notification_window_hours"] = 48
    results = evaluate_rules(scc)
    by_id = {r.id: r for r in results}
    assert by_id["VAL-BREACH-EXPORTER"].status == "FAIL"
    assert by_id["VAL-BREACH-SDAIA"].status == "PASS"
