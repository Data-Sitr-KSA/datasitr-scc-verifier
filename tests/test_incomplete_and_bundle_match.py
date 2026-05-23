"""Trust-boundary regressions for incomplete evaluation and bundle identity."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from scc_verifier import self_validate, verify
from scc_verifier.bundle import BUNDLE_ID
from scc_verifier.cli import main as cli_main

VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def _verify_quiet(scc: dict):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return verify(scc)


def test_missing_opa_yields_incomplete_not_pass(monkeypatch) -> None:
    monkeypatch.delenv("SCC_OPA_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")

    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    attestation = _verify_quiet(scc)

    assert attestation.subject.verdict == "INCOMPLETE"
    layer_2_statuses = {
        c.status
        for c in attestation.subject.checks
        if c.id.startswith("VAL-") or c.id.startswith("JUDGE-")
    }
    assert layer_2_statuses == {"INCOMPLETE"}
    assert self_validate(attestation).valid


def test_cli_missing_opa_exits_nonzero_by_default(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SCC_OPA_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")

    out = tmp_path / "attestation.json"
    exit_code = cli_main(
        [
            "verify",
            "--scc",
            str(VECTORS / "known_good" / "ksa_domestic_scc.json"),
            "--out",
            str(out),
        ]
    )

    assert exit_code != 0
    with out.open() as f:
        envelope = json.load(f)
    assert envelope["credentialSubject"]["verdict"] == "INCOMPLETE"


def test_cli_can_explicitly_allow_incomplete_without_opa(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SCC_OPA_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")

    out = tmp_path / "attestation.json"
    exit_code = cli_main(
        [
            "verify",
            "--scc",
            str(VECTORS / "known_good" / "ksa_domestic_scc.json"),
            "--out",
            str(out),
            "--allow-incomplete-without-opa",
        ]
    )

    assert exit_code == 0
    with out.open() as f:
        envelope = json.load(f)
    assert envelope["credentialSubject"]["verdict"] == "INCOMPLETE"


def test_allow_flag_does_not_mask_layer_2_crash(monkeypatch, tmp_path: Path) -> None:
    from scc_verifier import rego_evaluator

    monkeypatch.setattr(rego_evaluator, "is_opa_available", lambda: True)

    def crash(_scc: dict):
        raise RuntimeError("simulated layer-2 crash")

    monkeypatch.setattr(rego_evaluator, "evaluate_rules", crash)

    out = tmp_path / "attestation.json"
    exit_code = cli_main(
        [
            "verify",
            "--scc",
            str(VECTORS / "known_good" / "ksa_domestic_scc.json"),
            "--out",
            str(out),
            "--allow-incomplete-without-opa",
        ]
    )

    assert exit_code != 0
    with out.open() as f:
        envelope = json.load(f)
    subject = envelope["credentialSubject"]
    assert subject["verdict"] == "INCOMPLETE"
    incomplete = [c for c in subject["checks"] if c["status"] == "INCOMPLETE"]
    assert incomplete
    assert all("OPA binary not available" not in c.get("detail", "") for c in incomplete)
    assert any("Layer 2 evaluator raised RuntimeError" in c.get("detail", "") for c in incomplete)


def test_rule_bundle_required_must_match_active_bundle() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["rule_bundle_required"] = "sdaia-scc-v0.1-2099-01-01"

    attestation = _verify_quiet(scc)
    by_id = {c.id: c for c in attestation.subject.checks}

    assert attestation.subject.verdict == "FAIL"
    assert by_id["RULE-BUNDLE-MATCH"].status == "FAIL"
    assert by_id["RULE-BUNDLE-MATCH"].observed_value == {
        "required": "sdaia-scc-v0.1-2099-01-01",
        "active": BUNDLE_ID,
    }


def test_non_string_rule_bundle_required_is_not_applicable_and_schema_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["rule_bundle_required"] = 123

    attestation = _verify_quiet(scc)
    by_id = {c.id: c for c in attestation.subject.checks}

    assert attestation.subject.verdict == "FAIL"
    assert by_id["STRUCT-001"].status == "FAIL"
    assert by_id["RULE-BUNDLE-MATCH"].status == "NOT_APPLICABLE"
