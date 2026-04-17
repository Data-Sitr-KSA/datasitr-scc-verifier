"""Smoke tests for the Layer 1 JSON Schema validator.

These tests are deliberately minimal. The real coverage comes from the
test-vector corpus under ../test_vectors/ which is run end-to-end by the
CLI and by tests/test_vectors_roundtrip.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scc_verifier.schema_validator import validate_scc


VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def test_known_good_passes_schema() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    result = validate_scc(scc)
    assert result.valid, f"expected valid; errors: {result.errors}"


def test_known_bad_missing_governing_law_still_passes_schema() -> None:
    """The 'missing governing law' vector is a SEMANTIC failure, not a
    structural one. The governing_law object is present; it just contains
    the wrong jurisdiction. Layer 1 (schema) passes; Layer 2 (Rego) fails.
    """
    scc = _load(VECTORS / "known_bad" / "missing_governing_law.json")
    result = validate_scc(scc)
    assert result.valid, f"schema should pass; semantic rules handle the failure"


def test_malformed_document_fails_schema() -> None:
    """Synthesise a truly structurally-invalid document."""
    scc = {"scc_id": "MALFORMED"}
    result = validate_scc(scc)
    assert not result.valid
    assert len(result.errors) > 0


def test_invalid_scc_id_pattern_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["scc_id"] = "not-a-valid-id"
    result = validate_scc(scc)
    assert not result.valid


def test_negative_notification_window_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["breach_notification"]["sdaia_notification_window_hours"] = 0
    result = validate_scc(scc)
    assert not result.valid


def test_sdaia_window_over_72h_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["breach_notification"]["sdaia_notification_window_hours"] = 96
    result = validate_scc(scc)
    assert not result.valid


def test_sensitive_category_enum_enforced() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["subject_matter"]["sensitive_categories_art18"] = ["invalid_category"]
    result = validate_scc(scc)
    assert not result.valid


def test_response_window_over_30_days_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    scc["data_subject_rights"]["response_window_days"] = 45
    result = validate_scc(scc)
    assert not result.valid
