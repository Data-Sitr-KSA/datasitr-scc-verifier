"""Layer 1 structural validation regression suite.

These tests are the floor. They cover the JSON Schema boundary behaviors
that CI and future contributors must not accidentally weaken.
"""

from __future__ import annotations

import json
from pathlib import Path

from scc_verifier.schema_validator import validate_public_key_registry, validate_scc

VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def test_known_good_passes_schema() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    result = validate_scc(scc)
    assert result.valid, f"expected valid; errors: {result.errors}"


def test_known_bad_missing_governing_law_still_passes_schema() -> None:
    """The 'missing governing law' vector is a SEMANTIC failure, not a
    structural one. The governing_law object is present; it just contains
    the wrong jurisdiction. Layer 1 (schema) passes; Layer 2 (Rego) fails.
    """
    scc = _load(VECTORS / "known_bad" / "missing_governing_law.json")
    result = validate_scc(scc)
    assert result.valid, "schema should pass; semantic rules handle the failure"


def test_malformed_document_fails_schema() -> None:
    """Catches a document missing every mandatory clause."""
    scc = _load(VECTORS / "known_bad" / "structurally_malformed.json")
    result = validate_scc(scc)
    assert not result.valid
    assert len(result.errors) > 0


def test_invalid_scc_id_pattern_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["scc_id"] = "not-a-valid-id"
    result = validate_scc(scc)
    assert not result.valid


def test_negative_notification_window_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["breach_notification"]["sdaia_notification_window_hours"] = 0
    result = validate_scc(scc)
    assert not result.valid


def test_sdaia_window_over_72h_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["breach_notification"]["sdaia_notification_window_hours"] = 96
    result = validate_scc(scc)
    assert not result.valid


def test_sensitive_category_enum_enforced() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["subject_matter"]["sensitive_categories_art18"] = ["invalid_category"]
    result = validate_scc(scc)
    assert not result.valid


def test_template_role_pair_consistency_enforced() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["scc_template"]["template_id"] = "processor_to_controller"
    result = validate_scc(scc)
    assert not result.valid


def test_all_template_role_pairs_are_representable() -> None:
    base = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    cases = [
        ("controller_to_controller", "CONTROLLER", "CONTROLLER"),
        ("controller_to_processor", "CONTROLLER", "PROCESSOR"),
        ("processor_to_processor", "PROCESSOR", "SUB_PROCESSOR"),
        ("processor_to_controller", "PROCESSOR", "CONTROLLER"),
    ]

    for template_id, exporter_role, importer_role in cases:
        scc = json.loads(json.dumps(base))
        scc["scc_template"]["template_id"] = template_id
        scc["scc_template"]["exporter_role"] = exporter_role
        scc["scc_template"]["importer_role"] = importer_role
        scc["parties"]["exporter"]["role"] = exporter_role
        scc["parties"]["importer"]["role"] = importer_role
        result = validate_scc(scc)
        assert result.valid, (template_id, result.errors)


def test_response_window_over_30_days_fails() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["data_subject_rights"]["response_window_days"] = 45
    result = validate_scc(scc)
    assert not result.valid


# Format-checking regressions. Without an explicit FormatChecker, jsonschema
# treats `format: date` and `format: date-time` as informational and lets
# bad values pass. These tests lock the FormatChecker integration.


def test_malformed_date_fails() -> None:
    """`term.effective_date` is declared as `format: date`. A non-date
    string must be rejected."""
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["term"]["effective_date"] = "not-a-date"
    result = validate_scc(scc)
    assert not result.valid, "malformed date must fail validation"


def test_malformed_datetime_fails() -> None:
    """`signatures.exporter.signed_at` is declared as `format: date-time`.
    A non-timestamp string must be rejected."""
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["signatures"]["exporter"]["signed_at"] = "also-not-a-datetime"
    result = validate_scc(scc)
    assert not result.valid, "malformed date-time must fail validation"


def test_tra_expiry_date_format_enforced() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    scc["annex_a_tra"]["expires_at"] = "2027-13-45"  # impossible date
    result = validate_scc(scc)
    assert not result.valid


def test_public_key_registry_example_matches_schema() -> None:
    example = _load(Path(__file__).parent.parent / "examples" / "scc-verifier-keys.example.json")
    result = validate_public_key_registry(example)
    assert result.valid, result.errors
