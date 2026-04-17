"""Layer 1 structural validation against the SCC canonical form schema.

Uses the `jsonschema` library. Produces a structured result consumable by
the verifier, including per-path error messages so callers can localise
validation failures.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import jsonschema
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "jsonschema package is required. Install with: pip install jsonschema>=4.21"
    ) from e

SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
SCC_SCHEMA_PATH = SCHEMAS_DIR / "scc-canonical-v1.json"
ATTESTATION_SCHEMA_PATH = SCHEMAS_DIR / "attestation-envelope-v1.json"
EVIDENCE_SCHEMA_PATH = SCHEMAS_DIR / "evidence-credential-v1.json"


@dataclass(frozen=True)
class SchemaValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()


def _load(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def load_scc_schema() -> dict[str, Any]:
    """Load the SCC canonical form schema from the packaged schemas dir."""
    return _load(SCC_SCHEMA_PATH)


def load_attestation_schema() -> dict[str, Any]:
    """Load the attestation envelope schema."""
    return _load(ATTESTATION_SCHEMA_PATH)


def _validate_against(document: dict[str, Any], schema: dict[str, Any]) -> SchemaValidationResult:
    """Run a Draft 2020-12 validation with format checking enabled.

    Without the explicit FormatChecker, `format: date` and `format: date-time`
    are treated as informational only and malformed values silently pass.
    This is a non-obvious jsonschema default; we override it here.
    """
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors: list[str] = []
    for err in validator.iter_errors(document):
        path = "/".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{path}: {err.message}")
    return SchemaValidationResult(valid=len(errors) == 0, errors=tuple(errors))


def validate_scc(scc_document: dict[str, Any]) -> SchemaValidationResult:
    """Validate an SCC document against the canonical form schema.

    Callers should translate this into a CheckResult at the "structural"
    layer for inclusion in the attestation.
    """
    return _validate_against(scc_document, load_scc_schema())


def validate_attestation_envelope(envelope: dict[str, Any]) -> SchemaValidationResult:
    """Validate an attestation envelope against its own schema.

    Used by the self-check that guards against the class of bug where the
    verifier emits an attestation that fails its own published schema.
    """
    return _validate_against(envelope, load_attestation_schema())
