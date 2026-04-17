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
    from jsonschema import Draft202012Validator
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "jsonschema package is required. Install with: pip install jsonschema>=4.21"
    ) from e

SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "scc-canonical-v1.json"


@dataclass(frozen=True)
class SchemaValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()


def load_schema() -> dict[str, Any]:
    """Load the SCC canonical form schema from the packaged schemas dir."""
    with SCHEMA_PATH.open() as f:
        return json.load(f)


def validate_scc(scc_document: dict[str, Any]) -> SchemaValidationResult:
    """Validate an SCC document against the canonical form schema.

    Returns a structured result. Callers should translate this into a
    CheckResult at the "structural" layer for inclusion in the attestation.
    """
    schema = load_schema()
    validator = Draft202012Validator(schema)
    errors = []
    for err in validator.iter_errors(scc_document):
        path = "/".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{path}: {err.message}")
    return SchemaValidationResult(
        valid=len(errors) == 0,
        errors=tuple(errors),
    )
