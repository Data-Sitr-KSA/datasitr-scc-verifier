"""Deterministic hashing via JSON Canonicalization Scheme (RFC 8785).

Two documents that differ only in whitespace, key ordering, or number
formatting will produce the same canonical byte sequence and therefore the
same SHA-256 hash. This is the foundation of reproducibility: a third
party can independently canonicalize and hash the same logical document
and get the same bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    import jcs  # type: ignore
except ImportError:  # pragma: no cover
    jcs = None


def canonicalize(obj: Any) -> bytes:
    """Produce the canonical byte sequence for a JSON-serialisable object.

    Uses the `jcs` library (RFC 8785) when available. Falls back to a
    reduced-strength canonicalization using Python's built-in JSON module
    with sorted keys; acceptable for v0.1 but must be replaced before
    ratification.
    """
    if jcs is not None:
        return jcs.canonicalize(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_of(obj: Any) -> str:
    """SHA-256 hash of the canonical form. Returns `sha256:<hex>`."""
    canonical = canonicalize(obj)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"
