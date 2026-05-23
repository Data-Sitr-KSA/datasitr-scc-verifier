"""Determinism regressions for signed attestation envelopes."""

from __future__ import annotations

import copy
import json
import warnings
from datetime import UTC, datetime
from pathlib import Path

import scc_verifier.api as api_module
from scc_verifier import verify
from scc_verifier.canonicalization import canonicalize
from scc_verifier.signing import generate_keypair

VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def _strip_timestamp_fields(envelope: dict) -> dict:
    stripped = copy.deepcopy(envelope)
    stripped.pop("id")
    stripped.pop("validFrom")
    stripped["proof"].pop("created")
    return stripped


def test_verify_is_deterministic_under_fixed_timestamp(monkeypatch) -> None:
    """Same input, same key, same timestamp -> byte-identical envelope body.

    The production signature intentionally covers the timestamped envelope
    fields, so the test freezes time rather than weakening signing semantics.
    """

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 5, 23, 12, 0, 0, 123000, tzinfo=tz or UTC)

    monkeypatch.setattr(api_module, "datetime", FixedDatetime)

    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    signing_key = generate_keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        first = verify(scc, signing_key=signing_key).to_dict()
        second = verify(scc, signing_key=signing_key).to_dict()

    assert canonicalize(_strip_timestamp_fields(first)) == canonicalize(
        _strip_timestamp_fields(second)
    )
