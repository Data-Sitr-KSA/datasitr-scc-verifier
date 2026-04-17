"""Attestation envelope round-trip tests.

The core invariant: every attestation emitted by verify() must validate
against the attestation envelope schema. This is the regression guard
against the class of bug where the verifier ships envelopes that fail
their own published schema (as happened pre-0.1.0 with hardcoded
`UNSIGNED-DRAFT` and `PLACEHOLDER` strings).
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from scc_verifier import self_validate, verify

VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def _verify_with_ephemeral(scc: dict):
    """Run verify() suppressing the ephemeral-key UserWarning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return verify(scc)


def test_known_good_attestation_self_validates() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    attestation = _verify_with_ephemeral(scc)
    result = self_validate(attestation)
    assert result.valid, (
        f"attestation envelope must validate against its own schema; errors: {result.errors}"
    )


def test_malformed_scc_still_produces_self_valid_attestation() -> None:
    """Even when the SCC fails Layer 1, the resulting attestation
    envelope is still structurally valid — the verdict is FAIL but the
    envelope shape is correct."""
    scc = _load(VECTORS / "known_bad" / "structurally_malformed.json")
    attestation = _verify_with_ephemeral(scc)
    assert attestation.subject.verdict == "FAIL"
    result = self_validate(attestation)
    assert result.valid, f"envelope must still self-validate; errors: {result.errors}"


def test_attestation_has_real_rule_bundle_hash() -> None:
    """Rule bundle hash must be a real sha256:<64 hex> string, not a
    placeholder."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    attestation = _verify_with_ephemeral(scc)
    h = attestation.subject.rule_bundle_hash
    assert h.startswith("sha256:")
    assert len(h) == 71  # "sha256:" + 64 hex
    assert "PLACEHOLDER" not in h


def test_attestation_has_real_proof_value() -> None:
    """proofValue must be `ed25519:<base64url>` matching the envelope
    pattern, not a placeholder string."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    attestation = _verify_with_ephemeral(scc)
    proof = attestation.to_dict()["proof"]
    assert proof["proofValue"].startswith("ed25519:")
    assert "DRAFT" not in proof["proofValue"]
    assert "UNSIGNED" not in proof["proofValue"]


def test_ephemeral_key_emits_warning() -> None:
    """When no signing key is supplied, a UserWarning must be emitted.
    Silent ephemeral signing is a trap we deliberately guard against."""
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        verify(scc)
    assert any(issubclass(w.category, UserWarning) for w in captured)


def test_envelope_has_vc_context() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_domestic_scc.json")
    attestation = _verify_with_ephemeral(scc)
    envelope = attestation.to_dict()
    assert "https://www.w3.org/ns/credentials/v2" in envelope["@context"]
    assert "SccComplianceAttestation" in envelope["type"]
