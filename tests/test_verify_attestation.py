"""Third-party attestation verification tests."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from scc_verifier import verify
from scc_verifier.attestation_verifier import verify_attestation_envelope
from scc_verifier.cli import main as cli_main
from scc_verifier.signing import generate_keypair, save_public_key

VECTORS = Path(__file__).parent.parent / "test_vectors"


def _load(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def test_verify_attestation_signature_roundtrip() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    key = generate_keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        envelope = verify(scc, signing_key=key).to_dict()

    result = verify_attestation_envelope(envelope, key.public_key())
    assert result.valid, result.errors


def test_verify_attestation_rejects_tampered_subject() -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    key = generate_keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        envelope = verify(scc, signing_key=key).to_dict()

    envelope["credentialSubject"]["scc_id"] = "SCC-2099-01-999"
    result = verify_attestation_envelope(envelope, key.public_key())
    assert not result.valid
    assert not result.signature_valid


def test_cli_verify_attestation(tmp_path: Path) -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    key = generate_keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        envelope = verify(scc, signing_key=key).to_dict()

    attestation_path = tmp_path / "attestation.json"
    public_key_path = tmp_path / "verifier.pub.pem"
    attestation_path.write_text(json.dumps(envelope), encoding="utf-8")
    save_public_key(key.public_key(), public_key_path)

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation_path),
                "--public-key",
                str(public_key_path),
            ]
        )
        == 0
    )
