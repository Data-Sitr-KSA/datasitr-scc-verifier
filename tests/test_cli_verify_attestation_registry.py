"""CLI tests for registry-backed attestation verification."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scc_verifier import verify
from scc_verifier.cli import main as cli_main
from scc_verifier.signing import generate_keypair, public_key_sha256

ROOT = Path(__file__).parent.parent
VECTORS = ROOT / "test_vectors"


def _load(path: Path) -> dict[str, Any]:
    with path.open() as f:
        loaded: dict[str, Any] = json.load(f)
    return loaded


def _public_key_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _key_id(key: Ed25519PrivateKey) -> str:
    return f"key-{public_key_sha256(key.public_key())}"


def _registry_doc(key: Ed25519PrivateKey, *, status: str = "active") -> dict[str, Any]:
    return {
        "schema_version": "1",
        "issuer": "did:web:datasitr.com",
        "generated_at": "2026-01-01T00:00:00Z",
        "keys": [
            {
                "id": _key_id(key),
                "type": "Ed25519VerificationKey2020",
                "public_key_pem": _public_key_pem(key),
                "status": status,
                "not_before": "2026-01-01T00:00:00Z",
                "purpose": "test key",
            }
        ],
    }


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _signed_attestation(tmp_path: Path, key: Ed25519PrivateKey) -> Path:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        envelope = verify(scc, signing_key=key).to_dict()
    return _write_json(tmp_path / "attestation.json", envelope)


def _registry_path(tmp_path: Path, key: Ed25519PrivateKey, *, status: str = "active") -> Path:
    return _write_json(tmp_path / "registry.json", _registry_doc(key, status=status))


def test_cli_verify_attestation_with_valid_local_registry(tmp_path: Path) -> None:
    key = generate_keypair()
    attestation = _signed_attestation(tmp_path, key)
    registry = _registry_path(tmp_path, key)

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--key-registry",
                str(registry),
            ]
        )
        == 0
    )


def test_cli_verify_attestation_registry_rejects_invalid_signature(tmp_path: Path) -> None:
    key = generate_keypair()
    attestation = _signed_attestation(tmp_path, key)
    envelope = _load(attestation)
    envelope["credentialSubject"]["scc_id"] = "SCC-2099-01-999"
    _write_json(attestation, envelope)
    registry = _registry_path(tmp_path, key)

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--key-registry",
                str(registry),
            ]
        )
        == 1
    )


def test_cli_verify_attestation_registry_rejects_revoked_key(tmp_path: Path) -> None:
    key = generate_keypair()
    attestation = _signed_attestation(tmp_path, key)
    registry = _registry_path(tmp_path, key, status="revoked")

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--key-registry",
                str(registry),
            ]
        )
        == 1
    )


def test_cli_verify_attestation_registry_rejects_missing_key(tmp_path: Path) -> None:
    signing_key = generate_keypair()
    registry_key = generate_keypair()
    attestation = _signed_attestation(tmp_path, signing_key)
    registry = _registry_path(tmp_path, registry_key)

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--key-registry",
                str(registry),
            ]
        )
        == 1
    )


def test_cli_verify_attestation_registry_missing_file_exits_2(tmp_path: Path) -> None:
    key = generate_keypair()
    attestation = _signed_attestation(tmp_path, key)

    assert (
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--key-registry",
                str(tmp_path / "missing.json"),
            ]
        )
        == 2
    )


def test_cli_verify_attestation_key_sources_are_mutually_exclusive(tmp_path: Path) -> None:
    key = generate_keypair()
    attestation = _signed_attestation(tmp_path, key)
    registry = _registry_path(tmp_path, key)
    public_key = tmp_path / "key.pub.pem"
    public_key.write_text(_public_key_pem(key), encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli_main(
            [
                "verify-attestation",
                "--attestation",
                str(attestation),
                "--public-key",
                str(public_key),
                "--key-registry",
                str(registry),
            ]
        )
    assert exc.value.code == 2


def test_cli_keys_list_prints_registry_keys(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    key = generate_keypair()
    registry = _registry_path(tmp_path, key)

    assert cli_main(["keys", "list", "--registry", str(registry)]) == 0
    captured = capsys.readouterr()
    assert _key_id(key) in captured.out
    assert "status=active" in captured.out


def test_cli_keys_list_unreachable_url_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(*args, **kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert (
        cli_main(
            [
                "keys",
                "list",
                "--registry",
                "https://example.com/.well-known/scc-verifier-keys.json",
            ]
        )
        == 1
    )
