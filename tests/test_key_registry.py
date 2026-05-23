"""Public key registry loading and resolution tests."""

from __future__ import annotations

import json
import urllib.request
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scc_verifier import verify
from scc_verifier.attestation_verifier import verify_attestation_envelope
from scc_verifier.key_registry import (
    KeyStatusError,
    KeyWindowError,
    RegistryError,
    find_key_for_envelope,
    load_registry,
    load_registry_from_path,
    load_registry_from_url,
)
from scc_verifier.schema_validator import validate_public_key_registry
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


def _registry_doc(
    key: Ed25519PrivateKey,
    *,
    status: str = "active",
    not_before: str = "2026-01-01T00:00:00Z",
    not_after: str | None = None,
    issuer: str = "did:web:datasitr.com",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": _key_id(key),
        "type": "Ed25519VerificationKey2020",
        "public_key_pem": _public_key_pem(key),
        "status": status,
        "not_before": not_before,
        "purpose": "test key",
    }
    if not_after is not None:
        entry["not_after"] = not_after
    return {
        "schema_version": "1",
        "issuer": issuer,
        "generated_at": "2026-01-01T00:00:00Z",
        "keys": [entry],
    }


def _write_registry(tmp_path: Path, doc: dict[str, Any]) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _fake_envelope(key: Ed25519PrivateKey, *, valid_from: str = "2026-02-15T00:00:00Z"):
    return {
        "issuer": "did:web:datasitr.com",
        "validFrom": valid_from,
        "proof": {"verificationMethod": f"did:web:datasitr.com#{_key_id(key)}"},
    }


def test_public_key_registry_schema_validation(tmp_path: Path) -> None:
    example = _load(ROOT / "examples" / "scc-verifier-keys.example.json")
    assert validate_public_key_registry(example).valid

    missing_not_before = _registry_doc(generate_keypair())
    del missing_not_before["keys"][0]["not_before"]
    assert not validate_public_key_registry(missing_not_before).valid

    missing_schema_version = _registry_doc(generate_keypair())
    del missing_schema_version["schema_version"]
    assert not validate_public_key_registry(missing_schema_version).valid

    extra = _registry_doc(generate_keypair())
    extra["keys"][0]["unexpected"] = True
    assert not validate_public_key_registry(extra).valid

    bad_status = _registry_doc(generate_keypair(), status="paused")
    assert not validate_public_key_registry(bad_status).valid

    naive = _registry_doc(generate_keypair(), not_before="2026-01-01T00:00:00")
    path = _write_registry(tmp_path, naive)
    with pytest.raises(RegistryError, match="timezone offset|schema validation"):
        load_registry_from_path(path)


def test_load_registry_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []

    def fake_url(location: str):
        calls.append(("url", location))
        raise RegistryError("stop")

    def fake_path(path: Path):
        calls.append(("path", str(path)))
        raise RegistryError("stop")

    monkeypatch.setattr("scc_verifier.key_registry.load_registry_from_url", fake_url)
    monkeypatch.setattr("scc_verifier.key_registry.load_registry_from_path", fake_path)
    monkeypatch.chdir(tmp_path)

    for location in (
        "https://example.com/.well-known/scc-verifier-keys.json",
        str(tmp_path / "abs.json"),
        "./rel.json",
        (tmp_path / "file.json").as_uri(),
    ):
        with pytest.raises(RegistryError, match="stop"):
            load_registry(location)

    assert calls[0][0] == "url"
    assert [kind for kind, _ in calls[1:]] == ["path", "path", "path"]


def test_load_registry_from_url_rejects_http_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fake_urlopen(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network should not be called")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RegistryError, match="only https:// URLs are accepted; got http://"):
        load_registry_from_url("http://example.com/scc-verifier-keys.json")
    assert not called


def test_load_registry_from_url_fetches_and_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = generate_keypair()
    valid_bytes = json.dumps(_registry_doc(key)).encode("utf-8")

    class FakeResponse:
        def __init__(self, raw: bytes) -> None:
            self.raw = raw

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def read(self) -> bytes:
            return self.raw

    def fake_urlopen(request, *, timeout):
        assert timeout == 10.0
        assert request.full_url == "https://example.com/keys.json"
        assert "registry-client" in request.get_header("User-agent")
        return FakeResponse(valid_bytes)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    registry = load_registry_from_url("https://example.com/keys.json")
    assert registry.issuer == "did:web:datasitr.com"
    assert registry.keys[0].id == _key_id(key)

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: FakeResponse(b"{"))
    with pytest.raises(RegistryError, match="not valid JSON"):
        load_registry_from_url("https://example.com/keys.json")

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **k: FakeResponse(b'{"schema_version": "1"}'),
    )
    with pytest.raises(RegistryError, match="schema validation"):
        load_registry_from_url("https://example.com/keys.json")


def test_find_key_for_envelope_resolves_active_key(tmp_path: Path) -> None:
    active = generate_keypair()
    retired = generate_keypair()
    doc = _registry_doc(active)
    doc["keys"].append(
        _registry_doc(
            retired,
            status="retired",
            not_before="2026-01-01T00:00:00Z",
            not_after="2026-03-01T00:00:00Z",
        )["keys"][0]
    )
    registry = load_registry_from_path(_write_registry(tmp_path, doc))
    resolved = find_key_for_envelope(registry, _fake_envelope(active))
    assert resolved.id == _key_id(active)


def test_revoked_key_rejection(tmp_path: Path) -> None:
    key = generate_keypair()
    registry = load_registry_from_path(
        _write_registry(tmp_path, _registry_doc(key, status="revoked"))
    )
    with pytest.raises(KeyStatusError):
        find_key_for_envelope(registry, _fake_envelope(key, valid_from="2026-02-01T00:00:00Z"))


def test_retired_key_time_window_enforcement(tmp_path: Path) -> None:
    key = generate_keypair()
    registry = load_registry_from_path(
        _write_registry(
            tmp_path,
            _registry_doc(
                key,
                status="retired",
                not_before="2026-01-01T00:00:00Z",
                not_after="2026-03-01T00:00:00Z",
            ),
        )
    )
    assert find_key_for_envelope(registry, _fake_envelope(key)).id == _key_id(key)
    with pytest.raises(KeyWindowError):
        find_key_for_envelope(
            registry,
            _fake_envelope(key, valid_from="2026-04-01T00:00:00Z"),
        )
    assert find_key_for_envelope(
        registry,
        _fake_envelope(key),
        at=datetime(2026, 2, 15, tzinfo=UTC),
    ).id == _key_id(key)


def test_registry_backed_attestation_verification_roundtrip(tmp_path: Path) -> None:
    scc = _load(VECTORS / "known_good" / "ksa_to_foreign_processor_scc.json")
    key = generate_keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        envelope = verify(scc, signing_key=key).to_dict()

    registry = load_registry_from_path(_write_registry(tmp_path, _registry_doc(key)))
    result = verify_attestation_envelope(envelope, registry)
    assert result.valid, result.errors

    revoked = _registry_doc(key, status="revoked")
    revoked_registry = load_registry_from_path(_write_registry(tmp_path, revoked))
    revoked_result = verify_attestation_envelope(envelope, revoked_registry)
    assert not revoked_result.valid
    assert any("KeyStatusError" in error for error in revoked_result.errors)
