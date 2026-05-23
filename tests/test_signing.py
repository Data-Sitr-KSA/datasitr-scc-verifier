"""Ed25519 signing round-trip tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from scc_verifier.signing import (
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_sha256,
    save_private_key,
    save_public_key,
    sign_bytes,
    verify_signature,
)


def test_sign_verify_roundtrip() -> None:
    key = generate_keypair()
    payload = b"hello, regulators"
    signed = sign_bytes(key, payload)
    assert signed.startswith("ed25519:")
    assert verify_signature(key.public_key(), payload, signed)


def test_signature_rejects_tampered_payload() -> None:
    key = generate_keypair()
    signed = sign_bytes(key, b"original")
    assert not verify_signature(key.public_key(), b"tampered", signed)


def test_signature_rejects_different_key() -> None:
    key_a = generate_keypair()
    key_b = generate_keypair()
    signed = sign_bytes(key_a, b"payload")
    assert not verify_signature(key_b.public_key(), b"payload", signed)


def test_signature_rejects_malformed_prefix() -> None:
    key = generate_keypair()
    assert not verify_signature(key.public_key(), b"x", "rsa:notreal")
    assert not verify_signature(key.public_key(), b"x", "garbage")


def test_public_key_sha256_is_stable() -> None:
    key = generate_keypair()
    h1 = public_key_sha256(key.public_key())
    h2 = public_key_sha256(key.public_key())
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    key = generate_keypair()
    path = tmp_path / "test.ed25519"
    save_private_key(key, path)
    assert path.exists()
    loaded = load_private_key(path)
    # Sign with original, verify with loaded public key, and vice versa.
    payload = b"test payload"
    signed = sign_bytes(key, payload)
    assert verify_signature(loaded.public_key(), payload, signed)
    signed2 = sign_bytes(loaded, payload)
    assert verify_signature(key.public_key(), payload, signed2)


def test_save_and_load_public_key_roundtrip(tmp_path: Path) -> None:
    key = generate_keypair()
    path = tmp_path / "verifier.pub.pem"
    save_public_key(key.public_key(), path)
    loaded = load_public_key(path)
    payload = b"public key reload"
    assert verify_signature(loaded, payload, sign_bytes(key, payload))


def test_load_rejects_non_ed25519_key(tmp_path: Path) -> None:
    """A file that is not a valid Ed25519 PEM must be rejected."""
    bogus = tmp_path / "bogus.pem"
    bogus.write_bytes(b"not a real PEM")
    with pytest.raises(Exception):
        load_private_key(bogus)


def test_save_creates_missing_parent_dirs(tmp_path: Path) -> None:
    """save_private_key() must create missing parent directories rather
    than raising FileNotFoundError. This is the regression guard against
    the README's `keygen --out ./keys/verifier.ed25519` failing on a
    clean checkout where `./keys/` doesn't exist."""
    key = generate_keypair()
    nested = tmp_path / "deeply" / "nested" / "keys" / "verifier.ed25519"
    assert not nested.parent.exists()
    save_private_key(key, nested)
    assert nested.exists()
    # And the loaded key must work round-trip.
    loaded = load_private_key(nested)
    payload = b"after reload"
    assert verify_signature(loaded.public_key(), payload, sign_bytes(key, payload))
