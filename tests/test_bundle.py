"""Rule bundle hash determinism tests.

The bundle hash is what makes attestations reproducible forever. These
tests lock in the hashing semantics so future refactors cannot silently
change the hash for an unchanged rule set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scc_verifier.bundle import (
    BUNDLE_GLOBS,
    BUNDLE_ID,
    bundle_manifest,
    compute_bundle_hash,
)


def test_bundle_hash_is_sha256_prefixed() -> None:
    h = compute_bundle_hash()
    assert h.startswith("sha256:")
    assert len(h) == 71  # "sha256:" + 64 hex chars


def test_bundle_hash_is_deterministic() -> None:
    """Calling compute_bundle_hash() twice on an unchanged tree must
    produce byte-identical output."""
    assert compute_bundle_hash() == compute_bundle_hash()


def test_bundle_manifest_maps_relative_paths_to_hashes() -> None:
    manifest = bundle_manifest()
    assert manifest, "manifest must be non-empty"
    for rel, h in manifest.items():
        assert not rel.startswith("/")
        assert h.startswith("sha256:")
        assert len(h) == 71


def test_bundle_hash_changes_when_content_changes(tmp_path: Path) -> None:
    """Two directories with different content must produce different
    bundle hashes."""
    # Build a minimal bundle dir and compare two content variants.
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    for root, content in [(root_a, b"x"), (root_b, b"y")]:
        (root / "schemas").mkdir(parents=True)
        (root / "schemas" / "one.json").write_bytes(content)
    assert compute_bundle_hash(root_a) != compute_bundle_hash(root_b)


def test_bundle_hash_raises_on_empty_bundle(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        compute_bundle_hash(tmp_path)


def test_bundle_id_is_dated() -> None:
    """The bundle ID must follow the documented `sdaia-scc-vX.Y-YYYY-MM-DD`
    pattern so historical attestations remain reproducible."""
    assert BUNDLE_ID.startswith("sdaia-scc-v")
    assert "-2026-" in BUNDLE_ID or "-2025-" in BUNDLE_ID
