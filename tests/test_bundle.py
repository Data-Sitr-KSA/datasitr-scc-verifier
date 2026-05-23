"""Rule bundle hash determinism tests.

The bundle hash is what makes attestations reproducible forever. These
tests lock in the hashing semantics so future refactors cannot silently
change the hash for an unchanged rule set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scc_verifier.bundle import (
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
    # The date suffix identifies the regulatory moment, not the build
    # date. For v0.1 this is the SDAIA Data Transfer Regulations and
    # SCC template publication window (1-2 September 2024).
    assert "-2024-09-" in BUNDLE_ID, (
        f"BUNDLE_ID must reference the regulatory moment (2024-09-xx), "
        f"not the build date. Got: {BUNDLE_ID}"
    )


def test_bundle_id_does_not_conflate_with_build_date() -> None:
    """Regression test for D-01 drift finding: the bundle identifier
    previously used the build date (2026-04-17), which semantically
    misrepresents when the encoded regulations were published."""
    from scc_verifier.bundle import BUNDLE_BUILD_DATE

    assert BUNDLE_BUILD_DATE not in BUNDLE_ID, (
        "Build date must not appear in BUNDLE_ID; they are separate concerns"
    )


def test_shipped_vectors_require_active_bundle() -> None:
    """The reproducibility corpus must not drift from the active bundle ID."""
    import json

    vectors_root = Path(__file__).parent.parent / "test_vectors"
    for scc_path in vectors_root.glob("**/*.json"):
        if scc_path.name.endswith(".expected.json"):
            continue
        with scc_path.open() as f:
            scc = json.load(f)
        assert scc.get("rule_bundle_required") == BUNDLE_ID, (
            f"{scc_path.relative_to(vectors_root)} requires "
            f"{scc.get('rule_bundle_required')!r}, expected {BUNDLE_ID!r}"
        )


def test_bundle_manifest_includes_test_vectors() -> None:
    """Test vectors are part of the public reproducibility contract, so
    their bytes must be covered by the bundle hash. If this test fails,
    BUNDLE_GLOBS has drifted from the documented bundle contents."""
    manifest = bundle_manifest()
    vector_paths = [p for p in manifest if p.startswith("test_vectors/")]
    assert vector_paths, "bundle manifest must include test_vectors/*.json files"
    # Sanity: at least the shipped known-good vector and its expected file.
    assert any("known_good" in p for p in vector_paths)
    assert any(".expected.json" in p for p in vector_paths)


def test_bundle_hash_changes_when_test_vector_changes(tmp_path: Path) -> None:
    """Mutating a test-vector file must change the bundle hash. This is
    the regression guard against the reviewer's P2: the vector corpus is
    part of the bundle and must be bound to the hash."""
    # Construct a minimal two-file bundle (one schema, one vector) and
    # confirm that flipping the vector bytes flips the bundle hash.
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    for root, vector_content in [(root_a, b'{"v":1}'), (root_b, b'{"v":2}')]:
        (root / "schemas").mkdir(parents=True)
        (root / "schemas" / "s.json").write_bytes(b'{"schema":"dummy"}')
        (root / "test_vectors" / "cat").mkdir(parents=True)
        (root / "test_vectors" / "cat" / "v.json").write_bytes(vector_content)
    assert compute_bundle_hash(root_a) != compute_bundle_hash(root_b)
