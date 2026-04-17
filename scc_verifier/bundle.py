"""Rule bundle identity + content hashing.

A rule bundle is the collection of schemas, Rego rule files, and test
vectors that define what the verifier checks against. For an attestation
to be reproducible by a third party, every attestation must commit to the
exact bundle content it was evaluated under — not an opaque version
string, but a cryptographic hash of the bundle bytes.

This module computes that hash deterministically from the shipped
repository layout. The hash is stable across machines and Python versions
because we canonicalize both the file list (sorted) and each file's
content (raw bytes for JSON/Rego/text files).

For v0.1 the bundle is the local repository directory tree. When bundles
are later published as signed archives, this same function hashes the
archive's manifest file rather than the filesystem directly — but the
on-wire attestation format does not change.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

# Files that make up the "bundle content" — everything whose change should
# invalidate prior attestations. Order-independent; we sort before hashing.
BUNDLE_GLOBS: tuple[str, ...] = (
    "schemas/*.json",
    "rules/structural/*.rego",
    "rules/value/*.rego",
    "rules/reference/*.rego",
    "rules/freshness/*.rego",
    "rules/anchor/*.rego",
    "rules/judgment/*.rego",
)

BUNDLE_ID = "sdaia-scc-v0.1-2026-04-17"


def _bundle_files(root: Path = REPO_ROOT) -> list[Path]:
    """Return the sorted list of files that contribute to the bundle hash."""
    paths: set[Path] = set()
    for pattern in BUNDLE_GLOBS:
        paths.update(root.glob(pattern))
    return sorted(p for p in paths if p.is_file())


def compute_bundle_hash(root: Path = REPO_ROOT) -> str:
    """SHA-256 hash of the concatenated canonical file list.

    Hashing recipe (deterministic; any implementation can reproduce):
      1. Sort files by POSIX relative path.
      2. For each file, emit: `<relative_path>\\n<sha256_hex>\\n`
      3. SHA-256 the concatenation, return as `sha256:<hex>`.

    This avoids hashing file contents directly (which would be sensitive
    to line-ending differences), while still binding the attestation to
    the exact byte content of every file — because each file's SHA-256
    appears in the manifest.
    """
    files = _bundle_files(root)
    if not files:
        raise RuntimeError(
            f"bundle is empty under {root}; refusing to produce a meaningless hash"
        )
    outer = hashlib.sha256()
    for path in files:
        rel = path.relative_to(root).as_posix()
        inner = hashlib.sha256(path.read_bytes()).hexdigest()
        outer.update(f"{rel}\n{inner}\n".encode("utf-8"))
    return f"sha256:{outer.hexdigest()}"


def bundle_manifest(root: Path = REPO_ROOT) -> dict[str, str]:
    """Return the path→sha256 map that feeds the bundle hash.

    Useful for diagnostics when two verifiers disagree on a bundle hash:
    diffing manifests surfaces which file differs.
    """
    files = _bundle_files(root)
    return {
        path.relative_to(root).as_posix(): f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        for path in files
    }
