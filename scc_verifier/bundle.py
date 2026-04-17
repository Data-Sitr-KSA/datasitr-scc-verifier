"""Rule bundle identity + content hashing.

A rule bundle is the collection of schemas, Rego rule files, and test
vectors (including their per-vector *.expected.json files) that define
what the verifier checks against. For an attestation to be reproducible
by a third party, every attestation must commit to the exact bundle
content it was evaluated under — not an opaque version string, but a
cryptographic hash of the bundle bytes.

Test vectors are included in the bundle hash because they are part of
the public reproducibility contract: a third party verifying an
attestation should be able to re-run the same corpus against the same
rule bundle and get the same outcome. A rule change without a
corresponding test-vector update changes the bundle hash twice — once
for the rule file and once for any vector whose expected outcome moves —
and that dual-change property is what makes rule regressions detectable
at bundle-hash level.

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
#
# Ordering rationale:
#   - schemas/ — the canonical forms (SCC, attestation, evidence)
#   - rules/ — the semantic + structural + judgment rule catalogue
#   - test_vectors/ — the public reproducibility corpus (SCC docs +
#     per-vector *.expected.json outcomes)
BUNDLE_GLOBS: tuple[str, ...] = (
    "schemas/*.json",
    "rules/structural/*.rego",
    "rules/value/*.rego",
    "rules/reference/*.rego",
    "rules/freshness/*.rego",
    "rules/anchor/*.rego",
    "rules/judgment/*.rego",
    "test_vectors/**/*.json",
)

BUNDLE_ID = "sdaia-scc-v0.1-2024-09-02"
"""
Bundle version identifier, format: sdaia-scc-v{major}.{minor}-{YYYY-MM-DD}.

The date suffix identifies the **regulatory moment** the bundle encodes —
in this case the publication of SDAIA's Regulation on Personal Data
Transfer Outside the Kingdom (1 September 2024) and the companion Saudi
SCC template (2 September 2024). It is NOT the build date. A third party
reading an attestation citing this bundle should know which regulatory
text we compiled against, not which day we compiled it.

Minor-version bumps (0.1 → 0.2) indicate rule catalog expansion without
regulatory change. Major-version bumps (1.0 → 2.0) track SDAIA template
amendments; the date suffix moves with the major bump.
"""

BUNDLE_BUILD_DATE = "2026-04-17"
"""
Build-time provenance: the day this bundle's code was cut. Used for
diagnostics and reproducibility traceability; not part of the attestation
envelope.
"""


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
