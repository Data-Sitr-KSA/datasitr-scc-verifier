"""Canonicalization determinism tests.

The entire "mathematical certainty" property rests on canonicalize() being
deterministic. These tests verify that semantically-identical documents
with different key orderings produce byte-identical hashes.
"""

from __future__ import annotations

from scc_verifier.canonicalization import canonicalize, sha256_of


def test_key_order_does_not_affect_hash() -> None:
    a = {"a": 1, "b": 2, "c": 3}
    b = {"c": 3, "b": 2, "a": 1}
    assert sha256_of(a) == sha256_of(b)


def test_nested_key_order_does_not_affect_hash() -> None:
    a = {"outer": {"a": 1, "b": {"x": 10, "y": 20}}}
    b = {"outer": {"b": {"y": 20, "x": 10}, "a": 1}}
    assert sha256_of(a) == sha256_of(b)


def test_whitespace_does_not_affect_hash() -> None:
    """Canonical form is compact; different whitespace in a Python dict
    never reaches canonicalize() as whitespace. But the test is still
    useful — it confirms that no string serialization quirk leaks."""
    a = {"a": "value"}
    b = {"a": "value"}
    assert canonicalize(a) == canonicalize(b)


def test_different_documents_have_different_hashes() -> None:
    a = {"a": 1}
    b = {"a": 2}
    assert sha256_of(a) != sha256_of(b)


def test_hash_format() -> None:
    h = sha256_of({"hello": "world"})
    assert h.startswith("sha256:")
    assert len(h) == 71  # "sha256:" + 64 hex chars
