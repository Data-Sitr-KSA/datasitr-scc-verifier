"""CLI `run-vectors` contract tests.

The critical invariant: `run-vectors` must exit 0 only when every
non-pending vector matches its expected verdict. A previous v0.1 scaffold
had a hardcoded `return 0` that masked every divergence. These tests
lock down the honest exit-code contract.
"""

from __future__ import annotations

from scc_verifier.cli import main as cli_main


def test_run_vectors_exits_zero_when_all_match() -> None:
    """The shipped corpus should fully pass the v0.1 scope. Any non-pending
    vector that diverges from its v0_1_expected is a contract break."""
    exit_code = cli_main(["run-vectors"])
    assert exit_code == 0, "run-vectors must return 0 when all non-pending vectors match"


def test_verify_exits_zero_on_known_good(tmp_path) -> None:
    out = tmp_path / "attestation.json"
    exit_code = cli_main(
        [
            "verify",
            "--scc",
            "test_vectors/known_good/ksa_domestic_scc.json",
            "--out",
            str(out),
        ]
    )
    assert exit_code == 0
    assert out.exists()
    # Envelope must be non-empty JSON.
    import json
    with out.open() as f:
        envelope = json.load(f)
    assert envelope["credentialSubject"]["verdict"] == "PASS"
    assert envelope["proof"]["proofValue"].startswith("ed25519:")


def test_verify_exits_nonzero_on_structurally_malformed(tmp_path) -> None:
    out = tmp_path / "attestation.json"
    exit_code = cli_main(
        [
            "verify",
            "--scc",
            "test_vectors/known_bad/structurally_malformed.json",
            "--out",
            str(out),
        ]
    )
    assert exit_code != 0
