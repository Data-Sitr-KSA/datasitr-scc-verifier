"""scc-verify CLI.

Subcommands:
  verify         Run verification against a single SCC document.
  run-vectors    Run the packaged test-vector corpus.
  keygen         Generate a new Ed25519 signing keypair.

v0.1 scope: Layer 1 structural validation + real Ed25519 attestation
signing. Layer 2 (Rego semantic rules) lands in v0.2.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

from scc_verifier import __version__, self_validate, verify as verify_document
from scc_verifier.signing import (
    generate_keypair,
    load_private_key,
    save_private_key,
)


def _load_json(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def _cmd_verify(args: argparse.Namespace) -> int:
    scc_path = Path(args.scc)
    if not scc_path.exists():
        print(f"error: SCC file not found: {scc_path}", file=sys.stderr)
        return 2

    if args.signing_key:
        key_path = Path(args.signing_key)
        if not key_path.exists():
            print(f"error: signing key not found: {key_path}", file=sys.stderr)
            return 2
        signing_key = load_private_key(key_path)
    else:
        signing_key = None

    scc = _load_json(scc_path)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        attestation = verify_document(scc, signing_key=signing_key)
        for w in captured:
            print(f"warning: {w.message}", file=sys.stderr)

    envelope = attestation.to_dict()

    # Self-check: the envelope MUST validate against its own schema. This
    # is the guard against the class of bug where the verifier emits
    # something that fails its own published schema.
    self_check = self_validate(attestation)
    if not self_check.valid:
        print(
            "error: attestation envelope failed self-validation:\n  "
            + "\n  ".join(self_check.errors),
            file=sys.stderr,
        )
        return 3

    if args.out:
        with Path(args.out).open("w") as f:
            json.dump(envelope, f, indent=2)
        print(f"Attestation written to {args.out}")
    else:
        print(json.dumps(envelope, indent=2))

    verdict = attestation.subject.verdict
    s = attestation.subject.summary
    print(
        f"Verdict: {verdict}  "
        f"({s['passed']} PASS / {s['failed']} FAIL / "
        f"{s['requires_human_review']} REVIEW)",
        file=sys.stderr,
    )
    return 0 if verdict in ("PASS", "PASS_WITH_COUNSEL_ITEMS") else 1


def _cmd_run_vectors(args: argparse.Namespace) -> int:
    """Run packaged test vectors.

    Each vector's `<basename>.expected.json` declares the expected outcome.
    v0.2 evaluates Layer 1 (schema) plus Layer 2 (Rego rules) via OPA, so
    vectors are matched against this priority order:

        1. `v0_2_expected`   (preferred — current code version)
        2. `verdict`         (v1.0 target, same shape)
        3. `v0_1_expected`   (legacy fallback for un-updated vectors)

    Vectors marked `pending_layer_2: true` are still honored as a skip
    signal — if a future rule regresses and the vector drops back to
    Layer-1-only behavior, the skip re-engages automatically rather than
    generating a noisy FAIL.

    Exits 0 iff every non-pending vector matches its declared expectation.
    """
    vectors_root = Path(__file__).parent.parent / "test_vectors"
    categories = ("known_good", "known_bad", "judgment_required")

    failures: list[tuple[str, str, str, str]] = []
    skipped: list[tuple[str, str, str]] = []
    ran = 0

    for cat in categories:
        for scc_file in sorted((vectors_root / cat).glob("*.json")):
            # Expected files follow the pattern: `<vector_basename>.expected.json`.
            # Skip the expected files themselves.
            if scc_file.name.endswith(".expected.json"):
                continue
            expected_path = scc_file.with_suffix("").with_suffix(".expected.json")
            if not expected_path.exists():
                print(
                    f"  WARN  {cat}/{scc_file.name}  — no expected file at {expected_path.name}; skipping"
                )
                continue
            expected = _load_json(expected_path)

            if expected.get("pending_layer_2"):
                reason = expected.get("pending_reason", "layer 2 not yet wired")
                skipped.append((cat, scc_file.name, reason))
                print(f"  SKIP  {cat}/{scc_file.name}  — {reason}")
                continue

            # Expectation priority: v0.2 → v1.0 target → v0.1 legacy.
            want = (
                expected.get("v0_2_expected")
                or expected.get("verdict")
                or expected.get("v0_1_expected")
            )
            scc = _load_json(scc_file)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                attestation = verify_document(scc)
            got = attestation.subject.verdict

            if got == want:
                print(f"  PASS  {cat}/{scc_file.name}  → {got}")
            else:
                print(f"  FAIL  {cat}/{scc_file.name}  → {got}  (expected {want})")
                failures.append((cat, scc_file.name, got, want or "<unset>"))
            ran += 1

    print(
        f"\nRan {ran} vectors. {len(failures)} divergences. {len(skipped)} skipped (layer 2 pending)."
    )
    return 0 if not failures else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(
            f"error: {out} already exists; pass --force to overwrite",
            file=sys.stderr,
        )
        return 2
    key = generate_keypair()
    save_private_key(key, out)
    print(f"Wrote Ed25519 private key to {out} (mode 0600)")
    print(f"Guard this file. Do not commit it. See .gitignore for *.ed25519.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scc-verify",
        description="Machine-verifiable compliance for SDAIA SCCs",
    )
    parser.add_argument("--version", action="version", version=f"scc-verify {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify", help="Verify a single SCC document")
    p_verify.add_argument("--scc", required=True, help="Path to SCC JSON document")
    p_verify.add_argument(
        "--signing-key",
        help="Path to an Ed25519 private key (PEM). If omitted, an ephemeral key is used.",
    )
    p_verify.add_argument("--out", help="Write attestation JSON to this path")
    p_verify.set_defaults(func=_cmd_verify)

    p_run = sub.add_parser("run-vectors", help="Run the packaged test-vector corpus")
    p_run.set_defaults(func=_cmd_run_vectors)

    p_key = sub.add_parser("keygen", help="Generate an Ed25519 signing keypair")
    p_key.add_argument("--out", required=True, help="Output path for the private key")
    p_key.add_argument(
        "--force", action="store_true", help="Overwrite existing file at --out"
    )
    p_key.set_defaults(func=_cmd_keygen)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
