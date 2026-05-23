"""scc-verify CLI.

Subcommands:
  verify              Run verification against a single SCC document.
  verify-attestation  Verify an attestation signature with a public key or registry.
  run-vectors         Run the packaged test-vector corpus.
  keygen              Generate a new Ed25519 signing keypair.
  keys list           List keys in a public key registry.
  bundle info         Show the active rule-bundle identity, hash, and manifest.

v0.3 scope: Layer 1 structural validation + Layer 2 Rego rule evaluation
via the OPA binary + real Ed25519 attestation signing.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from datetime import datetime
from pathlib import Path

from scc_verifier import __version__, self_validate
from scc_verifier import verify as verify_document
from scc_verifier.attestation_verifier import verify_attestation_envelope
from scc_verifier.bundle import (
    BUNDLE_BUILD_DATE,
    BUNDLE_ID,
    bundle_manifest,
    compute_bundle_hash,
)
from scc_verifier.key_registry import KeyRegistry, RegistryError, load_registry
from scc_verifier.signing import (
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_sha256,
    save_private_key,
    save_public_key,
)


def _load_json(path: Path) -> dict:
    with path.open() as f:
        loaded: dict = json.load(f)
    return loaded


def _iso_z(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _registry_load_error_code(error: RegistryError) -> int:
    if str(error).startswith("only https://"):
        return 2
    return 1


def _is_incomplete_without_opa(envelope: dict) -> bool:
    """Return True when the only incomplete condition is missing OPA."""
    subject = envelope["credentialSubject"]
    if subject["verdict"] != "INCOMPLETE":
        return False
    checks = subject["checks"]
    incomplete = [c for c in checks if c["status"] == "INCOMPLETE"]
    return bool(incomplete) and all(
        "OPA binary not available" in c.get("detail", "") for c in incomplete
    )


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
        f"{s['requires_human_review']} REVIEW / "
        f"{s['not_applicable']} NA / "
        f"{s['incomplete']} INCOMPLETE)",
        file=sys.stderr,
    )
    if verdict in ("PASS", "PASS_WITH_COUNSEL_ITEMS"):
        return 0
    if args.allow_incomplete_without_opa and _is_incomplete_without_opa(envelope):
        print(
            "warning: returning success only because --allow-incomplete-without-opa was set; "
            "the attestation verdict remains INCOMPLETE",
            file=sys.stderr,
        )
        return 0
    return 1


def _cmd_run_vectors(args: argparse.Namespace) -> int:
    """Run packaged test vectors.

    Each vector's `<basename>.expected.json` declares the expected outcome.
    The current verifier evaluates Layer 1 (schema) plus Layer 2 (Rego rules)
    via OPA, so vectors are matched against this priority order:

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

            # Expectation priority: current expected field → v1.0 target → v0.1 legacy.
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


def _cmd_bundle_info(args: argparse.Namespace) -> int:
    """Print the bundle identity, hash, and (optionally) the file manifest.

    This is the command a reviewer runs first when they want to confirm
    they are looking at the same bytes the attestation was produced from.
    Output is JSON when `--format json`, human-readable otherwise. Both
    formats contain the same fields — the JSON form is for CI and the
    human form for eyeballs.
    """
    manifest = bundle_manifest()
    bundle_hash = compute_bundle_hash()

    if args.format == "json":
        payload: dict[str, object] = {
            "bundle_id": BUNDLE_ID,
            "bundle_build_date": BUNDLE_BUILD_DATE,
            "bundle_hash": bundle_hash,
            "file_count": len(manifest),
        }
        if args.verbose:
            payload["manifest"] = manifest
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Bundle ID:         {BUNDLE_ID}")
    print(f"Bundle build date: {BUNDLE_BUILD_DATE}")
    print(f"Bundle hash:       {bundle_hash}")
    print(f"File count:        {len(manifest)}")
    if args.verbose:
        print()
        print("Manifest (relative path → SHA-256 of content):")
        for rel, h in sorted(manifest.items()):
            print(f"  {h}  {rel}")
    else:
        print("(pass --verbose to print the per-file manifest)")
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(
            f"error: {out} already exists; pass --force to overwrite",
            file=sys.stderr,
        )
        return 2
    if args.public_out:
        public_out = Path(args.public_out)
        if public_out.exists() and not args.force:
            print(
                f"error: {public_out} already exists; pass --force to overwrite",
                file=sys.stderr,
            )
            return 2
    key = generate_keypair()
    save_private_key(key, out)
    print(f"Wrote Ed25519 private key to {out} (mode 0600)")
    if args.public_out:
        save_public_key(key.public_key(), public_out)
        print(f"Wrote Ed25519 public key to {public_out}")
    print(f"Public key id: key-{public_key_sha256(key.public_key())}")
    print("Guard this file. Do not commit it. See .gitignore for *.ed25519.")
    return 0


def _cmd_verify_attestation(args: argparse.Namespace) -> int:
    attestation_path = Path(args.attestation)
    if not attestation_path.exists():
        print(f"error: attestation file not found: {attestation_path}", file=sys.stderr)
        return 2

    envelope = _load_json(attestation_path)
    if args.key_registry:
        try:
            key_source = load_registry(args.key_registry)
        except FileNotFoundError:
            print(f"error: registry file not found: {args.key_registry}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"error: could not read registry: {e}", file=sys.stderr)
            return 2
        except RegistryError as e:
            print(f"error: {e}", file=sys.stderr)
            return _registry_load_error_code(e)
        result = verify_attestation_envelope(envelope, key_source)
    else:
        public_key_path = Path(args.public_key)
        if not public_key_path.exists():
            print(f"error: public key file not found: {public_key_path}", file=sys.stderr)
            return 2
        try:
            public_key = load_public_key(public_key_path)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        result = verify_attestation_envelope(
            envelope,
            public_key,
            require_verification_method_match=not args.allow_key_mismatch,
        )

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Schema valid:        {result.schema_valid}")
        print(f"Signature valid:     {result.signature_valid}")
        print(f"Key id matches VC:   {result.verification_method_matches_key}")
        print(f"Overall valid:       {result.valid}")
        for error in result.errors:
            print(f"error: {error}", file=sys.stderr)
    return 0 if result.valid else 1


def _registry_to_dict(registry: KeyRegistry) -> dict:
    return {
        "schema_version": registry.schema_version,
        "issuer": registry.issuer,
        "generated_at": _iso_z(registry.generated_at),
        "keys": [
            {
                "id": key.id,
                "status": key.status,
                "not_before": _iso_z(key.not_before),
                "not_after": _iso_z(key.not_after) if key.not_after is not None else None,
                "purpose": key.purpose,
            }
            for key in registry.keys
        ],
    }


def _cmd_keys_list(args: argparse.Namespace) -> int:
    try:
        registry = load_registry(args.registry)
    except (OSError, RegistryError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not registry.keys:
        print("error: registry contains no keys", file=sys.stderr)
        return 1

    payload = _registry_to_dict(registry)
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Issuer:       {registry.issuer}")
    print(f"Schema:       {registry.schema_version}")
    print(f"Generated at: {_iso_z(registry.generated_at)}")
    print("Keys:")
    for key in registry.keys:
        not_after = _iso_z(key.not_after) if key.not_after is not None else "-"
        purpose = key.purpose if key.purpose is not None else "-"
        print(
            f"  {key.id}  status={key.status}  "
            f"not_before={_iso_z(key.not_before)}  not_after={not_after}  "
            f"purpose={purpose}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scc-verify",
        description="Draft canonical-form verifier for machine-checkable SDAIA SCC elements",
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
    p_verify.add_argument(
        "--allow-incomplete-without-opa",
        action="store_true",
        help=(
            "Return exit code 0 for an INCOMPLETE attestation caused only by a missing "
            "OPA binary. The emitted verdict remains INCOMPLETE."
        ),
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_run = sub.add_parser("run-vectors", help="Run the packaged test-vector corpus")
    p_run.set_defaults(func=_cmd_run_vectors)

    p_key = sub.add_parser("keygen", help="Generate an Ed25519 signing keypair")
    p_key.add_argument("--out", required=True, help="Output path for the private key")
    p_key.add_argument("--public-out", help="Optional output path for the public key PEM")
    p_key.add_argument("--force", action="store_true", help="Overwrite existing file at --out")
    p_key.set_defaults(func=_cmd_keygen)

    p_verify_attestation = sub.add_parser(
        "verify-attestation",
        help="Verify an attestation envelope signature with an Ed25519 public key or registry",
    )
    p_verify_attestation.add_argument(
        "--attestation",
        required=True,
        help="Path to attestation envelope JSON",
    )
    key_source = p_verify_attestation.add_mutually_exclusive_group(required=True)
    key_source.add_argument(
        "--public-key",
        help="Path to Ed25519 public key PEM",
    )
    key_source.add_argument(
        "--key-registry",
        help="HTTPS URL, file:// URL, or local path to a public key registry JSON file",
    )
    p_verify_attestation.add_argument(
        "--allow-key-mismatch",
        action="store_true",
        help=(
            "Verify the signature even if proof.verificationMethod does not match the public "
            "key id. Has no effect with --key-registry, which always resolves by key id."
        ),
    )
    p_verify_attestation.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Output format (default: human).",
    )
    p_verify_attestation.set_defaults(func=_cmd_verify_attestation)

    p_keys = sub.add_parser(
        "keys",
        help="Inspect public key registries.",
    )
    keys_sub = p_keys.add_subparsers(dest="keys_cmd", required=True)
    p_keys_list = keys_sub.add_parser(
        "list",
        help="List keys from a public key registry.",
    )
    p_keys_list.add_argument(
        "--registry",
        required=True,
        help="HTTPS URL, file:// URL, or local path to a public key registry JSON file",
    )
    p_keys_list.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Output format (default: human).",
    )
    p_keys_list.set_defaults(func=_cmd_keys_list)

    p_bundle = sub.add_parser(
        "bundle",
        help="Inspect the rule bundle (ID, hash, manifest).",
    )
    bundle_sub = p_bundle.add_subparsers(dest="bundle_cmd", required=True)
    p_bundle_info = bundle_sub.add_parser(
        "info",
        help="Print the bundle ID, hash, and file manifest.",
    )
    p_bundle_info.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Output format (default: human).",
    )
    p_bundle_info.add_argument(
        "--verbose",
        action="store_true",
        help="Include the full per-file manifest.",
    )
    p_bundle_info.set_defaults(func=_cmd_bundle_info)

    args = parser.parse_args(argv)
    exit_code: int = args.func(args)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
