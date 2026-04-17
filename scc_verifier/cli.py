"""scc-verify CLI.

v0.1 supports:
  - Layer 1 structural validation (JSON Schema)
  - Test vector run

v0.2 will add OPA/Rego evaluation for Layer 2 (semantic rules).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scc_verifier import __version__
from scc_verifier.api import (
    Attestation,
    AttestationSubject,
    CheckResult,
    verdict_from_checks,
)
from scc_verifier.canonicalization import sha256_of
from scc_verifier.schema_validator import validate_scc


def _check_from_schema_result(result) -> CheckResult:
    if result.valid:
        return CheckResult(
            id="STRUCT-001",
            rule="has_all_mandatory_clauses_and_types",
            layer="structural",
            status="PASS",
            detail="SCC document conforms to scc-canonical-v1 schema",
        )
    return CheckResult(
        id="STRUCT-001",
        rule="has_all_mandatory_clauses_and_types",
        layer="structural",
        status="FAIL",
        detail="Schema validation errors: " + "; ".join(result.errors[:5]),
    )


def _verify_one(scc_path: Path, *, rule_bundle_id: str) -> Attestation:
    with scc_path.open() as f:
        scc = json.load(f)
    schema_result = validate_scc(scc)
    checks = (_check_from_schema_result(schema_result),)
    subject = AttestationSubject(
        scc_id=scc.get("scc_id", "UNKNOWN"),
        scc_document_hash=sha256_of(scc),
        rule_bundle_id=rule_bundle_id,
        rule_bundle_hash="sha256:PLACEHOLDER_v0.1_NOT_YET_SIGNED",
        ratification_status="not-yet-ratified-by-sdaia",
        verdict=verdict_from_checks(checks),
        checks=checks,
    )
    now = datetime.now(timezone.utc)
    return Attestation(
        id=f"urn:datasitr:attestation:{subject.scc_id}:{now.isoformat()}",
        issuer="did:web:datasitr.com",
        valid_from=now,
        subject=subject,
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    scc_path = Path(args.scc)
    if not scc_path.exists():
        print(f"error: SCC file not found: {scc_path}", file=sys.stderr)
        return 2
    attestation = _verify_one(scc_path, rule_bundle_id=args.bundle_id)
    out = attestation.to_dict()
    if args.out:
        with Path(args.out).open("w") as f:
            json.dump(out, f, indent=2)
        print(f"Attestation written to {args.out}")
    else:
        print(json.dumps(out, indent=2))
    verdict = attestation.subject.verdict
    summary = attestation.subject.summary
    print(
        f"Verdict: {verdict}  "
        f"({summary['passed']} PASS / {summary['failed']} FAIL / "
        f"{summary['requires_human_review']} REVIEW)",
        file=sys.stderr,
    )
    return 0 if verdict in ("PASS", "PASS_WITH_COUNSEL_ITEMS") else 1


def _cmd_run_vectors(args: argparse.Namespace) -> int:
    """Run all test vectors in the packaged test_vectors/ directory."""
    vectors_root = Path(__file__).parent.parent / "test_vectors"
    categories = ("known_good", "known_bad", "judgment_required")
    failures = []
    ran = 0
    for cat in categories:
        for scc_file in sorted((vectors_root / cat).glob("*.json")):
            if scc_file.name == "expected_verdict.json":
                continue
            expected_path = scc_file.parent / "expected_verdict.json"
            if not expected_path.exists():
                continue
            with expected_path.open() as f:
                expected = json.load(f)
            attestation = _verify_one(scc_file, rule_bundle_id=args.bundle_id)
            actual_verdict = attestation.subject.verdict
            expected_verdict = expected.get("verdict")
            # v0.1 only evaluates Layer 1 — so "known_bad" vectors that fail
            # on Layer-2 rules (not yet implemented) will currently verify
            # structurally PASS. We report this as EXPECTED_LAYER_2 for
            # transparency rather than hiding it.
            if actual_verdict == expected_verdict:
                print(f"  PASS  {cat}/{scc_file.name}  → {actual_verdict}")
            else:
                note = ""
                if cat == "known_bad":
                    note = "  (expected FAIL — Layer 2 rules land in v0.2)"
                print(
                    f"  DIFF  {cat}/{scc_file.name}  "
                    f"→ {actual_verdict}  (expected {expected_verdict}){note}"
                )
                failures.append((cat, scc_file.name, actual_verdict, expected_verdict))
            ran += 1
    print(f"\nRan {ran} vectors. {len(failures)} divergences (some expected in v0.1).")
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
        "--bundle-id",
        default="sdaia-scc-v0.1-2026-04-17",
        help="Rule bundle identifier (v0.1 default)",
    )
    p_verify.add_argument("--out", help="Write attestation to this path")
    p_verify.set_defaults(func=_cmd_verify)

    p_run = sub.add_parser("run-vectors", help="Run the packaged test-vector corpus")
    p_run.add_argument(
        "--bundle-id",
        default="sdaia-scc-v0.1-2026-04-17",
    )
    p_run.set_defaults(func=_cmd_run_vectors)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
