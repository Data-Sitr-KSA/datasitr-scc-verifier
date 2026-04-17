"""Layer 2 — OPA/Rego rule evaluation.

Evaluates the authored Rego rules against an SCC document and returns a
list of CheckResult objects. Uses the OPA binary as a subprocess so that
the canonical Rego runtime (github.com/open-policy-agent/opa) is the
ground truth, not a re-implementation.

Why subprocess rather than an embedded library:
  - OPA is widely available (`brew install opa`, Docker images, deb/rpm
    packages). Third parties reproducing our verdicts use the same
    binary.
  - The OPA binary is a single Go executable with no shared-library
    dependencies, so it works identically across macOS / Linux / Windows.
  - Pure-Python Rego implementations exist but are less mature and diverge
    from OPA in edge cases; we do not want rule-evaluation drift.

Discovery order for the OPA binary:
  1. `SCC_OPA_BIN` environment variable if set.
  2. `opa` on PATH.
  3. Loudly raise with install instructions if neither is present.

Rule registry:
  Each known rule (STRUCT-001, VAL-GOV-LAW, ...) maps to a Rego package
  and query expression. Adding a rule = adding a row in `RULE_REGISTRY`
  plus authoring the corresponding .rego file. No other code changes.

For v0.2 we evaluate the 8 already-authored Layer-2 / judgment rules
plus the STRUCT-001 rule (the latter can also be evaluated via Layer 1
schema validation, but running it through OPA too is a cheap
consistency check against the schema).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scc_verifier.api import CheckResult

REPO_ROOT = Path(__file__).parent.parent
RULES_DIR = REPO_ROOT / "rules"


class OpaNotFoundError(RuntimeError):
    """Raised when no OPA binary is discoverable. Message includes install
    instructions so CI and first-time users are not stuck."""


@dataclass(frozen=True)
class RuleDefinition:
    """One authored Rego rule registered with the evaluator.

    The evaluator queries `data.{package}.{result_var}` after loading all
    rule files; Rego returns the structured result dict that `CheckResult`
    is constructed from.
    """

    id: str
    package: str
    result_var: str
    source_file: str  # relative path from rules/, for traceability


RULE_REGISTRY: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        id="STRUCT-001",
        package="sdaia.scc.structural",
        result_var="result",
        source_file="structural/mandatory_clauses.rego",
    ),
    RuleDefinition(
        id="VAL-GOV-LAW",
        package="sdaia.scc.value",
        result_var="governing_law_result",
        source_file="value/governing_law.rego",
    ),
    RuleDefinition(
        id="VAL-DISPUTE-FORUM",
        package="sdaia.scc.value",
        result_var="dispute_forum_result",
        source_file="value/governing_law.rego",
    ),
    RuleDefinition(
        id="VAL-BREACH-EXPORTER",
        package="sdaia.scc.value",
        result_var="exporter_window_result",
        source_file="value/breach_windows.rego",
    ),
    RuleDefinition(
        id="VAL-BREACH-SDAIA",
        package="sdaia.scc.value",
        result_var="sdaia_window_result",
        source_file="value/breach_windows.rego",
    ),
    RuleDefinition(
        id="VAL-SENSITIVE-ROUTE",
        package="sdaia.scc.value",
        result_var="sensitive_route_result",
        source_file="value/sensitive_data_routing.rego",
    ),
    RuleDefinition(
        id="JUDGE-LIAB-001",
        package="sdaia.scc.judgment",
        result_var="liability_result",
        source_file="judgment/flagged_clauses.rego",
    ),
    RuleDefinition(
        id="JUDGE-GOV-ACCESS-001",
        package="sdaia.scc.judgment",
        result_var="gov_access_result",
        source_file="judgment/flagged_clauses.rego",
    ),
    RuleDefinition(
        id="JUDGE-INDEM-001",
        package="sdaia.scc.judgment",
        result_var="indemnification_result",
        source_file="judgment/flagged_clauses.rego",
    ),
)


def find_opa() -> str:
    """Locate the OPA binary. Raises OpaNotFoundError with install help."""
    env_bin = os.environ.get("SCC_OPA_BIN")
    if env_bin:
        path = Path(env_bin)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise OpaNotFoundError(f"SCC_OPA_BIN={env_bin!r} is set but is not an executable file.")
    found = shutil.which("opa")
    if found:
        return found
    raise OpaNotFoundError(
        "OPA binary not found. Install it with one of:\n"
        "  macOS:   brew install opa\n"
        "  Linux:   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x opa && sudo mv opa /usr/local/bin/\n"
        "  Docker:  docker run openpolicyagent/opa:latest\n"
        "Or set SCC_OPA_BIN=/path/to/opa explicitly."
    )


def is_opa_available() -> bool:
    """Return True if an OPA binary is discoverable, False otherwise.

    Useful for CI branching: skip Layer 2 tests when OPA is absent rather
    than failing the entire suite.
    """
    try:
        find_opa()
        return True
    except OpaNotFoundError:
        return False


def _rule_source_paths() -> list[str]:
    """Return the list of .rego files to load into OPA, as absolute paths.

    We read the registry rather than globbing so that adding a rule to
    the registry is the authoritative "now it runs" signal — no surprise
    rules get evaluated because someone dropped a file in rules/.
    """
    paths: list[str] = []
    seen: set[Path] = set()
    for rule in RULE_REGISTRY:
        path = (RULES_DIR / rule.source_file).resolve()
        if path not in seen:
            seen.add(path)
            if not path.is_file():
                raise FileNotFoundError(f"Rego source missing: {path}")
            paths.append(str(path))
    return paths


def _build_input(scc_document: dict[str, Any]) -> dict[str, Any]:
    """Wrap the SCC document into the input shape the rules expect.

    The rules all reference `input.scc.<field>`, so we wrap as
    `{"scc": <document>}`. Keeping the wrapper here means rule authors
    never have to think about input shape when adding new rules.
    """
    return {"scc": scc_document}


def _opa_eval(opa_bin: str, input_doc: dict[str, Any], query: str, data_paths: list[str]) -> Any:
    """Run `opa eval` with a JSON input and --format=json, return parsed.

    Raises subprocess.CalledProcessError on non-zero exit. The `query`
    should resolve to the structured result dict (e.g.,
    `data.sdaia.scc.value.governing_law_result`).
    """
    cmd = [opa_bin, "eval", "--format=json", "--stdin-input", query]
    for p in data_paths:
        cmd.extend(["--data", p])
    proc = subprocess.run(
        cmd,
        input=json.dumps(input_doc),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(proc.stdout)


def evaluate_rules(scc_document: dict[str, Any]) -> tuple[CheckResult, ...]:
    """Evaluate the full RULE_REGISTRY against an SCC document.

    Returns one CheckResult per rule. Raises OpaNotFoundError if the OPA
    binary isn't discoverable — caller decides how to react (the api.verify
    path degrades gracefully to Layer-1-only when OPA is absent).

    Implementation note: we issue one `opa eval` per rule. This is
    simpler than one bulk query that returns everything, avoids the
    caller having to walk a nested object, and keeps error messages
    scoped to the rule that failed. Performance is fine — OPA startup is
    ~20ms per call, rule evaluation is microseconds, and the rule count
    is ~10 for v0.2.
    """
    opa_bin = find_opa()
    input_doc = _build_input(scc_document)
    data_paths = _rule_source_paths()

    results: list[CheckResult] = []
    for rule in RULE_REGISTRY:
        query = f"data.{rule.package}.{rule.result_var}"
        raw = _opa_eval(opa_bin, input_doc, query, data_paths)
        rego_result = _extract_result(raw, query)
        results.append(_to_check_result(rego_result, rule))
    return tuple(results)


def _extract_result(raw: dict[str, Any], query: str) -> dict[str, Any]:
    """Pull the structured result dict out of OPA's eval response.

    OPA's `--format=json` shape: {"result": [{"expressions": [{"value": <x>, ...}]}]}
    We always query a single expression; we take the first (and only)
    expression's value.
    """
    try:
        value: dict[str, Any] = raw["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"OPA returned an unexpected shape for query {query!r}: {raw!r}") from e
    return value


def _to_check_result(rego_result: dict[str, Any], rule: RuleDefinition) -> CheckResult:
    """Translate a Rego result dict into our CheckResult dataclass.

    The Rego rules are authored to return dicts matching the CheckResult
    shape (id, rule, layer, status, optional detail / observed_value /
    counsel_field / rationale_required). This function is a thin mapping,
    not a transformation.
    """
    return CheckResult(
        id=rego_result.get("id", rule.id),
        rule=rego_result.get("rule", "unknown"),
        layer=rego_result.get("layer", "value"),
        status=rego_result.get("status", "FAIL"),
        detail=rego_result.get("detail"),
        observed_value=rego_result.get("observed_value"),
        counsel_field=rego_result.get("counsel_field"),
        rationale_required=bool(rego_result.get("rationale_required", False)),
    )
