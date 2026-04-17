# STRUCT-001 — Mandatory clause presence
#
# The SDAIA SCC template mandates 15 top-level clauses. This rule verifies
# that every mandatory clause is present in the canonical form.
#
# Regulatory basis: SDAIA Standard Contractual Clauses for Personal Data
# Transfer (2024-09-02).

package sdaia.scc.structural

default has_all_mandatory_clauses = false

mandatory_clauses := {
    "parties",
    "subject_matter",
    "obligations",
    "data_subject_rights",
    "security",
    "breach_notification",
    "onward_transfers",
    "audit_rights",
    "governing_law",
    "term",
    "liability",
    "annex_a_tra",
    "annex_b_toms_ref",
    "annex_c_subprocessors",
    "signatures",
}

has_all_mandatory_clauses {
    present := {clause | clause := mandatory_clauses[_]; input.scc[clause]}
    count(mandatory_clauses - present) == 0
}

missing_clauses[clause] {
    clause := mandatory_clauses[_]
    not input.scc[clause]
}

# Result object consumed by the verifier library. Always produced; `status`
# and `detail` reflect the evaluation outcome.

result := {
    "id": "STRUCT-001",
    "rule": "has_all_mandatory_clauses",
    "layer": "structural",
    "status": status,
    "detail": detail,
}

status = "PASS" {
    has_all_mandatory_clauses
}

status = "FAIL" {
    not has_all_mandatory_clauses
}

detail = sprintf("All %d mandatory clauses present", [count(mandatory_clauses)]) {
    has_all_mandatory_clauses
}

detail = sprintf("Missing clauses: %v", [missing_list]) {
    not has_all_mandatory_clauses
    missing_list := [c | c := missing_clauses[_]]
}
