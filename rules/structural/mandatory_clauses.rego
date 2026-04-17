# STRUCT-001 — Mandatory clause presence
#
# The SDAIA SCC template mandates 15 top-level clauses. This rule verifies
# that every mandatory clause is present in the canonical form.
#
# Regulatory basis: SDAIA Standard Contractual Clauses for Personal Data
# Transfer (2024-09-02).
#
# Rego v1 syntax (OPA >= 1.0).

package sdaia.scc.structural

import rego.v1

default has_all_mandatory_clauses := false

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

has_all_mandatory_clauses if {
	present := {clause | some clause in mandatory_clauses; input.scc[clause]}
	count(mandatory_clauses - present) == 0
}

missing_clauses contains clause if {
	some clause in mandatory_clauses
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

status := "PASS" if has_all_mandatory_clauses

status := "FAIL" if not has_all_mandatory_clauses

detail := sprintf("All %d mandatory clauses present", [count(mandatory_clauses)]) if {
	has_all_mandatory_clauses
}

detail := sprintf("Missing clauses: %v", [missing_list]) if {
	not has_all_mandatory_clauses
	missing_list := [c | some c in missing_clauses]
}
