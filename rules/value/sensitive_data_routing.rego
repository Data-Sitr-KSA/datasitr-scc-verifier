# VAL-SENSITIVE-ROUTE — Article 18 sensitive data with onward transfer needs review
#
# If any Article 18 sensitive category is declared in scope (health,
# biometric, genetic, criminal, financial, religious, ethnic, political, union
# membership) and onward transfers are permitted, v0.2 requires counsel review.
#
# This is intentionally not a hard FAIL in the draft bundle. SDAIA's SCC text
# contemplates subsequent transfer where the third party accedes to the clauses
# and the appropriate template/provisions apply. v0.2 does not yet verify
# accession, role-template fit, additional sensitive-data safeguards, or TRA
# evidence, so the safe machine-checkable posture is to flag the route for
# counsel review instead of asserting a regulatory violation.
#
# Regulatory basis: SDAIA SCC Clause 13 sensitive-data and subsequent-transfer
# provisions; PDPL Article 18; Data Transfer Regulations.
#
# Rego v1 syntax (OPA >= 1.0).

package sdaia.scc.value

import rego.v1

default sensitive_route_needs_review := false

sensitive_categories_present if {
	some cat in input.scc.subject_matter.sensitive_categories_art18
	cat != "none"
}

sensitive_route_needs_review if {
	sensitive_categories_present
	input.scc.onward_transfers.permitted == true
}

sensitive_route_result := {
	"id": "VAL-SENSITIVE-ROUTE",
	"rule": "sensitive_data_forbids_onward_transfer",
	"layer": "value",
	"status": sensitive_status,
	"detail": sensitive_detail,
	"counsel_field": sensitive_counsel_field,
	"rationale_required": sensitive_rationale_required,
}

sensitive_status := "PASS" if not sensitive_route_needs_review

sensitive_status := "REQUIRES_HUMAN_REVIEW" if sensitive_route_needs_review

sensitive_detail := "No Article 18 sensitive categories declared OR onward transfers correctly disallowed" if {
	not sensitive_route_needs_review
}

sensitive_detail := "Article 18 sensitive category declared AND onward transfers permitted — counsel must confirm SCC accession, template fit, additional safeguards, and TRA evidence" if {
	sensitive_route_needs_review
}

sensitive_counsel_field := "onward_transfers" if sensitive_route_needs_review

sensitive_counsel_field := null if not sensitive_route_needs_review

sensitive_rationale_required := true if sensitive_route_needs_review

sensitive_rationale_required := false if not sensitive_route_needs_review
