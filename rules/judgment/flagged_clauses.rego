# JUDGE-LIAB-001 — Liability cap commercial reasonableness
# JUDGE-INDEM-001 — Indemnification scope adequacy (detected; not decided)
# JUDGE-GOV-ACCESS-001 — Government-access warranty credibility
#
# These clauses are structurally detectable but their commercial and legal
# adequacy requires Saudi-licensed counsel. The verifier emits
# REQUIRES_HUMAN_REVIEW with a pointer to the field counsel must opine on.
# It does NOT attempt the legal judgment itself.
#
# Rego v1 syntax (OPA >= 1.0).

package sdaia.scc.judgment

import rego.v1

liability_result := {
	"id": "JUDGE-LIAB-001",
	"rule": "liability_cap_commercial_reasonableness",
	"layer": "judgment",
	"status": liability_status,
	"counsel_field": "liability.cap_amount_sar",
	"rationale_required": true,
	"detail": "Liability cap requires counsel opinion on commercial reasonableness. Machine check confirms structural presence only.",
}

liability_status := "REQUIRES_HUMAN_REVIEW" if input.scc.liability

liability_status := "FAIL" if not input.scc.liability

gov_access_result := {
	"id": "JUDGE-GOV-ACCESS-001",
	"rule": "government_access_warranty_credibility",
	"layer": "judgment",
	"status": "REQUIRES_HUMAN_REVIEW",
	"counsel_field": "obligations.importer[?text_ref==\"section_9\"]",
	"rationale_required": true,
	"detail": "Government-access warranty requires counsel opinion on destination-country law compatibility. Post-CLOUD-Act jurisdictions warrant particular scrutiny.",
}

indemnification_result := {
	"id": "JUDGE-INDEM-001",
	"rule": "indemnification_scope_adequacy",
	"layer": "judgment",
	"status": "REQUIRES_HUMAN_REVIEW",
	"counsel_field": "liability.rationale_ref",
	"rationale_required": true,
	"detail": "Indemnification scope requires counsel opinion. Check for asymmetry, carve-outs for gross negligence and wilful misconduct, and interaction with liability cap.",
}
