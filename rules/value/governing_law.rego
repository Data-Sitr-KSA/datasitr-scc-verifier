# VAL-GOV-LAW — Governing law is the Kingdom of Saudi Arabia
# VAL-DISPUTE-FORUM — Dispute-resolution forum is KSA courts
#
# The SDAIA SCC template requires Saudi law as governing law and says disputes
# fall under the Kingdom's jurisdiction and courts. Arbitration alternatives
# are not hard-passed in this draft bundle unless a future counsel-reviewed
# rule note establishes the exact legal basis.
#
# Regulatory basis: SDAIA SCC template §11, Data Transfer Regulations 2024-09-01.
#
# Rego v1 syntax (OPA >= 1.0).

package sdaia.scc.value

import rego.v1

default governing_law_is_ksa := false

default dispute_forum_is_ksa := false

accepted_jurisdictions := {
	"Kingdom of Saudi Arabia",
	"المملكة العربية السعودية",
}

accepted_dispute_forums := {
	"Saudi courts",
	"Riyadh courts",
}

governing_law_is_ksa if {
	input.scc.governing_law.jurisdiction in accepted_jurisdictions
}

dispute_forum_is_ksa if {
	input.scc.governing_law.dispute_forum in accepted_dispute_forums
}

governing_law_result := {
	"id": "VAL-GOV-LAW",
	"rule": "governing_law_is_ksa",
	"layer": "value",
	"status": governing_law_status,
	"observed_value": input.scc.governing_law.jurisdiction,
}

governing_law_status := "PASS" if governing_law_is_ksa

governing_law_status := "FAIL" if not governing_law_is_ksa

dispute_forum_result := {
	"id": "VAL-DISPUTE-FORUM",
	"rule": "dispute_forum_is_ksa",
	"layer": "value",
	"status": dispute_forum_status,
	"observed_value": input.scc.governing_law.dispute_forum,
}

dispute_forum_status := "PASS" if dispute_forum_is_ksa

dispute_forum_status := "FAIL" if not dispute_forum_is_ksa
