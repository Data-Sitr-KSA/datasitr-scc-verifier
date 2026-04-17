# VAL-GOV-LAW — Governing law is the Kingdom of Saudi Arabia
# VAL-DISPUTE-FORUM — Dispute-resolution forum is a KSA venue
#
# The SDAIA SCC template requires Saudi law as governing law and a KSA venue
# for dispute resolution. A SCC citing foreign governing law (e.g., English
# law, EU law) does not satisfy the Data Transfer Regulations' Article 29
# requirements, regardless of other safeguards.
#
# Regulatory basis: SDAIA SCC template §11, Data Transfer Regulations 2024-09-01.

package sdaia.scc.value

default governing_law_is_ksa = false
default dispute_forum_is_ksa = false

accepted_jurisdictions := {
    "Kingdom of Saudi Arabia",
    "المملكة العربية السعودية",
}

accepted_dispute_forums := {
    "Saudi courts",
    "SDAIA-recognised arbitration body",
    "SDAIA-recognized arbitration body",
    "Riyadh courts",
    "Saudi Center for Commercial Arbitration",
}

governing_law_is_ksa {
    input.scc.governing_law.jurisdiction == accepted_jurisdictions[_]
}

dispute_forum_is_ksa {
    input.scc.governing_law.dispute_forum == accepted_dispute_forums[_]
}

governing_law_result := {
    "id": "VAL-GOV-LAW",
    "rule": "governing_law_is_ksa",
    "layer": "value",
    "status": governing_law_status,
    "observed_value": input.scc.governing_law.jurisdiction,
}

governing_law_status = "PASS" { governing_law_is_ksa }
governing_law_status = "FAIL" { not governing_law_is_ksa }

dispute_forum_result := {
    "id": "VAL-DISPUTE-FORUM",
    "rule": "dispute_forum_is_ksa",
    "layer": "value",
    "status": dispute_forum_status,
    "observed_value": input.scc.governing_law.dispute_forum,
}

dispute_forum_status = "PASS" { dispute_forum_is_ksa }
dispute_forum_status = "FAIL" { not dispute_forum_is_ksa }
