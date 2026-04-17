# VAL-SENSITIVE-ROUTE — Article 18 sensitive data cannot route to onward transfers
#
# If any Article 18 sensitive category is declared in scope (health,
# biometric, genetic, criminal, financial, religious, ethnic, political,
# union membership), onward transfers MUST be disallowed.
#
# This is a hard rule. It protects against the common error of declaring
# sensitive data in the subject matter but leaving onward-transfer
# permission open.
#
# Regulatory basis: PDPL Article 18; Data Transfer Regulations.

package sdaia.scc.value

default sensitive_routing_ok = true

sensitive_categories_present {
    cat := input.scc.subject_matter.sensitive_categories_art18[_]
    cat != "none"
}

sensitive_routing_ok = false {
    sensitive_categories_present
    input.scc.onward_transfers.permitted == true
}

sensitive_route_result := {
    "id": "VAL-SENSITIVE-ROUTE",
    "rule": "sensitive_data_forbids_onward_transfer",
    "layer": "value",
    "status": sensitive_status,
    "detail": sensitive_detail,
}

sensitive_status = "PASS" { sensitive_routing_ok }
sensitive_status = "FAIL" { not sensitive_routing_ok }

sensitive_detail = "No Article 18 sensitive categories declared OR onward transfers correctly disallowed" {
    sensitive_routing_ok
}

sensitive_detail = "Article 18 sensitive category declared AND onward transfers permitted — regulatory violation" {
    not sensitive_routing_ok
}
