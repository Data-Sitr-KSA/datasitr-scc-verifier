# VAL-BREACH-EXPORTER — Exporter breach notification window
# VAL-BREACH-SDAIA — SDAIA breach notification window
#
# SDAIA requires personal-data breaches to be notified to the authority
# within 72 hours of awareness. The contractual exporter-notification
# window is typically narrower (often 24 hours) to give the exporter
# time to coordinate the regulatory notification.
#
# Regulatory basis: PDPL breach-notification provisions, SDAIA guidance.

package sdaia.scc.value

default exporter_window_ok = false
default sdaia_window_ok = false

max_exporter_window_hours := 24
max_sdaia_window_hours := 72

exporter_window_ok {
    input.scc.breach_notification.exporter_notification_window_hours <= max_exporter_window_hours
    input.scc.breach_notification.exporter_notification_window_hours > 0
}

sdaia_window_ok {
    input.scc.breach_notification.sdaia_notification_window_hours <= max_sdaia_window_hours
    input.scc.breach_notification.sdaia_notification_window_hours > 0
}

exporter_window_result := {
    "id": "VAL-BREACH-EXPORTER",
    "rule": "exporter_breach_window_within_bound",
    "layer": "value",
    "status": exporter_status,
    "observed_value": input.scc.breach_notification.exporter_notification_window_hours,
    "detail": sprintf("Observed %d h; maximum %d h", [
        input.scc.breach_notification.exporter_notification_window_hours,
        max_exporter_window_hours,
    ]),
}

exporter_status = "PASS" { exporter_window_ok }
exporter_status = "FAIL" { not exporter_window_ok }

sdaia_window_result := {
    "id": "VAL-BREACH-SDAIA",
    "rule": "sdaia_breach_window_within_bound",
    "layer": "value",
    "status": sdaia_status,
    "observed_value": input.scc.breach_notification.sdaia_notification_window_hours,
    "detail": sprintf("Observed %d h; maximum %d h", [
        input.scc.breach_notification.sdaia_notification_window_hours,
        max_sdaia_window_hours,
    ]),
}

sdaia_status = "PASS" { sdaia_window_ok }
sdaia_status = "FAIL" { not sdaia_window_ok }
