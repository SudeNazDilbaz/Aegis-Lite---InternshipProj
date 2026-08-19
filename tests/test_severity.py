from aegis_lite.severity import get_threat_severity


print("========== THREAT SEVERITY TEST ==========\n")

threat_types = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Path Traversal",
    "Brute Force",
    "Unknown Attack",
]

for threat in threat_types:
    severity = get_threat_severity(threat)

    print(
        f"Threat: {threat} | "
        f"Severity: {severity}"
    )