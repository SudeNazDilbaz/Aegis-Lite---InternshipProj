THREAT_SEVERITY = {
    "SQL Injection": "High",
    "Cross-Site Scripting (XSS)": "High",
    "Path Traversal": "Medium",
    "Brute Force": "Critical",
    "Reconnaissance": "Low",
}


def get_threat_severity(threat_type: str) -> str:
    return THREAT_SEVERITY.get(threat_type, "Low")