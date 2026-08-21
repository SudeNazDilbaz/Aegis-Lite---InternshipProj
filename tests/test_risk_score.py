from aegis_lite.risk_score import calculate_risk_score


print("========== RISK SCORE TEST ==========\n")

test_cases = [
    {
        "name": "SQL Injection",
        "severity": "High",
        "status_code": 403,
        "ip_frequency": 1,
        "evidence_count": 1,
    },
    {
        "name": "Path Traversal",
        "severity": "Medium",
        "status_code": 403,
        "ip_frequency": 1,
        "evidence_count": 1,
    },
    {
        "name": "Brute Force",
        "severity": "Critical",
        "status_code": 401,
        "ip_frequency": 5,
        "evidence_count": 5,
    },
    {
        "name": "Reconnaissance",
        "severity": "Low",
        "status_code": None,
        "ip_frequency": 3,
        "evidence_count": 3,
    },
    {
        "name": "Unknown Event",
        "severity": "Unknown",
        "status_code": None,
        "ip_frequency": 1,
        "evidence_count": 1,
    },
]

for case in test_cases:
    score = calculate_risk_score(
        severity=case["severity"],
        status_code=case["status_code"],
        ip_frequency=case["ip_frequency"],
        evidence_count=case["evidence_count"],
    )

    print(
        f"Threat: {case['name']} | "
        f"Severity: {case['severity']} | "
        f"Risk Score: {score}/100"
    )