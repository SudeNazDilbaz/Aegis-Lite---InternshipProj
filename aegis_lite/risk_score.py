SEVERITY_SCORES = {
    "Low": 20,
    "Medium": 40,
    "High": 60,
    "Critical": 80,
}

def calculate_risk_score(
    severity: str,
    status_code=None,
    ip_frequency: int = 1,
    evidence_count: int = 1,
) -> int:

    score = SEVERITY_SCORES.get(severity, 0)

    # HTTP response contribution
    if status_code in [401, 403]:
        score += 10

    # Repeated activity from the same IP
    if ip_frequency >= 5:
        score += 10
    elif ip_frequency >= 3:
        score += 5

    # Multiple pieces of behavioral evidence
    if evidence_count >= 3:
        score += 10
    elif evidence_count >= 2:
        score += 5

    return min(score, 100)