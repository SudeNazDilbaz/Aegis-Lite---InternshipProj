from aegis_lite.threat_detector import detect_threat
from aegis_lite.brute_force import detect_brute_force
from aegis_lite.severity import get_threat_severity
from aegis_lite.recon_detector import detect_reconnaissance
from aegis_lite.risk_score import calculate_risk_score

def get_detected_threats(logs: list) -> list:
    detected_threats = []

    for log in logs:
        threat = detect_threat(log)

        if threat is not None:
            ip_frequency = sum(
            1 for item in logs
            if item.get("ip") == log.get("ip")
            )

            detected_threats.append({
                "Threat Type": threat,
                "IP Address": log.get("ip"),
                "Method": log.get("method"),
                "Request": log.get("path"),
                "Status Code": log.get("status_code"),
                "Line Number": log.get("line_number"),
                "Severity": get_threat_severity(threat),
                "Risk Score": calculate_risk_score(
                    severity=get_threat_severity(threat),
                    status_code=log.get("status_code"),
                    ip_frequency=ip_frequency,
                    evidence_count=1
                )
            })

    brute_force_results = detect_brute_force(
        logs,
        time_window_seconds=60,
        threshold=5,
    )
    for result in brute_force_results:
        detected_threats.append({
            "Threat Type": "Brute Force",
            "Severity": get_threat_severity("Brute Force"),
            "IP Address": result.get("ip"),
            "Method": "POST",
            "Request": "/login",
            "Status Code": 401,
            "Line Number": "-",
            "Risk Score": calculate_risk_score(
                severity=get_threat_severity("Brute Force"),
                status_code=401,
                ip_frequency=result.get("attempt_count", 1),
                evidence_count=result.get("attempt_count", 1)
            )
        })
    
    recon_results = detect_reconnaissance(
    logs,
    threshold=2,
    )
    for result in recon_results:
        detected_threats.append({
            "Threat Type": "Reconnaissance",
            "Severity": get_threat_severity("Reconnaissance"),
            "IP Address": result.get("ip"),
            "Method": "-",
            "Request": ", ".join(result.get("paths", [])),
            "Status Code": "-",
            "Line Number": None,
            "Risk Score": calculate_risk_score(
                severity=get_threat_severity("Reconnaissance"),
                status_code=None,
                ip_frequency=result.get("unique_paths", 1),
                evidence_count=result.get("unique_paths", 1)
            )    
        })
    return detected_threats 