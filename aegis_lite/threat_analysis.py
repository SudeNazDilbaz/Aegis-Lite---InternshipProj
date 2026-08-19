from aegis_lite.threat_detector import detect_threat
from aegis_lite.brute_force import detect_brute_force
from aegis_lite.severity import get_threat_severity

def get_detected_threats(logs: list) -> list:
    detected_threats = []

    for log in logs:
        threat = detect_threat(log)

        if threat is not None:
            detected_threats.append({
                "Threat Type": threat,
                "IP Address": log.get("ip"),
                "Method": log.get("method"),
                "Request": log.get("path"),
                "Status Code": log.get("status_code"),
                "Line Number": log.get("line_number"),
                "Severity": get_threat_severity(threat),
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
            "Line Number": "-"
        })
    return detected_threats