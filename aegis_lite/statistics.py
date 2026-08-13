from aegis_lite.threat_detector import detect_threat
from aegis_lite.brute_force import detect_brute_force

def count_status_codes(logs: list) -> dict:
    status_counts = {}

    for log in logs:
        status_code = log.get("status_code")

        status_counts[status_code] = (
            status_counts.get(status_code, 0) + 1
        )

    return status_counts

def count_threats(logs: list) -> dict:
    threat_counts = {}

    for log in logs:
        threat = detect_threat(log)

        if threat is not None:
            threat_counts[threat] = threat_counts.get(threat, 0) + 1

    return threat_counts

def count_ip_addresses(logs: list) -> dict:
    ip_counts = {}

    for log in logs:
        ip = log.get("ip")

        if ip is not None:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return ip_counts

def generate_security_summary(
    access_logs: list,
    attack_logs: list,
) -> dict:

    threat_counts = count_threats(attack_logs)

    brute_force_results = detect_brute_force(
        attack_logs,
        threshold=5,
        time_window_seconds=60,
        
    )

    threat_counts["Brute Force"] = len(brute_force_results)

    return {
        "total_access_logs": len(access_logs),
        "total_attack_logs": len(attack_logs),
        "total_threats": sum(threat_counts.values()),
        "access_status_codes": count_status_codes(access_logs),
        "attack_status_codes": count_status_codes(attack_logs),
        "threat_counts": threat_counts,
        "top_ip_addresses": count_ip_addresses(attack_logs),
    }