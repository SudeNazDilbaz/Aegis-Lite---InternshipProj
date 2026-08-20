from aegis_lite.geo_ip import get_ip_location
from aegis_lite.telegram_alert import send_telegram_alert

def create_threat_alert(log_entry: dict, threat: str) -> bool:
    ip = log_entry.get("ip")
    path = log_entry.get("path")
    status_code = log_entry.get("status_code")

    location = get_ip_location(ip)

    country = location.get("country")
    city = location.get("city")

    message = (
        "🚨 Aegis-Lite Security Alert\n\n"
        f"Threat: {threat}\n"
        f"IP Address: {ip}\n"
        f"Location: {country}, {city}\n"
        f"Request: {path}\n"
        f"Status Code: {status_code}"
    )

    return send_telegram_alert(message)

def create_brute_force_alert(brute_force_result: dict) -> bool:
    ip = brute_force_result.get("ip")
    attempts = brute_force_result.get("attempts")
    window = brute_force_result.get("time_window_seconds")

    location = get_ip_location(ip)

    country = location.get("country")
    city = location.get("city")

    message = (
        "🚨 Aegis-Lite Security Alert\n\n"
        "Threat: Brute Force\n"
        f"IP Address: {ip}\n"
        f"Location: {country}, {city}\n"
        f"Failed Attempts: {attempts}\n"
        f"Time Window: {window} seconds"
    )

    return send_telegram_alert(message)

def create_recon_alert(recon_result: dict) -> bool:
    ip = recon_result.get("ip")
    paths = recon_result.get("paths", [])
    unique_paths = recon_result.get("unique_paths")

    location = get_ip_location(ip)

    country = location.get("country")
    city = location.get("city")

    path_text = ", ".join(paths)

    message = (
        "🚨 Aegis-Lite Security Alert\n\n"
        "Threat: Reconnaissance\n"
        f"IP Address: {ip}\n"
        f"Location: {country}, {city}\n"
        f"Unique Sensitive Paths: {unique_paths}\n"
        f"Paths: {path_text}"
    )

    return send_telegram_alert(message)