SENSITIVE_PATHS = {
    "/admin",
    "/administrator",
    "/admin/login",
    "/config",
    "/.env",
    "/settings",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/mysql",
    "/backup.zip",
    "/backup.tar.gz",
}


def detect_reconnaissance(logs: list, threshold: int = 2) -> list:
    ip_activity = {}

    for log in logs:
        ip = log.get("ip")
        path = log.get("path")

        if path in SENSITIVE_PATHS:
            if ip not in ip_activity:
                ip_activity[ip] = set()

            ip_activity[ip].add(path)

    detected = []

    for ip, paths in ip_activity.items():
        if len(paths) >= threshold:
            detected.append({
                "ip": ip,
                "unique_paths": len(paths),
                "paths": sorted(paths),
                "threat": "Reconnaissance",
            })

    return detected