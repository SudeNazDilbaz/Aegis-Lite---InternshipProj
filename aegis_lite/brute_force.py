from datetime import datetime, timedelta


TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def detect_brute_force(
    logs: list[dict],
    threshold: int = 5,
    time_window_seconds: int = 60,
) -> list[dict]:
    """
    Detect repeated failed login attempts from the same IP address
    within a specified time window.
    """
    attempts = {}

    for log_entry in logs:
        is_failed_login = (
            log_entry.get("method") == "POST"
            and log_entry.get("path") == "/login"
            and log_entry.get("status_code") == 401
        )

        if not is_failed_login:
            continue

        ip = log_entry.get("ip")
        timestamp = datetime.strptime(
            log_entry.get("timestamp"),
            TIME_FORMAT,
        )

        if ip not in attempts:
            attempts[ip] = []

        attempts[ip].append(timestamp)

    detected_ips = []

    for ip, timestamps in attempts.items():
        timestamps.sort()

        for start_index in range(len(timestamps)):
            window_start = timestamps[start_index]
            window_end = window_start + timedelta(
                seconds=time_window_seconds
            )

            attempts_in_window = 0

            for timestamp in timestamps[start_index:]:
                if timestamp <= window_end:
                    attempts_in_window += 1
                else:
                    break

            if attempts_in_window >= threshold:
                detected_ips.append(
                    {
                        "ip": ip,
                        "attempt_count": attempts_in_window,
                        "time_window_seconds": time_window_seconds,
                        "threat": "Brute Force",
                    }
                )
                break

    return detected_ips