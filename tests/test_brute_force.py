from aegis_lite.brute_force import detect_brute_force
from aegis_lite.log_parser import read_log_file


attack_logs = read_log_file("sample_logs/attack.log")
access_logs = read_log_file("sample_logs/access.log")


print("Attack log brute-force results:\n")

attack_results = detect_brute_force(
    attack_logs,
    threshold=5,
    time_window_seconds=60,
)

if attack_results:
    for result in attack_results:
        print(
            f"IP: {result['ip']} | "
            f"Attempts: {result['attempt_count']} | "
            f"Time Window: {result['time_window_seconds']} seconds | "
            f"Threat: {result['threat']}"
        )
else:
    print("No brute-force activity detected.")