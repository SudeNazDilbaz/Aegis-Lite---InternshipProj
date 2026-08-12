from aegis_lite.log_parser import read_log_file
from aegis_lite.threat_detector import detect_threat
from aegis_lite.alert_manager import create_threat_alert
from aegis_lite.brute_force import detect_brute_force
from aegis_lite.alert_manager import create_brute_force_alert

print("========== AUTOMATED THREAT ALERT TEST ==========\n")

attack_logs = read_log_file("sample_logs/attack.log")

detected_count = 0
sent_count = 0

for log_entry in attack_logs:
    threat = detect_threat(log_entry)

    if threat is not None:
        detected_count += 1

        print(
            f"Detected: {threat} | "
            f"IP: {log_entry.get('ip')}"
        )

        result = create_threat_alert(log_entry, threat)

        if result:
            sent_count += 1
            print("Alert Status: SENT\n")
        else:
            print("Alert Status: FAILED\n")


print("========== SUMMARY ==========\n")

print(f"Threats Detected : {detected_count}")
print(f"Alerts Sent      : {sent_count}")

print("\n========== BRUTE FORCE ALERT TEST ==========\n")

brute_force_results = detect_brute_force(attack_logs)

for result in brute_force_results:
    alert_sent = create_brute_force_alert(result)

    if alert_sent:
        print(
            f"PASS - Brute Force alert sent | "
            f"IP: {result.get('ip')}"
        )
    else:
        print("FAIL - Brute Force alert could not be sent.")

print("\n========== NORMAL TRAFFIC ALERT TEST ==========\n")

access_logs = read_log_file("sample_logs/access.log")

normal_alert_count = 0

for log_entry in access_logs:
    threat = detect_threat(log_entry)

    if threat is not None:
        create_threat_alert(log_entry, threat)
        normal_alert_count += 1

normal_brute_force = detect_brute_force(
    access_logs,
    threshold=5,
    time_window_seconds=60,
)

if normal_brute_force:
    normal_alert_count += len(normal_brute_force)

if normal_alert_count == 0:
    print("PASS - Normal traffic produced no alerts.")
else:
    print(
        f"FAIL - Normal traffic produced "
        f"{normal_alert_count} unexpected alerts."
    )        