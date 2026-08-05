from aegis_lite.log_parser import read_log_file
from aegis_lite.threat_detector import detect_threat


attack_logs = read_log_file("sample_logs/attack.log")
access_logs = read_log_file("sample_logs/access.log")


print("Attack log detection results:\n")

for log_entry in attack_logs:
    threat = detect_threat(log_entry)

    print(
        f"Line: {log_entry['line_number']} | "
        f"IP: {log_entry['ip']} | "
        f"Path: {log_entry['path']} | "
        f"Threat: {threat}"
    )


print("\nNormal access log detection results:\n")

for log_entry in access_logs:
    threat = detect_threat(log_entry)

    print(
        f"Line: {log_entry['line_number']} | "
        f"Path: {log_entry['path']} | "
        f"Threat: {threat}"
    )