from aegis_lite.log_parser import read_log_file
from aegis_lite.threat_analysis import get_detected_threats


print("========== THREAT ANALYSIS TEST ==========\n")

attack_logs = read_log_file("sample_logs/attack.log")

detected_threats = get_detected_threats(attack_logs)

for threat in detected_threats:
    print(
        f"Threat: {threat['Threat Type']} | "
        f"IP: {threat['IP Address']} | "
        f"Request: {threat['Request']} | "
        f"Status: {threat['Status Code']}"
    )

print(f"\nTotal Detected Threats: {len(detected_threats)}")