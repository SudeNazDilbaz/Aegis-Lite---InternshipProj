from aegis_lite.log_parser import read_log_file
from aegis_lite.statistics import count_status_codes, count_threats, count_ip_addresses, generate_security_summary


print("========== STATUS CODE STATISTICS ==========\n")

access_logs = read_log_file("sample_logs/access.log")
attack_logs = read_log_file("sample_logs/attack.log")

access_status_counts = count_status_codes(access_logs)
attack_status_counts = count_status_codes(attack_logs)

print("Access Log Status Codes:")
print(access_status_counts)

print("\nAttack Log Status Codes:")
print(attack_status_counts)

print("\n========== THREAT STATISTICS ==========\n")

summary = generate_security_summary(
    access_logs,
    attack_logs,
)

print("Detected Threats:")
print(summary["threat_counts"])

print("\n========== TOP IP STATISTICS ==========\n")

ip_counts = count_ip_addresses(attack_logs)

sorted_ips = sorted(
    ip_counts.items(),
    key=lambda item: item[1],
    reverse=True,
)

for ip, count in sorted_ips:
    print(f"{ip}: {count}")

summary = generate_security_summary(
    access_logs,
    attack_logs,
)

print("\n========== SECURITY SUMMARY ==========\n")
print(summary)    