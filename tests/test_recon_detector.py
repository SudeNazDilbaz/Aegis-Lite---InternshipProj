from aegis_lite.log_parser import read_log_file
from aegis_lite.recon_detector import detect_reconnaissance


print("========== RECONNAISSANCE DETECTION TEST ==========\n")

attack_logs = read_log_file("sample_logs/attack.log")

recon_results = detect_reconnaissance(
    attack_logs,
    threshold=2
)

for result in recon_results:
    print(
        f"IP: {result['ip']} | "
        f"Unique Paths: {result['unique_paths']} | "
        f"Paths: {', '.join(result['paths'])} | "
        f"Threat: {result['threat']}"
    )

print(f"\nTotal Reconnaissance Events: {len(recon_results)}")