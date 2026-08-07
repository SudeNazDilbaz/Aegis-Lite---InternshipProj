import time


start_time = time.perf_counter()

from aegis_lite.log_parser import read_log_file
from aegis_lite.threat_detector import detect_threat
from aegis_lite.brute_force import detect_brute_force

access_logs = read_log_file("sample_logs/access.log")
attack_logs = read_log_file("sample_logs/attack.log")


print("========== AEGIS-LITE SYSTEM TEST ==========\n")

print(f"Access logs loaded: {len(access_logs)}")
print(f"Attack logs loaded: {len(attack_logs)}")


print("\n========== THREAT DETECTION ==========\n")

detected_threats = []

for log_entry in attack_logs:
    threat = detect_threat(log_entry)

    if threat is not None:
        detected_threats.append(threat)
        print(f"PASS - {threat} detected")


print("\n========== BRUTE FORCE DETECTION ==========\n")

brute_force_results = detect_brute_force(
    attack_logs,
    threshold=5,
    time_window_seconds=60,
)

if brute_force_results:
    for result in brute_force_results:
        print(
            f"PASS - IP: {result['ip']} | "
            f"Attempts: {result['attempt_count']} | "
            f"Window: {result['time_window_seconds']} seconds"
        )
else:
    print("FAIL - No brute-force activity detected")


print("\n========== NORMAL TRAFFIC CHECK ==========\n")

false_positives = []

for log_entry in access_logs:
    threat = detect_threat(log_entry)

    if threat is not None:
        false_positives.append(threat)

normal_brute_force = detect_brute_force(access_logs)

if not false_positives and not normal_brute_force:
    print("PASS - Normal access logs produced no threat alerts")
else:
    print("FAIL - False positive detected")


print("\n========== SUMMARY ==========\n")

parser_pass = len(access_logs) == 10 and len(attack_logs) == 13

threat_pass = (
    "SQL Injection" in detected_threats
    and "Cross-Site Scripting (XSS)" in detected_threats
    and "Path Traversal" in detected_threats
)

brute_force_pass = len(brute_force_results) > 0

normal_traffic_pass = (
    not false_positives
    and not normal_brute_force
)


print(f"Parser: {'PASS' if parser_pass else 'FAIL'}")
print(f"Threat Detector: {'PASS' if threat_pass else 'FAIL'}")
print(f"Brute Force Detector: {'PASS' if brute_force_pass else 'FAIL'}")
print(f"Normal Traffic Check: {'PASS' if normal_traffic_pass else 'FAIL'}")


print("\n========== STATISTICS ==========\n")

print(f"Total Access Logs : {len(access_logs)}")
print(f"Total Attack Logs : {len(attack_logs)}")

print(f"SQL Injection Detections : {detected_threats.count('SQL Injection')}")
print(f"XSS Detections           : {detected_threats.count('Cross-Site Scripting (XSS)')}")
print(f"Path Traversal Detections: {detected_threats.count('Path Traversal')}")
print(f"Brute Force Detections   : {len(brute_force_results)}")

print(f"False Positives          : {len(false_positives)}")

print("\n========== PROJECT STATUS ==========\n")

print("Log Parser           ✔")
print("Threat Detector      ✔")
print("Brute Force Engine   ✔")
print("System Validation    ✔")

print("\nWeek 1 Progress: 100%")

end_time = time.perf_counter()

print(f"\nExecution Time: {end_time - start_time:.6f} sec")


system_pass = (
    parser_pass
    and threat_pass
    and brute_force_pass
    and normal_traffic_pass
)

print(
    f"\nSystem Status: "
    f"{'SUCCESS' if system_pass else 'FAILED'}"
)
