from aegis_lite.log_parser import parse_log_line, read_log_file


sample_line = (
    '192.0.2.10 - - '
    '[03/Aug/2026:09:00:12 +0300] '
    '"GET / HTTP/1.1" '
    '200 1245 '
    '"-" '
    '"Mozilla/5.0"'
)

single_result = parse_log_line(sample_line)

print("Single line result:")
print(single_result)

print("\nAccess log results:")

access_logs = read_log_file("sample_logs/access.log")

for log in access_logs:
    print(log)


print(f"\nTotal parsed access logs: {len(access_logs)}")


print("\nAttack log results:")

attack_logs = read_log_file("sample_logs/attack.log")

for log in attack_logs:
    print(log)

print(f"\nTotal parsed attack logs: {len(attack_logs)}")