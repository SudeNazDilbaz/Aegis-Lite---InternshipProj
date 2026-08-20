import re
from pathlib import Path


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) '
    r'(?P<path>\S+) '
    r'(?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<response_size>\d+|-) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_log_line(line: str) -> dict | None:
    """
    Parse a single Apache/Nginx combined log line.

    Returns a dictionary when the line matches the expected format.
    Returns None when the line is invalid.
    """
    match = LOG_PATTERN.fullmatch(line.strip())

    if not match:
        return None

    log_data = match.groupdict()

    log_data["status_code"] = int(log_data["status_code"])

    if log_data["response_size"] != "-":
        log_data["response_size"] = int(log_data["response_size"])
    else:
        log_data["response_size"] = 0

    return log_data

def read_log_file(file_path: str) -> list[dict]:
    """
    Read a log file line by line and parse valid entries.

    Invalid or empty lines are skipped.
    """
    parsed_logs = []
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            parsed_line = parse_log_line(line)

            if parsed_line is not None:
                parsed_line["line_number"] = line_number
                parsed_logs.append(parsed_line)

    return parsed_logs