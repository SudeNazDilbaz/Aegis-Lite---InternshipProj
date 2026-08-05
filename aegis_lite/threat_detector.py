import re


SQL_INJECTION_PATTERN = re.compile(
    r"<SQLI_TEST>",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"<XSS_TEST>",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"<PATH_TRAVERSAL_TEST>",
    re.IGNORECASE,
)


def detect_sql_injection(path: str) -> bool:
    """Return True when the path contains an SQL injection test pattern."""
    return SQL_INJECTION_PATTERN.search(path) is not None


def detect_xss(path: str) -> bool:
    """Return True when the path contains an XSS test pattern."""
    return XSS_PATTERN.search(path) is not None


def detect_path_traversal(path: str) -> bool:
    """Return True when the path contains a path traversal test pattern."""
    return PATH_TRAVERSAL_PATTERN.search(path) is not None


def detect_threat(log_entry: dict) -> str | None:
    """
    Analyze a parsed log entry and return the detected threat type.

    Returns None when no supported threat pattern is detected.
    """
    path = log_entry.get("path", "")

    if detect_sql_injection(path):
        return "SQL Injection"

    if detect_xss(path):
        return "Cross-Site Scripting (XSS)"

    if detect_path_traversal(path):
        return "Path Traversal"

    return None