"""
Sanitization & Redaction Engine
Redacts passwords, tokens, API keys, and sensitive authorization headers before external transmission.
"""

import re
from typing import Dict, Any, Tuple


BEARER_REGEX = re.compile(r'(?:Authorization:\s*Bearer|Bearer\s+)([A-Za-z0-9\-._~+/]+=*)', re.IGNORECASE)
API_KEY_REGEX = re.compile(r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)(?:\s*[:=]\s*["\']?)([A-Za-z0-9\-_]{16,})["\']?', re.IGNORECASE)
PASSWORD_REGEX = re.compile(r'(?:password|passwd|pwd|secret)(?:\s*[:=]\s*["\']?)([^"\'\s&,]{3,})["\']?', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')


def sanitize_line(text: str) -> Tuple[str, Dict[str, int]]:
    """Sanitize a single log line, replacing secrets with redaction placeholders."""
    stats = {"tokens": 0, "api_keys": 0, "passwords": 0, "emails": 0}

    def replace_bearer(match):
        stats["tokens"] += 1
        return "Bearer [REDACTED_TOKEN]"

    def replace_api_key(match):
        stats["api_keys"] += 1
        return match.group(0).replace(match.group(1), "[REDACTED_API_KEY]")

    def replace_pwd(match):
        stats["passwords"] += 1
        return match.group(0).replace(match.group(1), "[REDACTED_PASSWORD]")

    def replace_email(match):
        stats["emails"] += 1
        email = match.group(0)
        parts = email.split('@')
        user, domain = parts[0], parts[1]
        masked = f"{user[0]}***{user[-1]}" if len(user) > 2 else "***"
        return f"{masked}@{domain}"

    cleaned = BEARER_REGEX.sub(replace_bearer, text)
    cleaned = API_KEY_REGEX.sub(replace_api_key, cleaned)
    cleaned = PASSWORD_REGEX.sub(replace_pwd, cleaned)
    cleaned = EMAIL_REGEX.sub(replace_email, cleaned)

    return cleaned, stats


def sanitize_batch_for_ai(lines: list[str]) -> Tuple[str, int]:
    """Sanitize a list of log lines for external AI inspection."""
    total_redacted = 0
    sanitized_lines = []
    for line in lines:
        cleaned, stats = sanitize_line(line)
        total_redacted += sum(stats.values())
        sanitized_lines.append(cleaned)
    return "\n".join(sanitized_lines), total_redacted


def sanitize_csv_field(val: Any) -> str:
    """Neutralize CSV formula injection by prepending apostrophe if field starts with dangerous characters."""
    if val is None:
        return '""'
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        s = f"'{s}"
    s = s.replace('"', '""')
    return f'"{s}"'
