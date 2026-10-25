"""
Nginx Combined Access & Error Log Parser
"""

import re
from typing import Optional, Dict, Any
from app.ai.sanitization import sanitize_line

NGINX_ACCESS_REGEX = re.compile(
    r'^([\d\.:a-fA-F]+)\s+[\w\-]+\s+([\w\-]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)
NGINX_ERROR_REGEX = re.compile(
    r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[([a-z]+)\]\s+(\d+)#\d+:\s+(.*)$'
)


def parse_nginx_access(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    m = NGINX_ACCESS_REGEX.match(line)
    if not m:
        return None

    ip, auth_user, raw_date, method, path, protocol, status_str, bytes_str, referer, user_agent = m.groups()
    status = int(status_str)
    bytes_val = int(bytes_str) if bytes_str and bytes_str != "-" else 0
    sanitized_text, _ = sanitize_line(line)

    level = "INFO"
    if status >= 500:
        level = "CRITICAL"
    elif status >= 400:
        level = "WARN"

    return {
        "id": f"nginx-{line_number}",
        "line_number": line_number,
        "raw": line,
        "sanitized": sanitized_text,
        "timestamp": raw_date,
        "level": level,
        "source": "nginx_access",
        "service": "nginx",
        "message": f"{method} {path} -> {status} ({bytes_val}B)",
        "ip": ip,
        "http": {
            "method": method,
            "path": path,
            "status": status,
            "bytes": bytes_val,
            "user_agent": user_agent or "",
            "referer": referer if referer != "-" else "",
        },
        "auth": {"user": auth_user, "status": "SUCCESS"} if auth_user and auth_user != "-" else None,
    }


def parse_nginx_error(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    m = NGINX_ERROR_REGEX.match(line)
    if not m:
        return None

    raw_date, raw_level, pid, message = m.groups()
    sanitized_text, _ = sanitize_line(line)

    client_ip_m = re.search(r'client:\s+([\d\.:a-fA-F]+)', message)
    ip = client_ip_m.group(1) if client_ip_m else None

    req_m = re.search(r'request:\s+"([A-Z]+)\s+([^\s]+)', message)
    http_dict = None
    if req_m:
        http_dict = {"method": req_m.group(1), "path": req_m.group(2), "status": 500}

    level = "ERROR"
    if raw_level in ("crit", "alert", "emerg"):
        level = "CRITICAL"
    elif raw_level == "warn":
        level = "WARN"

    return {
        "id": f"nginx-err-{line_number}",
        "line_number": line_number,
        "raw": line,
        "sanitized": sanitized_text,
        "timestamp": raw_date,
        "level": level,
        "source": "nginx_error",
        "service": "nginx",
        "pid": int(pid),
        "message": message,
        "ip": ip,
        "http": http_dict,
    }
