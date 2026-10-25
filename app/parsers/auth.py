"""
Authentication & SSH Log Parser
"""

import re
from typing import Optional, Dict, Any
from app.ai.sanitization import sanitize_line

AUTH_BASE_PATTERN = re.compile(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s+(.*)$')
FAILED_PATTERN = re.compile(r'Failed (?:password|publickey) for (?:invalid user\s+)?(\w+)\s+from\s+([\d\.:a-fA-F]+)\s+port\s+(\d+)', re.IGNORECASE)
ACCEPTED_PATTERN = re.compile(r'Accepted (?:password|publickey) for (\w+)\s+from\s+([\d\.:a-fA-F]+)\s+port\s+(\d+)', re.IGNORECASE)


def parse_auth_line(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    match = AUTH_BASE_PATTERN.match(line)
    if not match:
        return None

    raw_date, hostname, service, raw_pid, message = match.groups()
    if not any(k in service for k in ("ssh", "sudo", "login", "pam", "auth")):
        return None

    sanitized_text, _ = sanitize_line(line)
    auth_status = "SUCCESS"
    user = None
    ip = None
    port = None

    fail_m = FAILED_PATTERN.search(message)
    if fail_m:
        auth_status = "FAILURE"
        user, ip, port_str = fail_m.groups()
        port = int(port_str)
    else:
        acc_m = ACCEPTED_PATTERN.search(message)
        if acc_m:
            auth_status = "SUCCESS"
            user, ip, port_str = acc_m.groups()
            port = int(port_str)
        elif "Disconnected" in message or "Connection closed" in message:
            auth_status = "DISCONNECT"
            ip_m = re.search(r'from ([\d\.:a-fA-F]+)', message)
            if ip_m:
                ip = ip_m.group(1)

    level = "WARN" if auth_status == "FAILURE" else "INFO"

    return {
        "id": f"auth-{line_number}",
        "line_number": line_number,
        "raw": line,
        "sanitized": sanitized_text,
        "timestamp": raw_date,
        "level": level,
        "source": "auth",
        "hostname": hostname,
        "service": service,
        "pid": int(raw_pid) if raw_pid else None,
        "message": message,
        "ip": ip,
        "auth": {
            "user": user,
            "status": auth_status,
            "port": port,
        }
    }
