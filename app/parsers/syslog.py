"""
Syslog & Standard Linux Log Parsers (RFC 3164 / RFC 5424)
"""

import re
from typing import Optional, Dict, Any
from app.ai.sanitization import sanitize_line

RFC3164_PATTERN = re.compile(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:?\s+(.*)$')
RFC5424_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:?\s+(.*)$')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_syslog_line(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    match = RFC3164_PATTERN.match(line)
    if not match:
        match = RFC5424_PATTERN.match(line)
        if not match:
            return None

    timestamp_str, hostname, service, pid, message = match.groups()
    sanitized_text, _ = sanitize_line(line)
    
    # Extract IP if present
    ip_match = IP_PATTERN.search(message)
    ip = ip_match.group(0) if ip_match else None

    # Detect level
    msg_upper = message.upper()
    level = "INFO"
    if any(k in msg_upper for k in ["CRITICAL", "PANIC", "EMERGENCY", "OOM-KILLER"]):
        level = "CRITICAL"
    elif any(k in msg_upper for k in ["ERROR", "ERR", "FAIL", "FAILED"]):
        level = "ERROR"
    elif any(k in msg_upper for k in ["WARN", "WARNING"]):
        level = "WARN"

    return {
        "id": f"sys-{line_number}",
        "line_number": line_number,
        "raw": line,
        "sanitized": sanitized_text,
        "timestamp": timestamp_str,
        "level": level,
        "source": "syslog",
        "hostname": hostname,
        "service": service,
        "pid": int(pid) if pid else None,
        "message": message,
        "ip": ip,
    }
