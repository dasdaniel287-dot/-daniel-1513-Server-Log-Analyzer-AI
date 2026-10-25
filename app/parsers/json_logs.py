"""
Structured JSON Log Parser
Supports Bunyan, Pino, Winston, Docker container logs, and CloudWatch JSON.
"""

import json
from typing import Optional, Dict, Any
from app.ai.sanitization import sanitize_line


def parse_json_line(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None

    try:
        data = json.loads(stripped)
    except Exception:
        return None

    sanitized_text, _ = sanitize_line(line)
    timestamp = str(data.get("time") or data.get("timestamp") or data.get("@timestamp") or data.get("date") or "")
    raw_level = str(data.get("level") or data.get("severity") or data.get("status") or "INFO").upper()

    level = "INFO"
    if any(k in raw_level for k in ("CRIT", "FATAL")):
        level = "CRITICAL"
    elif any(k in raw_level for k in ("ERR", "EXCEPTION")):
        level = "ERROR"
    elif "WARN" in raw_level:
        level = "WARN"
    elif "DEBUG" in raw_level:
        level = "DEBUG"

    message = data.get("message") or data.get("msg") or data.get("log") or json.dumps(data)
    ip = data.get("ip") or data.get("client_ip") or data.get("remote_addr")

    http_dict = None
    if "status" in data or "status_code" in data or "method" in data:
        http_dict = {
            "method": data.get("method", "GET"),
            "path": data.get("path") or data.get("url", "/"),
            "status": int(data.get("status") or data.get("status_code", 200)),
            "user_agent": data.get("user_agent", ""),
        }

    return {
        "id": f"json-{line_number}",
        "line_number": line_number,
        "raw": line,
        "sanitized": sanitized_text,
        "timestamp": timestamp,
        "level": level,
        "source": "json",
        "hostname": data.get("host") or data.get("hostname"),
        "service": data.get("service") or data.get("app"),
        "message": str(message),
        "ip": ip,
        "http": http_dict,
        "exception_class": (data.get("error") or {}).get("name") if isinstance(data.get("error"), dict) else None,
    }
