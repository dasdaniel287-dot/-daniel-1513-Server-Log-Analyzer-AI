"""
Error Detection & Grouping Engine
"""

import re
from typing import List, Dict, Any


def group_repeated_errors(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}

    for entry in entries:
        level = entry.get("level")
        if level in ("ERROR", "CRITICAL"):
            msg = entry.get("message", "")
            # Normalize signature: mask IPs, numbers, UUIDs
            normalized = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', msg)
            normalized = re.sub(r'\b\d+\b', '<N>', normalized)
            normalized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<UUID>', normalized, flags=re.I)
            sig = f"{entry.get('service') or entry.get('source')}:{normalized[:120]}"

            if sig not in groups:
                groups[sig] = {
                    "id": f"err-grp-{len(groups) + 1}",
                    "signature": sig,
                    "service": entry.get("service") or entry.get("source") or "application",
                    "count": 1,
                    "first_seen": entry.get("timestamp", ""),
                    "last_seen": entry.get("timestamp", ""),
                    "sample_message": msg,
                    "level": level,
                }
            else:
                groups[sig]["count"] += 1
                groups[sig]["last_seen"] = entry.get("timestamp", "")

    return sorted(groups.values(), key=lambda g: g["count"], reverse=True)
