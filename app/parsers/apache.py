"""
Apache Access & Error Log Parser
"""

from typing import Optional, Dict, Any
from app.parsers.nginx import parse_nginx_access


def parse_apache_access(line: str, line_number: int) -> Optional[Dict[str, Any]]:
    # Apache Combined Log Format shares identical field geometry with Nginx Combined
    res = parse_nginx_access(line, line_number)
    if res:
        res["source"] = "apache_access"
        res["service"] = "apache"
    return res
