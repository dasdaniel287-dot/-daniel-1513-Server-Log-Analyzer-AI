"""
JSON Report Generation Module
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any


def generate_json_report(analysis_data: Dict[str, Any]) -> str:
    payload = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "application": "Server Log Analyzer AI",
            "report_format_version": "2026.1",
        },
        "summary": analysis_data.get("summary", {}),
        "alerts": analysis_data.get("alerts", []),
        "incidents": analysis_data.get("incidents", []),
        "anomalies": analysis_data.get("anomalies", []),
        "error_groups": analysis_data.get("error_groups", []),
        "auth_statistics": analysis_data.get("auth_stats", {}),
        "http_statistics": analysis_data.get("http_stats", {}),
    }
    return json.dumps(payload, indent=2)
