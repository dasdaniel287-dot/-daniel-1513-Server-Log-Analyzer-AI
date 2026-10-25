"""
Unit Tests for Analysis & Correlation Engine
"""

from app.analysis.authentication import analyze_authentication_events
from app.analysis.errors import group_repeated_errors


def test_brute_force_detection():
    entries = [
        {
            "line_number": i,
            "ip": "198.51.100.42",
            "auth": {"user": "admin", "status": "FAILURE"},
            "timestamp": f"2026-10-25T14:00:0{i}Z"
        }
        for i in range(1, 6)
    ]
    stats, alerts = analyze_authentication_events(entries, brute_force_threshold=4)
    assert stats["failed_attempts"] == 5
    assert len(alerts) >= 1
    assert alerts[0]["category"] == "Authentication"
    assert "198.51.100.42" in alerts[0]["title"]


def test_error_grouping_normalizes_signatures():
    entries = [
        {"level": "ERROR", "message": "Failed connect to 10.0.0.1: Connection timeout", "service": "db"},
        {"level": "ERROR", "message": "Failed connect to 10.0.0.2: Connection timeout", "service": "db"},
        {"level": "ERROR", "message": "Failed connect to 10.0.0.3: Connection timeout", "service": "db"},
    ]
    groups = group_repeated_errors(entries)
    assert len(groups) == 1
    assert groups[0]["count"] == 3
    assert "<IP>" in groups[0]["signature"]
