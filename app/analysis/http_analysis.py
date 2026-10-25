"""
HTTP Access & Error Log Analysis Module
"""

from typing import List, Dict, Any, Tuple

SCANNER_PATHS = [
    "/.env", "/.git", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/actuator", "/cgi-bin", "/etc/passwd", "/swagger-ui", "/shell",
]

SCANNER_AGENTS = ["sqlmap", "nikto", "masscan", "dirbuster", "gobuster", "nmap"]


def analyze_http_traffic(
    entries: List[Dict[str, Any]],
    probe_threshold: int = 3,
    error_5xx_threshold: int = 5
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    total_requests = 0
    status_dist: Dict[str, int] = {}
    path_4xx: Dict[str, Dict[str, Any]] = {}
    errors_5xx: Dict[str, int] = {}
    scanners_detected: Dict[str, Dict[str, Any]] = {}
    alerts: List[Dict[str, Any]] = []

    for entry in entries:
        http = entry.get("http")
        if not http:
            continue

        total_requests += 1
        status = http.get("status", 200)
        code_str = str(status)
        status_dist[code_str] = status_dist.get(code_str, 0) + 1

        path = http.get("path", "")
        ip = entry.get("ip") or "unknown"
        ua = http.get("user_agent", "")

        # 4xx tracking
        if 400 <= status < 500:
            if path not in path_4xx:
                path_4xx[path] = {"count": 0, "ips": set()}
            path_4xx[path]["count"] += 1
            path_4xx[path]["ips"].add(ip)

        # 5xx tracking
        if status >= 500:
            key = f"{http.get('method', 'GET')} {path}"
            errors_5xx[key] = errors_5xx.get(key, 0) + 1

        # Scanner User-Agent check
        ua_lower = ua.lower()
        for scanner in SCANNER_AGENTS:
            if scanner in ua_lower:
                if ua not in scanners_detected:
                    scanners_detected[ua] = {"count": 0, "ips": set()}
                scanners_detected[ua]["count"] += 1
                scanners_detected[ua]["ips"].add(ip)
                break

    # Alerts for probes
    probe_hits = {p: d for p, d in path_4xx.items() if any(sp in p.lower() for sp in SCANNER_PATHS)}
    if sum(d["count"] for d in probe_hits.values()) >= probe_threshold:
        alerts.append({
            "id": "ALT-WEB-001",
            "timestamp": entries[0].get("timestamp", "") if entries else "",
            "severity": "Medium",
            "category": "HTTP Traffic",
            "title": f"Web Reconnaissance Probes Detected ({len(probe_hits)} sensitive paths)",
            "source_log": "nginx / apache access",
            "line_references": [],
            "evidence": [f"Probed paths: {', '.join(list(probe_hits.keys())[:5])}"],
            "rule_explanation": "Automated tools systematically probe for exposed config files and admin portals.",
            "confidence": "High",
            "recommended_steps": [
                "Verify web server returns 404/403 and blocks access to sensitive files.",
                "Review WAF rate limiting rules.",
            ],
            "status": "New",
            "occurrences": sum(d["count"] for d in probe_hits.values()),
        })

    # Alerts for 5xx surges
    total_5xx = sum(errors_5xx.values())
    if total_5xx >= error_5xx_threshold:
        alerts.append({
            "id": "ALT-REL-001",
            "timestamp": entries[0].get("timestamp", "") if entries else "",
            "severity": "High",
            "category": "Reliability",
            "title": f"Service Interruption: {total_5xx} HTTP 5xx Responses Recorded",
            "source_log": "nginx / apache error",
            "line_references": [],
            "evidence": [f"Failing endpoints: {', '.join(list(errors_5xx.keys())[:4])}"],
            "rule_explanation": "Spike in 5xx errors indicates backend service crashes or connection dropouts.",
            "confidence": "High",
            "recommended_steps": [
                "Check backend application process logs for traceback exceptions.",
                "Verify database connection pool saturation.",
            ],
            "status": "New",
            "occurrences": total_5xx,
        })

    stats = {
        "total_requests": total_requests,
        "status_distribution": status_dist,
        "top_4xx_paths": [
            {"path": p, "count": d["count"], "ips": sorted(list(d["ips"]))}
            for p, d in sorted(path_4xx.items(), key=lambda x: x[1]["count"], reverse=True)[:8]
        ],
        "top_5xx_errors": [
            {"path": p, "count": count, "status": 500}
            for p, count in sorted(errors_5xx.items(), key=lambda x: x[1], reverse=True)[:8]
        ],
        "scanner_user_agents": [
            {"user_agent": ua, "count": d["count"], "ips": sorted(list(d["ips"]))}
            for ua, d in scanners_detected.items()
        ],
    }

    return stats, alerts
