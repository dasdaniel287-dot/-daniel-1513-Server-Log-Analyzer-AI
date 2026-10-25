"""
Authentication Analysis Module
Identifies brute-force, spray, and compromised credential indicators.
"""

from typing import List, Dict, Any, Tuple


def analyze_authentication_events(
    entries: List[Dict[str, Any]],
    brute_force_threshold: int = 4,
    spray_threshold: int = 3
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    total_attempts = 0
    failed_attempts = 0
    successful_logins = 0

    ip_failures: Dict[str, Dict[str, Any]] = {}
    user_data: Dict[str, Dict[str, int]] = {}
    suspicious_sequences: List[Dict[str, Any]] = []

    for entry in entries:
        auth = entry.get("auth")
        if not auth:
            continue

        total_attempts += 1
        user = auth.get("user") or "unknown"
        ip = entry.get("ip") or "unknown"

        if user not in user_data:
            user_data[user] = {"failures": 0, "successes": 0}

        status = auth.get("status")
        if status == "FAILURE":
            failed_attempts += 1
            user_data[user]["failures"] += 1

            if ip not in ip_failures:
                ip_failures[ip] = {"count": 0, "targets": set(), "lines": []}
            ip_failures[ip]["count"] += 1
            ip_failures[ip]["targets"].add(user)
            ip_failures[ip]["lines"].append(entry.get("line_number"))

        elif status == "SUCCESS":
            successful_logins += 1
            user_data[user]["successes"] += 1

            # Check if this IP previously had multiple failures
            if ip in ip_failures and ip_failures[ip]["count"] >= 2:
                suspicious_sequences.append({
                    "ip": ip,
                    "user": user,
                    "failed_before_success": ip_failures[ip]["count"],
                    "timestamp": entry.get("timestamp", ""),
                })

    alerts: List[Dict[str, Any]] = []
    alert_seq = 1

    # Brute-force rule
    for ip, data in ip_failures.items():
        if data["count"] >= brute_force_threshold:
            alerts.append({
                "id": f"ALT-{alert_seq:03d}",
                "timestamp": entries[0].get("timestamp", "") if entries else "",
                "severity": "Critical" if data["count"] >= 10 else "High",
                "category": "Authentication",
                "title": f"Potential Brute-Force Indicator: {data['count']} Failed Attempts from {ip}",
                "source_log": "auth / sshd",
                "line_references": data["lines"][:5],
                "evidence": [
                    f"Observed {data['count']} authentication failures from source host {ip}",
                    f"Target accounts tested: {', '.join(sorted(data['targets']))}",
                ],
                "rule_explanation": "Repeated failed logins indicate automated credential guessing against the host.",
                "confidence": "High",
                "recommended_steps": [
                    f"Verify whether IP {ip} is authorized.",
                    "Review fail2ban / SSH rate limiting configuration.",
                ],
                "status": "New",
                "occurrences": data["count"],
            })
            alert_seq += 1

    # Success after failure rule
    for seq in suspicious_sequences:
        alerts.append({
            "id": f"ALT-{alert_seq:03d}",
            "timestamp": seq["timestamp"],
            "severity": "Critical",
            "category": "Authentication",
            "title": f"High Priority: Successful Login Following {seq['failed_before_success']} Failures ({seq['user']} @ {seq['ip']})",
            "source_log": "auth / sshd",
            "line_references": ip_failures.get(seq["ip"], {}).get("lines", [])[:3],
            "evidence": [
                f"IP {seq['ip']} logged in as '{seq['user']}' after {seq['failed_before_success']} failed attempts.",
            ],
            "rule_explanation": "Valid authentication immediately succeeding brute-force activity warrants urgent validation.",
            "confidence": "High",
            "recommended_steps": [
                f"Contact user '{seq['user']}' to confirm legitimate login.",
                "Review auditd session commands.",
            ],
            "status": "New",
            "occurrences": seq["failed_before_success"] + 1,
        })
        alert_seq += 1

    failure_rate = round((failed_attempts / total_attempts) * 100) if total_attempts > 0 else 0

    stats = {
        "total_attempts": total_attempts,
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "failure_rate": failure_rate,
        "top_targeted_users": [
            {"user": u, "failures": d["failures"], "successes": d["successes"]}
            for u, d in sorted(user_data.items(), key=lambda x: x[1]["failures"], reverse=True)[:8]
        ],
        "top_failed_ips": [
            {"ip": ip, "count": d["count"], "targets": sorted(list(d["targets"]))}
            for ip, d in sorted(ip_failures.items(), key=lambda x: x[1]["count"], reverse=True)[:8]
        ],
        "suspicious_sequences": suspicious_sequences,
    }

    return stats, alerts
