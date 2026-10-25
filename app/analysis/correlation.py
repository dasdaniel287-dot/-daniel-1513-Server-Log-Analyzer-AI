"""
Incident Correlation Module
Groups events by time proximity, shared source IP, or cascading service failures.
"""

from typing import List, Dict, Any


def correlate_incidents(
    entries: List[Dict[str, Any]],
    auth_stats: Dict[str, Any],
    error_groups: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    incidents: List[Dict[str, Any]] = []
    inc_seq = 1

    # 1. IP-level incident correlation
    for ip_rec in auth_stats.get("top_failed_ips", []):
        if ip_rec.get("count", 0) >= 4:
            ip = ip_rec["ip"]
            related = [e for e in entries if e.get("ip") == ip]
            incidents.append({
                "id": f"INC-{inc_seq:03d}",
                "title": f"Host Correlation: Persistent Authentication Pressure from {ip}",
                "severity": "Critical" if ip_rec["count"] >= 10 else "High",
                "correlation_key": f"IP:{ip}",
                "correlation_type": "IP_ADDRESS",
                "event_count": len(related),
                "first_seen": related[0].get("timestamp", "") if related else "",
                "last_seen": related[-1].get("timestamp", "") if related else "",
                "rationale": f"Correlated {len(related)} events from host {ip} targeting accounts: {', '.join(ip_rec.get('targets', []))}.",
                "indicators": [f"Source IP: {ip}", f"Total Failures: {ip_rec['count']}"],
                "sample_events": related[:5],
            })
            inc_seq += 1

    # 2. Service-level incident correlation
    if error_groups and len(error_groups) >= 2:
        error_entries = [e for e in entries if e.get("level") in ("ERROR", "CRITICAL")]
        services = list(set(e.get("service") or e.get("source") for e in error_entries))
        incidents.append({
            "id": f"INC-{inc_seq:03d}",
            "title": f"Service Interruption: Cascading Error Cluster Across ({', '.join(services[:3])})",
            "severity": "Critical" if any(e.get("level") == "CRITICAL" for e in error_entries) else "High",
            "correlation_key": f"SERVICE:{'_'.join(services[:2])}",
            "correlation_type": "SERVICE_FAILURE",
            "event_count": len(error_entries),
            "first_seen": error_entries[0].get("timestamp", "") if error_entries else "",
            "last_seen": error_entries[-1].get("timestamp", "") if error_entries else "",
            "rationale": f"Identified {len(error_entries)} severe error events across {len(services)} services in the observed log timeline.",
            "indicators": [f"Impacted services: {', '.join(services)}", f"Distinct error patterns: {len(error_groups)}"],
            "sample_events": error_entries[:5],
        })
        inc_seq += 1

    return incidents
