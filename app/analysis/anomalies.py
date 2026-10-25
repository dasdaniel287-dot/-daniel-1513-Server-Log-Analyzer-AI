"""
Statistical Anomaly Detection Module
"""

import math
from typing import List, Dict, Any


def detect_statistical_anomalies(
    timeline_buckets: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if len(timeline_buckets) < 3:
        return []

    error_counts = [b.get("errors", 0) for b in timeline_buckets]
    avg = sum(error_counts) / len(error_counts)
    variance = sum((x - avg) ** 2 for x in error_counts) / len(error_counts)
    std_dev = math.sqrt(variance)

    anomalies: List[Dict[str, Any]] = []
    if std_dev == 0:
        return anomalies

    for b in timeline_buckets:
        errors = b.get("errors", 0)
        z_score = (errors - avg) / std_dev
        if z_score >= 2.0 and errors >= 3:
            anomalies.append({
                "id": f"ANOM-{len(anomalies) + 1:03d}",
                "type": "Statistical Error Surge",
                "severity": "High",
                "description": f"Error count of {errors} in window {b.get('bucket')} is {z_score:.1f} standard deviations above baseline.",
                "observed_value": f"{errors} errors",
                "baseline_value": f"Mean: {avg:.1f} (std: {std_dev:.1f})",
                "evidence": [f"Z-score: {z_score:.2f}"],
                "timestamp": b.get("bucket", ""),
                "score": min(99, int(z_score * 20)),
            })

    return anomalies
