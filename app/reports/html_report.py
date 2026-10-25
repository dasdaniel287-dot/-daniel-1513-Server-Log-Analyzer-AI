"""
Standalone HTML Report Generator
"""

import html
from datetime import datetime, timezone
from typing import Dict, Any


def generate_html_report(analysis_data: Dict[str, Any], notes: str = "") -> str:
    summary = analysis_data.get("summary", {})
    alerts = analysis_data.get("alerts", [])
    error_groups = analysis_data.get("error_groups", [])

    alert_rows = ""
    for a in alerts:
        color = "#ef4444" if a.get("severity") == "Critical" else "#f97316" if a.get("severity") == "High" else "#eab308"
        alert_rows += f"""
        <tr>
            <td style="padding: 8px; font-family: monospace; border-bottom: 1px solid #334155;">{html.escape(str(a.get("id")))}</td>
            <td style="padding: 8px; font-weight: bold; color: {color}; border-bottom: 1px solid #334155;">{html.escape(str(a.get("severity")))}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{html.escape(str(a.get("title")))}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{html.escape(str(a.get("category")))}</td>
            <td style="padding: 8px; font-family: monospace; border-bottom: 1px solid #334155;">{html.escape(str(a.get("status")))}</td>
        </tr>
        """

    error_rows = ""
    for eg in error_groups[:6]:
        error_rows += f"""
        <tr>
            <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #334155;">{eg.get('count')}</td>
            <td style="padding: 8px; font-family: monospace; border-bottom: 1px solid #334155;">{html.escape(str(eg.get('service')))}</td>
            <td style="padding: 8px; font-family: monospace; border-bottom: 1px solid #334155;">{html.escape(str(eg.get('sample_message'))[:100])}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Server Log Analyzer AI - Incident Report</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 32px; line-height: 1.5; }}
        h1, h2 {{ color: #ffffff; }}
        .meta-strip {{ display: flex; gap: 20px; background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 24px; }}
        .meta-box {{ flex: 1; border-left: 2px solid #38bdf8; padding-left: 12px; }}
        .meta-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; }}
        .meta-num {{ font-size: 20px; font-weight: 700; font-family: monospace; color: #f8fafc; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #1e293b; border-radius: 6px; overflow: hidden; font-size: 13px; }}
        th {{ background: #334155; padding: 10px; text-align: left; text-transform: uppercase; font-size: 11px; color: #cbd5e1; }}
    </style>
</head>
<body>
    <h1>Security & Operational Incident Report</h1>
    <p style="color: #94a3b8; font-size: 13px;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · Server Log Analyzer AI</p>

    <div class="meta-strip">
        <div class="meta-box">
            <div class="meta-title">Total Records</div>
            <div class="meta-num">{summary.get('total_lines', 0)}</div>
        </div>
        <div class="meta-box">
            <div class="meta-title">Errors / Warnings</div>
            <div class="meta-num">{summary.get('error_count', 0)} / {summary.get('warn_count', 0)}</div>
        </div>
        <div class="meta-box">
            <div class="meta-title">Security Alerts</div>
            <div class="meta-num">{len(alerts)}</div>
        </div>
    </div>

    {f'<div style="background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 24px;"><h3>Analyst Notes</h3><p>{html.escape(notes)}</p></div>' if notes else ''}

    <h2>Security Alerts ({len(alerts)})</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th><th>Severity</th><th>Title</th><th>Category</th><th>Status</th>
            </tr>
        </thead>
        <tbody>
            {alert_rows if alert_rows else '<tr><td colspan="5" style="padding: 16px; text-align: center; color: #94a3b8;">No alerts triggered.</td></tr>'}
        </tbody>
    </table>

    <h2>Recurring Error Clusters</h2>
    <table>
        <thead>
            <tr><th>Count</th><th>Service</th><th>Sample Message</th></tr>
        </thead>
        <tbody>
            {error_rows if error_rows else '<tr><td colspan="3" style="padding: 16px; text-align: center; color: #94a3b8;">No recurring errors recorded.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""
