"""
FastAPI Routes for Server Log Analyzer AI
"""

import time
import io
import csv
from fastapi import APIRouter, HTTPException, Response
from app.config import settings
from app.api.schemas import LogAnalysisRequest, AiInvestigateRequest, ExportReportRequest, BenchmarkRequest
from app.parsers.auth import parse_auth_line
from app.parsers.nginx import parse_nginx_access, parse_nginx_error
from app.parsers.syslog import parse_syslog_line
from app.parsers.json_logs import parse_json_line
from app.analysis.errors import group_repeated_errors
from app.analysis.authentication import analyze_authentication_events
from app.analysis.http_analysis import analyze_http_traffic
from app.analysis.correlation import correlate_incidents
from app.ai.assistant import investigate_incident
from app.reports.html_report import generate_html_report
from app.reports.json_report import generate_json_report
from app.ai.sanitization import sanitize_csv_field

router = APIRouter(prefix="/api")


def parse_and_analyze_raw(raw_text: str):
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    entries = []
    
    for idx, line in enumerate(lines, 1):
        parsed = None
        # Try JSON
        if line.startswith("{") and line.endswith("}"):
            parsed = parse_json_line(line, idx)
        if not parsed:
            parsed = parse_auth_line(line, idx)
        if not parsed:
            parsed = parse_nginx_access(line, idx)
        if not parsed:
            parsed = parse_nginx_error(line, idx)
        if not parsed:
            parsed = parse_syslog_line(line, idx)
            
        if parsed:
            entries.append(parsed)
        else:
            # Fallback
            entries.append({
                "id": f"gen-{idx}",
                "line_number": idx,
                "raw": line,
                "sanitized": line,
                "timestamp": "",
                "level": "INFO",
                "source": "custom",
                "message": line,
            })

    error_groups = group_repeated_errors(entries)
    auth_stats, auth_alerts = analyze_authentication_events(entries)
    http_stats, http_alerts = analyze_http_traffic(entries)
    incidents = correlate_incidents(entries, auth_stats, error_groups)
    
    alerts = auth_alerts + http_alerts
    errors_count = sum(1 for e in entries if e.get("level") in ("ERROR", "CRITICAL"))
    warn_count = sum(1 for e in entries if e.get("level") == "WARN")

    summary = {
        "total_lines": len(lines),
        "parsed_records": len(entries),
        "error_count": errors_count,
        "warn_count": warn_count,
        "alerts_count": len(alerts),
        "incidents_count": len(incidents),
    }

    return {
        "summary": summary,
        "alerts": alerts,
        "incidents": incidents,
        "error_groups": error_groups,
        "auth_stats": auth_stats,
        "http_stats": http_stats,
        "entries": entries[:200],  # sample preview
    }


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "ai_enabled": bool(settings.GEMINI_API_KEY),
    }


@router.post("/analyze")
def analyze_endpoint(payload: LogAnalysisRequest):
    try:
        result = parse_and_analyze_raw(payload.raw_content)
        return {"success": True, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/investigate")
def ai_investigate_endpoint(payload: AiInvestigateRequest):
    res = investigate_incident(
        title=payload.title,
        severity=payload.severity,
        category=payload.category,
        evidence=payload.evidence,
        rule_explanation=payload.rule_explanation or "",
        log_excerpts=payload.log_excerpts or []
    )
    return res


@router.post("/reports/export")
def export_report_endpoint(payload: ExportReportRequest):
    fmt = payload.format.lower()
    if fmt == "html":
        content = generate_html_report(payload.analysis_data, payload.analyst_notes or "")
        return Response(content=content, media_type="text/html")
    elif fmt == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["Line", "Timestamp", "Level", "Source", "Message"])
        for e in payload.analysis_data.get("entries", []):
            writer.writerow([
                sanitize_csv_field(e.get("line_number")),
                sanitize_csv_field(e.get("timestamp")),
                sanitize_csv_field(e.get("level")),
                sanitize_csv_field(e.get("source")),
                sanitize_csv_field(e.get("sanitized")),
            ])
        return Response(content=out.getvalue(), media_type="text/csv")
    else:
        content = generate_json_report(payload.analysis_data)
        return Response(content=content, media_type="application/json")


@router.post("/benchmarks")
def benchmark_endpoint(payload: BenchmarkRequest):
    count = max(1000, min(50000, payload.line_count))
    sample_line = '198.51.100.1 - - [25/Oct/2026:14:00:00 +0000] "GET /api/v1/resource HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    raw_synthetic = "\n".join([sample_line] * count)

    start = time.perf_counter()
    res = parse_and_analyze_raw(raw_synthetic)
    elapsed_ms = (time.perf_counter() - start) * 1000

    throughput = round(count / (elapsed_ms / 1000), 1)

    return {
        "success": True,
        "benchmark": {
            "target_lines": count,
            "duration_ms": round(elapsed_ms, 2),
            "throughput_lines_sec": throughput,
        }
    }
