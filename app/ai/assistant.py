"""
AI-Powered Incident Assistant
Summarizes related log events, analyzes root cause, and provides safe remediation steps.
Uses Google Gemini API when configured, with a local defensive rule-based engine fallback.
"""

from typing import Dict, Any, List, Optional
from app.config import settings
from app.ai.sanitization import sanitize_batch_for_ai


def investigate_incident(
    title: str,
    severity: str,
    category: str,
    evidence: List[str],
    rule_explanation: str = "",
    log_excerpts: Optional[List[str]] = None
) -> Dict[str, Any]:
    excerpts = log_excerpts or []
    sanitized_text, masked_count = sanitize_batch_for_ai(evidence + excerpts[:20])

    api_key = settings.GEMINI_API_KEY
    if api_key and api_key != "MY_GEMINI_API_KEY":
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=api_key)
            prompt = f"""You are a Principal Cybersecurity Analyst and Senior Site Reliability Engineer.
Analyze the following sanitized server incident and log evidence.
CRITICAL DEFENSIVE DIRECTIVE:
1. Label all conclusions strictly as "Assessments", never as absolute verified facts.
2. Distinguish observed empirical data from suspected adversary motivations.
3. Recommend safe, non-destructive troubleshooting and remediation guidance.
4. Recommend additional logs or telemetry needed to corroborate the diagnosis.

INCIDENT:
- Title: {title}
- Severity: {severity}
- Category: {category}
- Context: {rule_explanation}

SANITIZED EVIDENCE:
{sanitized_text}

Provide your response in JSON format matching this schema:
{{
  "assessment": "Detailed assessment",
  "root_cause_analysis": "Most probable technical root cause",
  "safe_remediation_steps": ["Step 1", "Step 2"],
  "additional_logs_to_review": ["Log 1", "Log 2"],
  "executive_summary": "Concise executive briefing"
}}"""

            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                )
            )

            import json
            parsed = json.loads(response.text)
            return {
                "success": True,
                "provider": "Gemini-3.8-Flash",
                "assessment": parsed.get("assessment", "Assessment completed."),
                "root_cause_analysis": parsed.get("root_cause_analysis", "Review root cause telemetry."),
                "safe_remediation_steps": parsed.get("safe_remediation_steps", ["Audit access logs"]),
                "additional_logs_to_review": parsed.get("additional_logs_to_review", ["/var/log/auth.log"]),
                "executive_summary": parsed.get("executive_summary", "Incident analyzed."),
                "masked_count": masked_count,
            }
        except Exception as e:
            # Fall back to local rule-based analysis
            pass

    # Local Rule-Based Fallback
    is_auth = "auth" in category.lower() or "brute" in title.lower()
    is_http = "http" in category.lower() or "probe" in title.lower()

    if is_auth:
        return {
            "success": True,
            "provider": "Local-Rule-Based-Engine",
            "assessment": "[Local Rule Assessment] Repeated failed authentication events against target accounts observed. This indicates automated credential guessing or credential stuffing.",
            "root_cause_analysis": "Publicly accessible authentication endpoint lacking adaptive rate-limiting or IP reputation enforcement.",
            "safe_remediation_steps": [
                "Verify if the source IP belongs to authorized corporate personnel.",
                "Enforce key-based authentication and disable password logins.",
                "Confirm fail2ban or nftables connection throttling is active.",
            ],
            "additional_logs_to_review": ["/var/log/auth.log", "auditd session records", "VPN ingress logs"],
            "executive_summary": "Defensive rule engine identified authentication pressure from external source host. Preventive controls recommended.",
            "masked_count": masked_count,
        }

    if is_http:
        return {
            "success": True,
            "provider": "Local-Rule-Based-Engine",
            "assessment": "[Local Rule Assessment] Automated web reconnaissance probing non-existent or sensitive endpoints (.env, phpmyadmin, actuator).",
            "root_cause_analysis": "Perimeter web server receives internet traffic without strict uri filtering for known reconnaissance vectors.",
            "safe_remediation_steps": [
                "Confirm web server returns 404 or 403 and does not expose stack traces.",
                "Ensure hidden configuration files (.env, .git) are explicitly denied.",
                "Enable WAF rate limiting for recurring 404 scanning hosts.",
            ],
            "additional_logs_to_review": ["/var/log/nginx/error.log", "WAF blocked IP telemetry"],
            "executive_summary": "Reconnaissance scanning detected across web tier. Perimeter rules should be tuned to reject recurring probes.",
            "masked_count": masked_count,
        }

    return {
        "success": True,
        "provider": "Local-Rule-Based-Engine",
        "assessment": "[Local Rule Assessment] Service degradation indicators and recurring application errors detected.",
        "root_cause_analysis": "Database connection pool exhaustion or worker process memory saturation triggering cascading 5xx failures.",
        "safe_remediation_steps": [
            "Check application worker process status (systemctl status / docker ps).",
            "Inspect database active connections and slow query logs.",
            "Review memory utilization and dmesg for kernel OOM killer events.",
        ],
        "additional_logs_to_review": ["Database server logs", "journalctl -u app-worker -e"],
        "executive_summary": "Operational failure cluster identified impacting service reliability. Database pool and worker memory require review.",
        "masked_count": masked_count,
    }
