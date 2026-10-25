# REST API Reference — Server Log Analyzer AI

## Base URL
`http://localhost:3000/api`

---

### 1. Health Status
`GET /api/health`

Returns application version, engine status, and Gemini integration availability.

```json
{
  "status": "healthy",
  "application": "Server Log Analyzer AI",
  "version": "2026.1.0-LTS",
  "uptimeSeconds": 1420,
  "geminiConfigured": true
}
```

---

### 2. Ingest & Analyze Logs
`POST /api/analyze`

**Request Body:**
```json
{
  "rawContent": "Oct 25 14:02:11 bastion sshd[28410]: Failed password for invalid user admin from 198.51.100.42 port 49212 ssh2\n...",
  "customRules": []
}
```

**Response:**
Returns complete `AnalysisResult` object containing summary metrics, active alerts, error groups, authentication statistics, HTTP traffic breakdown, and chronological timeline buckets.

---

### 3. AI Incident Investigation
`POST /api/ai/investigate`

**Request Body:**
```json
{
  "incidentTitle": "Potential Brute-Force Indicator: 10 Failed Attempts from 198.51.100.42",
  "severity": "Critical",
  "category": "Authentication",
  "evidence": ["10 failed attempts from 198.51.100.42"],
  "ruleExplanation": "Consecutive authentication failures from single IP."
}
```

**Response:**
```json
{
  "success": true,
  "provider": "Gemini-3.8-Flash",
  "assessment": "Detailed analytical assessment distinguishing observed facts from suspected motives.",
  "rootCauseAnalysis": "Publicly accessible authentication endpoint without rate limiting.",
  "safeRemediationSteps": ["Step 1", "Step 2"],
  "additionalLogsToReview": ["/var/log/auth.log"],
  "executiveSummary": "Concise executive briefing.",
  "sanitizationReport": { "maskedCount": 2 }
}
```

---

### 4. Report Export
`POST /api/reports/export`

Accepts `format: "csv" | "json" | "html"` and returns downloadable data stream.
CSV exports strictly enforce formula injection escaping.

---

### 5. Reproducible Benchmarks
`POST /api/benchmarks`

Executes in-memory parsing on 1,000, 10,000, or 50,000 synthetic log records, reporting throughput (lines/second) and latency metrics.
