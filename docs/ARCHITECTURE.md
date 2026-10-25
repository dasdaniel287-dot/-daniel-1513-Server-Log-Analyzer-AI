# Technical Architecture — Server Log Analyzer AI

## 1. System Overview & Core Invariants

Server Log Analyzer AI is an open-source, defensive cybersecurity and Site Reliability Engineering (SRE) platform. It parses heterogeneous server logs, detects operational failures, identifies adversarial indicators, and correlates multi-source incidents while strictly protecting credentials and PII.

### Invariants:
1. **Defensive Separation**: Observed facts are distinguished from suspected threats. An unverified finding is never presented as a confirmed attack.
2. **Local-First Privacy**: Sensitive authorization headers (Bearer tokens), passwords, secret keys, and email addresses are masked deterministically *prior* to UI presentation or external AI inspection.
3. **Graceful Fallback**: If external AI models (Gemini) are unavailable, a local deterministic rule-based analysis engine executes without service interruption.
4. **Formula Injection Neutralization**: All spreadsheet CSV exports sanitize cell values starting with `=, +, -, @, \t, \r` to prevent client execution vulnerabilities.

---

## 2. Ingestion & Parsing Pipeline

```
  [Raw Log Input] (Syslog, Nginx, Apache, Auth, JSON, Windows)
         │
         ▼
  [Validation Layer] (Filename sanitization, Size bounds <= 50MB)
         │
         ▼
  [Sanitization Engine] (Masks Bearer tokens, API keys, passwords, PII)
         │
         ▼
  [Modular Dispatcher]
     ├── Syslog RFC 3164 / 5424 Parser
     ├── SSH / PAM Auth Parser
     ├── Nginx / Apache Access & Error Parsers
     ├── Python / Application Traceback Parser
     └── JSON (Bunyan, Pino, Winston) Parser
```

---

## 3. Analysis & Correlation Math

### A. Temporal Sliding Windows
Events are partitioned into sliding intervals ($W$ minutes). If failed authentication attempts from IP $x$ exceed threshold $\theta_{\text{auth}}$ within window $W$, an `ALT-AUTH` alert is generated.

### B. Statistical Z-Score Anomaly Engine
Given event count time-series $X = \{x_1, x_2, \dots, x_N\}$, the mean $\mu$ and standard deviation $\sigma$ are calculated:
$$\mu = \frac{1}{N} \sum_{i=1}^N x_i, \quad \sigma = \sqrt{\frac{1}{N} \sum_{i=1}^N (x_i - \mu)^2}$$
A time window $k$ triggers a statistical surge alert when:
$$Z_k = \frac{x_k - \mu}{\sigma} \ge 2.0 \quad \text{and} \quad x_k \ge 3$$

### C. Multi-Source Incident Correlation
Correlations are formulated across:
- **Shared Source Host**: Grouping reconnaissance scans with SSH authentication spikes from the same IP.
- **Service Dependency Cascades**: Grouping database connection pool timeouts with upstream reverse proxy 502/504 errors.
