# Server Log Analyzer AI (2026 LTS)

> **Intelligent Log Monitoring, Anomaly Detection & Defensive Security Analysis Platform**

[![CI Tests](https://github.com/example/server-log-analyzer-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/example/server-log-analyzer-ai)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Node.js: 20+](https://img.shields.io/badge/node-20%2B-green)](https://nodejs.org/)

Server Log Analyzer AI is a modular, privacy-preserving defensive cybersecurity, Site Reliability Engineering (SRE), and incident investigation platform. It parses heterogeneous server logs, detects operational crashes, identifies potential brute-force patterns and web vulnerability scans, correlates cascading incidents, and generates actionable reports.

---

## Key Features

- **Multi-Source Ingestion & Parsing**: Native modular parsers for Syslog (RFC 3164/5424), Journald, SSH authentication, Nginx combined access/error, Apache, Python application tracebacks, JSON (Bunyan, Pino, Winston, CloudWatch), and Windows Event exports.
- **Authentication Threat Analysis**: Detects repeated password guessing, multi-account credential spraying, and high-priority anomalies (e.g. successful logins following repeated failures).
- **HTTP Traffic & Scanner Profiling**: Detects automated security scanners (sqlmap, nikto, dirbuster), path traversal attempts (`/etc/passwd`), and sensitive configuration probing (`.env`, `phpmyadmin`, `actuator`).
- **Operational Reliability & SRE**: Tracks database connection pool exhaustion, timeout cascades, and Linux kernel Out-Of-Memory (OOM) killer events.
- **Incident Correlation Engine**: Groups related events across hosts and services by temporal clustering, shared IP, or cascading dependencies.
- **AI-Powered Incident Assistant**: Powered by **Gemini 3.8 Flash** with automatic local rule-based fallback. Generates root-cause hypotheses, safe remediation recommendations, and executive summaries.
- **Strict Defensive Privacy**: Local-first redactor automatically masks Bearer tokens, API keys, passwords, and PII *before* external processing.
- **Safe Export Engine**: Generates HTML, JSON, and CSV reports with defenses against CSV formula injection.
- **Reproducible Performance Benchmarks**: Benchmarks throughput (50,000+ lines/sec) directly from the console.

---

## Supported Platforms

| Operating System | Support Level | Runtime |
| :--- | :--- | :--- |
| **Linux (Ubuntu / Debian / RHEL)** | Full Tier 1 | Native Node.js / Python 3.11 |
| **Docker / Kubernetes** | Full Containerized | Alpine / Debian Slim multi-stage |
| **Windows 10/11** | Full Tier 1 | PowerShell / WSL2 |
| **macOS (Apple Silicon & Intel)** | Full Tier 1 | Native Homebrew |
| **Termux (Android)** | Supported | Pure-Python fallback mode |

---

## Architecture

```
               ┌───────────────────────────────┐
               │    Server Log Analyzer AI     │
               │   (React + TypeScript SPA)    │
               └───────────────┬───────────────┘
                               │
               ┌───────────────▼───────────────┐
               │     Express / FastAPI API     │
               └───────────────┬───────────────┘
                               │
    ┌──────────────────────────┼──────────────────────────┐
    ▼                          ▼                          ▼
┌──────────────┐       ┌──────────────┐           ┌──────────────┐
│ Ingestion &  │       │  Detection & │           │ AI Assistant │
│ Sanitization │       │ Correlation  │           │   (Gemini)   │
└──────────────┘       └──────────────┘           └──────────────┘
    │                          │                          │
    ▼                          ▼                          ▼
  Tokens & PII           Sliding Window              Defensive
  Deterministic          Z-Score Spike              Assessment
  Redaction              Incident Graph              (Non-Fact)
```

---

## Quickstart

### Option A: Full-Stack Web Platform (Node.js & Vite)

```bash
# Clone the repository
git clone https://github.com/example/server-log-analyzer-ai.git
cd server-log-analyzer-ai

# Install dependencies
npm install

# Start the full-stack dev server
npm run dev
```

Open `http://localhost:3000` in your browser.

### Option B: Python Backend (FastAPI & Uvicorn)

```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run ASGI server
python -m uvicorn app.main:app --host 0.0.0.0 --port 3000
```

### Option C: Docker Compose

```bash
docker compose up -d
```

---

## Defensive Security & Ethics Policy

1. **Authorization**: This tool is designed exclusively for authorized system administrators, security analysts, and engineers defending their infrastructure.
2. **Fact vs. Assessment**: The software systematically labels analytical conclusions as **assessments**, avoiding premature classification of operational noise as confirmed security incidents.
3. **No Automatic Firewall Alterations**: To avoid unintended denial-of-service against authorized users, the system does not unilaterally block IPs; it presents actionable evidence for human verification.
4. **Data Isolation**: Log excerpts transmitted to AI analysis endpoints are stripped of authentication credentials, authorization tokens, and personal identifiers.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
