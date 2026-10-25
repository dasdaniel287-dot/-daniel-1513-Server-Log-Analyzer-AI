/**
 * Server Log Analyzer AI - Full-Stack Express Server
 * Serves REST API endpoints and mounts Vite middlewares for dev/production.
 */

import express, { Request, Response } from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { analyzeLogs, DEFAULT_DETECTION_RULES } from './src/engine/analyzer';
import { sanitizeLogForAi } from './src/engine/sanitization';
import { generateCsvExport, generateHtmlReport, generateJsonExport } from './src/engine/reports';
import { SAMPLE_LOGS } from './src/data/sampleLogs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health Check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    application: 'Server Log Analyzer AI',
    version: '2026.1.0-LTS',
    uptimeSeconds: Math.floor(process.uptime()),
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// Sample Logs List
app.get('/api/sample-logs', (_req: Request, res: Response) => {
  res.json({
    samples: SAMPLE_LOGS.map((s) => ({
      id: s.id,
      name: s.name,
      category: s.category,
      description: s.description,
      preview: s.content.slice(0, 300),
    })),
  });
});

// Get Specific Sample Log
app.get('/api/sample-logs/:id', (req: Request, res: Response) => {
  const sample = SAMPLE_LOGS.find((s) => s.id === req.params.id);
  if (!sample) {
    return res.status(404).json({ error: 'Sample log not found' });
  }
  res.json({ sample });
});

// Primary Log Analysis Endpoint
app.post('/api/analyze', (req: Request, res: Response) => {
  try {
    const { rawContent, customRules } = req.body;
    if (typeof rawContent !== 'string') {
      return res.status(400).json({ error: 'Invalid payload: rawContent string required' });
    }

    const rules = Array.isArray(customRules) ? customRules : DEFAULT_DETECTION_RULES;
    const result = analyzeLogs(rawContent, rules);

    return res.json({ success: true, result });
  } catch (error) {
    console.error('Log analysis failed:', error);
    return res.status(500).json({ error: 'Internal log analysis error' });
  }
});

// AI Incident Investigation Endpoint
app.post('/api/ai/investigate', async (req: Request, res: Response) => {
  try {
    const { incidentTitle, severity, category, evidence, logExcerpts, ruleExplanation } = req.body;

    const excerptsArray = Array.isArray(logExcerpts) ? logExcerpts : [];
    // Strict sanitization of logs and evidence before external transmission
    const sanitizedContext = sanitizeLogForAi([
      ...(Array.isArray(evidence) ? evidence : []),
      ...excerptsArray.slice(0, 30),
    ]);

    const apiKey = process.env.GEMINI_API_KEY;

    if (apiKey && apiKey !== 'MY_GEMINI_API_KEY') {
      try {
        const ai = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });

        const prompt = `You are a Principal Cybersecurity Analyst and Senior Site Reliability Engineer (SRE).
Analyze the following sanitized server incident and log evidence.
CRITICAL DEFENSIVE SECURITY DIRECTIVE:
1. Label all conclusions strictly as "Assessments", never as absolute verified facts.
2. Distinguish observed empirical data from suspected adversarial techniques.
3. Provide safe, non-destructive troubleshooting and remediation guidance.
4. Recommend additional logs or telemetry needed to corroborate the diagnosis.

INCIDENT DETAILS:
- Title: ${incidentTitle || 'Correlated Server Incident'}
- Severity: ${severity || 'Medium'}
- Category: ${category || 'System Incident'}
- Triggering Rule: ${ruleExplanation || 'Statistical and pattern correlation'}

SANITIZED EVIDENCE & LOG EXCERPTS:
${sanitizedContext.sanitizedText}

Respond with valid JSON containing exactly these keys:
{
  "assessment": "Detailed analytical assessment distinguishing observed facts from suspected motives",
  "rootCauseAnalysis": "Most probable technical root cause (e.g., misconfigured rate-limit, exposed secret, unindexed query)",
  "safeRemediationSteps": ["Step 1", "Step 2", "Step 3", "Step 4"],
  "additionalLogsToReview": ["Log source 1 to inspect", "Log source 2 to inspect"],
  "executiveSummary": "A concise 2-3 sentence executive briefing suitable for leadership."
}`;

        const generatePromise = ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            temperature: 0.2,
          },
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Gemini API request timed out')), 6000)
        );

        const response = await Promise.race([generatePromise, timeoutPromise]);
        const responseText = response.text || '{}';
        const parsedAi = JSON.parse(responseText);

        return res.json({
          success: true,
          provider: 'Gemini-3.8-Flash',
          assessment: parsedAi.assessment || 'Assessment completed.',
          rootCauseAnalysis: parsedAi.rootCauseAnalysis || 'Root cause investigation recommended.',
          safeRemediationSteps: parsedAi.safeRemediationSteps || ['Review firewall', 'Audit logs'],
          additionalLogsToReview: parsedAi.additionalLogsToReview || ['/var/log/auth.log', '/var/log/syslog'],
          executiveSummary: parsedAi.executiveSummary || 'Incident under investigation.',
          sanitizationReport: {
            maskedCount: sanitizedContext.stats.maskedCount,
          },
          timestamp: new Date().toISOString(),
        });
      } catch (geminiError) {
        console.warn('Gemini API call failed, falling back to local defensive rule engine:', geminiError);
      }
    }

    // Local Rule-Based Fallback Engine
    const fallbackAssessment = generateLocalIncidentAssessment(incidentTitle, severity, category, evidence);

    return res.json({
      success: true,
      provider: 'Local-Rule-Based-Engine',
      ...fallbackAssessment,
      sanitizationReport: {
        maskedCount: sanitizedContext.stats.maskedCount,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('AI investigation endpoint error:', error);
    return res.status(500).json({ error: 'Failed to complete incident investigation' });
  }
});

function generateLocalIncidentAssessment(
  title = '',
  severity = 'Medium',
  category = 'General',
  evidence: string[] = []
) {
  const isAuth = category.toLowerCase().includes('auth') || title.toLowerCase().includes('brute') || title.toLowerCase().includes('spray');
  const isHttp = category.toLowerCase().includes('http') || title.toLowerCase().includes('web') || title.toLowerCase().includes('probe');
  const isReliability = category.toLowerCase().includes('reliability') || title.toLowerCase().includes('crash') || title.toLowerCase().includes('pool');

  if (isAuth) {
    return {
      assessment: `[Local Rule Assessment] Observed repeated failed authentication events against target accounts. While pattern aligns with automated credential guessing or distributed credential stuffing, it must be treated as a suspected threat pending internal IP verification.`,
      rootCauseAnalysis: `Publicly accessible authentication endpoint (SSH/PAM) lacking progressive delay or adaptive GeoIP/IP reputation filtering, allowing rapid succession attempts.`,
      safeRemediationSteps: [
        'Verify if the source IP belongs to authorized corporate VPN, test script, or legitimate employee.',
        'Enforce key-based authentication and disable password logins for administrative accounts.',
        'Enable rate limiting via fail2ban or nftables/iptables connection rate limits.',
        'Verify whether any successful login followed the failed attempts.',
      ],
      additionalLogsToReview: [
        '/var/log/auth.log (audit subsequent sessions from the source IP)',
        '~/.bash_history or auditd logs for accounts that experienced authentication',
        'VPN and identity provider (IdP) access logs',
      ],
      executiveSummary: `Defensive rule engine identified authentication pressure from external source host. Preventive controls recommended to prevent credential compromise.`,
    };
  }

  if (isHttp) {
    return {
      assessment: `[Local Rule Assessment] Detected automated reconnaissance probing non-existent or sensitive application endpoints (.env, phpmyadmin, actuator). These probes are typical of background internet scanning.`,
      rootCauseAnalysis: `Web server receives internet-facing HTTP requests without strict perimeter ingress filtering for known exploratory uri vectors.`,
      safeRemediationSteps: [
        'Confirm web server returns 404 or 403 and does not expose stack traces or directory listings.',
        'Ensure sensitive configuration files (.env, .git) are explicitly denied in nginx/apache configs.',
        'Implement Web Application Firewall (WAF) rate limiting for aggressive 404 scanning hosts.',
      ],
      additionalLogsToReview: [
        '/var/log/nginx/error.log or /var/log/apache2/error.log',
        'Cloudflare / AWS WAF request metrics and blocked IP list',
      ],
      executiveSummary: `Reconnaissance scanning detected across web tier. Web server responded defensively with 4xx codes; perimeter rules should be tuned to reject recurring probes.`,
    };
  }

  return {
    assessment: `[Local Rule Assessment] Detected service interruption and resource exhaustion indicators. High volume of 5xx errors or connection timeouts indicate upstream service degradation.`,
    rootCauseAnalysis: `Database connection pool depletion, runaway query latency, or container memory limit saturation triggering worker process termination.`,
    safeRemediationSteps: [
      'Inspect application worker process status (e.g. systemctl status or docker ps).',
      'Check database active connections and slow query log to identify long-running transactions.',
      'Review memory utilization and kernel dmesg logs for OOM killer invocations.',
      'Verify upstream reverse proxy keepalive and timeout configurations.',
    ],
    additionalLogsToReview: [
      'Database server logs (e.g. /var/log/postgresql/postgresql.log)',
      'System journald (journalctl -u app-worker -e)',
      'APM telemetry and container resource metrics',
    ],
    executiveSummary: `Operational failure cluster identified impacting service reliability. Database connection pool and process memory limits require immediate SRE review.`,
  };
}

// Export Report Endpoint
app.post('/api/reports/export', (req: Request, res: Response) => {
  try {
    const { format, analysis, incidentNotes } = req.body;
    if (!analysis) {
      return res.status(400).json({ error: 'Missing analysis payload' });
    }

    if (format === 'csv') {
      const csv = generateCsvExport(analysis);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="server-log-analysis.csv"');
      return res.send(csv);
    }

    if (format === 'json') {
      const jsonStr = generateJsonExport(analysis);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="server-log-analysis.json"');
      return res.send(jsonStr);
    }

    // Default HTML
    const html = generateHtmlReport(analysis, incidentNotes);
    res.setHeader('Content-Type', 'text/html');
    return res.send(html);
  } catch (error) {
    console.error('Report export error:', error);
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Reproducible Performance Benchmarks Endpoint
app.post('/api/benchmarks', (req: Request, res: Response) => {
  try {
    const { lineCount = 10000 } = req.body;
    const targetLines = Math.min(100000, Math.max(1000, parseInt(String(lineCount), 10)));

    // Generate synthetic log lines in memory
    const syntheticLines: string[] = [];
    const baseDate = new Date('2026-10-25T12:00:00Z');

    for (let i = 0; i < targetLines; i++) {
      const d = new Date(baseDate.getTime() + i * 100);
      const iso = d.toISOString();
      const ip = `198.51.100.${(i % 50) + 1}`;
      if (i % 15 === 0) {
        syntheticLines.push(`Oct 25 12:00:00 host sshd[${2000 + (i % 100)}]: Failed password for invalid user admin from ${ip} port 49212 ssh2`);
      } else if (i % 25 === 0) {
        syntheticLines.push(`${ip} - - [25/Oct/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "sqlmap/1.7"`);
      } else if (i % 30 === 0) {
        syntheticLines.push(`${iso} [ERROR] [app.db] ConnectionPoolTimeout: QueuePool limit reached`);
      } else {
        syntheticLines.push(`${ip} - - [25/Oct/2026:12:00:00 +0000] "GET /api/v1/resource HTTP/1.1" 200 1240 "-" "Mozilla/5.0"`);
      }
    }

    const payload = syntheticLines.join('\n');
    const startMemory = process.memoryUsage().heapUsed;
    const startTime = performance.now();

    const result = analyzeLogs(payload, DEFAULT_DETECTION_RULES);

    const endTime = performance.now();
    const endMemory = process.memoryUsage().heapUsed;

    const durationMs = Math.round((endTime - startTime) * 100) / 100;
    const throughput = Math.round((targetLines / (durationMs / 1000)) * 10) / 10;
    const memoryDeltaMb = Math.round(((endMemory - startMemory) / 1024 / 1024) * 100) / 100;

    return res.json({
      success: true,
      benchmark: {
        targetLines,
        parsedRecords: result.summary.parsedRecords,
        durationMs,
        throughputLinesPerSec: throughput,
        memoryDeltaMb,
        alertsDetected: result.alerts.length,
        errorGroupsCount: result.errorGroups.length,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('Benchmark execution error:', error);
    return res.status(500).json({ error: 'Benchmark execution failed' });
  }
});

// Mount Vite or serve static dist
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server Log Analyzer AI backend running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
