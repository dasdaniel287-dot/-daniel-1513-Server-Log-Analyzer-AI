/**
 * Report Generation Engine
 * Exports: CSV, JSON, HTML (Printable & Archival)
 * Strictly enforces CSV formula injection defenses.
 */

import { AnalysisResult } from '../types/log';
import { sanitizeCsvField } from './sanitization';

export function generateCsvExport(analysis: AnalysisResult): string {
  const headers = [
    'Line Number',
    'Timestamp',
    'Level',
    'Source',
    'Service',
    'IP Address',
    'HTTP Method',
    'HTTP Path',
    'HTTP Status',
    'Auth User',
    'Auth Status',
    'Message',
  ];

  const rows: string[] = [headers.map((h) => sanitizeCsvField(h)).join(',')];

  for (const e of analysis.entries) {
    const row = [
      e.lineNumber,
      e.timestamp,
      e.level,
      e.source,
      e.service || '',
      e.ip || '',
      e.http?.method || '',
      e.http?.path || '',
      e.http?.status || '',
      e.auth?.user || '',
      e.auth?.status || '',
      e.sanitized,
    ];
    rows.push(row.map(sanitizeCsvField).join(','));
  }

  return rows.join('\r\n');
}

export function generateJsonExport(analysis: AnalysisResult): string {
  const exportPayload = {
    metadata: {
      generatedAt: new Date().toISOString(),
      generator: 'Server Log Analyzer AI v2.4 (2026 Production Edition)',
      reportVersion: '1.0',
    },
    summary: analysis.summary,
    alerts: analysis.alerts,
    anomalies: analysis.anomalies,
    incidents: analysis.incidents,
    errorGroups: analysis.errorGroups,
    authStatistics: analysis.authStats,
    httpStatistics: analysis.httpStats,
    sampleEntries: analysis.entries.slice(0, 100),
  };

  return JSON.stringify(exportPayload, null, 2);
}

export function generateHtmlReport(analysis: AnalysisResult, incidentNotes?: string): string {
  const { summary, alerts, incidents, errorGroups, authStats, httpStats } = analysis;

  const escapeHtml = (str: string) =>
    str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');

  const alertRows = alerts
    .map(
      (a) => `
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-family: monospace;">${escapeHtml(a.id)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-weight: bold; color: ${
        a.severity === 'Critical' ? '#ef4444' : a.severity === 'High' ? '#f97316' : '#eab308'
      };">${escapeHtml(a.severity)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155;">${escapeHtml(a.title)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155;">${escapeHtml(a.category)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-family: monospace;">${escapeHtml(a.status)}</td>
    </tr>
  `
    )
    .join('');

  const errorRows = errorGroups
    .slice(0, 8)
    .map(
      (err) => `
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-weight: bold;">${err.count}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-family: monospace;">${escapeHtml(err.service)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-size: 13px; font-family: monospace;">${escapeHtml(err.sampleMessage)}</td>
      <td style="padding: 8px; border-bottom: 1px solid #334155; font-size: 12px; font-family: monospace;">${escapeHtml(err.lastSeen)}</td>
    </tr>
  `
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security & Operational Incident Report - Server Log Analyzer AI</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 32px; line-height: 1.5; }
    h1, h2, h3 { color: #f8fafc; font-weight: 700; }
    .header { border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }
    .meta-box { background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 24px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
    .meta-item { border-left: 2px solid #38bdf8; padding-left: 12px; }
    .meta-label { font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }
    .meta-val { font-size: 20px; font-weight: 700; font-family: monospace; color: #f8fafc; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 28px; background: #0f172a; border-radius: 6px; overflow: hidden; }
    th { text-align: left; padding: 10px; background: #1e293b; color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .notes-box { background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 16px; margin-bottom: 24px; font-size: 14px; color: #e2e8f0; }
    @media print {
      body { background: #ffffff !important; color: #0f172a !important; padding: 0 !important; }
      .meta-box, table, th { background: #f8fafc !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; }
      td { border-bottom: 1px solid #e2e8f0 !important; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin: 0 0 6px 0; font-size: 24px;">Security & Operational Incident Report</h1>
      <div style="font-size: 13px; color: #94a3b8;">Server Log Analyzer AI · Defensive Security & Reliability Platform</div>
    </div>
    <div style="text-align: right; font-size: 12px; color: #94a3b8; font-family: monospace;">
      Generated: ${new Date().toUTCString()}<br>
      Version: 2026.1-LTS
    </div>
  </div>

  <div class="meta-box">
    <div class="meta-item">
      <div class="meta-label">Total Records Processed</div>
      <div class="meta-val">${summary.totalLines.toLocaleString()}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Errors / Critical</div>
      <div class="meta-val" style="color: ${summary.errorCount > 0 ? '#ef4444' : '#22c55e'};">
        ${summary.errorCount} / ${summary.criticalCount}
      </div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Security Alerts</div>
      <div class="meta-val" style="color: ${alerts.length > 0 ? '#f97316' : '#22c55e'};">${alerts.length}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Correlated Incidents</div>
      <div class="meta-val">${incidents.length}</div>
    </div>
  </div>

  ${
    incidentNotes
      ? `
  <h2>Analyst & AI Incident Assessment</h2>
  <div class="notes-box">
    ${escapeHtml(incidentNotes).replace(/\n/g, '<br>')}
  </div>
  `
      : ''
  }

  <h2>Active Security Alerts (${alerts.length})</h2>
  ${
    alerts.length === 0
      ? '<p style="color: #94a3b8;">No security alerts triggered under current thresholds.</p>'
      : `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Finding / Title</th>
          <th>Category</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${alertRows}
      </tbody>
    </table>
  `
  }

  <h2>Recurring Errors & Exception Clusters</h2>
  ${
    errorGroups.length === 0
      ? '<p style="color: #94a3b8;">No error patterns identified in dataset.</p>'
      : `
    <table>
      <thead>
        <tr>
          <th>Count</th>
          <th>Service</th>
          <th>Normalized Error Signature</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody>
        ${errorRows}
      </tbody>
    </table>
  `
  }

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 24px;">
    <div>
      <h3>Authentication Summary</h3>
      <ul style="font-size: 13px; color: #cbd5e1; line-height: 1.8;">
        <li>Total Login Attempts: <strong>${authStats.totalAttempts}</strong></li>
        <li>Failed Authentications: <strong>${authStats.failedAttempts}</strong> (${authStats.failureRate}%)</li>
        <li>Successful Logins: <strong>${authStats.successfulLogins}</strong></li>
        <li>Top Targeted Accounts: <strong>${
          authStats.topTargetedUsers.map((u) => `${u.user} (${u.failures} fails)`).join(', ') || 'None'
        }</strong></li>
      </ul>
    </div>
    <div>
      <h3>HTTP Inbound Traffic Profile</h3>
      <ul style="font-size: 13px; color: #cbd5e1; line-height: 1.8;">
        <li>Total HTTP Requests: <strong>${httpStats.totalRequests}</strong></li>
        <li>Unique Probed 4xx Paths: <strong>${httpStats.top4xxPaths.length}</strong></li>
        <li>Known Security Scanner Hits: <strong>${httpStats.scannerUserAgents.reduce((a, b) => a + b.count, 0)}</strong></li>
      </ul>
    </div>
  </div>

  <div style="margin-top: 40px; padding-top: 16px; border-top: 1px solid #334155; font-size: 11px; color: #64748b; text-align: center;">
    CONFIDENTIAL · For Authorized Systems Administration & Defensive Cybersecurity Audit Only · Server Log Analyzer AI
  </div>
</body>
</html>`;
}
