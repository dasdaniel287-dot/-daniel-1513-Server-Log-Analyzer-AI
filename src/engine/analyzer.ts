/**
 * Core Analysis Engine
 * Defensive Cybersecurity, Anomaly Detection & Incident Correlation
 */

import {
  AnalysisResult,
  AnalysisSummary,
  AnomalyFinding,
  AuthStatistics,
  CorrelatedIncident,
  DetectionRuleConfig,
  ErrorGroup,
  HttpStatistics,
  LogEntry,
  LogLevel,
  SecurityAlert,
  TimelineBucket,
} from '../types/log';
import { parseLogLine } from './parsers';

export const DEFAULT_DETECTION_RULES: DetectionRuleConfig[] = [
  {
    id: 'RULE_AUTH_BRUTE_FORCE',
    name: 'SSH / Auth Brute-Force Detection',
    category: 'Authentication',
    enabled: true,
    threshold: 4, // 4+ failures from same IP within window
    windowMinutes: 10,
    description: 'Triggers alert when multiple consecutive failed login attempts occur from a single source IP.',
  },
  {
    id: 'RULE_AUTH_SPRAY',
    name: 'Multi-Account Credential Spraying',
    category: 'Authentication',
    enabled: true,
    threshold: 3, // 3+ distinct user accounts from single IP
    windowMinutes: 15,
    description: 'Detects a single host attempting authentication against multiple usernames (horizontal credential spray).',
  },
  {
    id: 'RULE_SUCCESS_AFTER_FAILURE',
    name: 'Privilege Compromise Indicator',
    category: 'Authentication',
    enabled: true,
    threshold: 2, // 2+ failures immediately followed by success
    windowMinutes: 15,
    description: 'Alerts when a successful login occurs from an IP that recently produced repeated authentication failures.',
  },
  {
    id: 'RULE_WEB_DIR_TRAVERSAL_PROBE',
    name: 'Web Reconnaissance & Path Traversal Probe',
    category: 'HTTP Traffic',
    enabled: true,
    threshold: 3, // 3+ requests to sensitive or scan paths
    windowMinutes: 10,
    description: 'Flags probing for sensitive files (e.g. .env, phpmyadmin, wp-login, etc/passwd, actuator).',
  },
  {
    id: 'RULE_HTTP_5XX_SURGE',
    name: 'Application 5xx Gateway / Service Crash Surge',
    category: 'Reliability',
    enabled: true,
    threshold: 5,
    windowMinutes: 5,
    description: 'Alerts when internal server errors or bad gateway responses surge within a tight time window.',
  },
  {
    id: 'RULE_DB_RESOURCE_EXHAUSTION',
    name: 'Database / Memory Resource Exhaustion',
    category: 'Reliability',
    enabled: true,
    threshold: 2,
    windowMinutes: 10,
    description: 'Detects DB connection timeouts, connection pool exhaustion, or kernel Out-Of-Memory (OOM) killer events.',
  },
  {
    id: 'RULE_SCANNER_USER_AGENT',
    name: 'Automated Security Scanner User-Agent',
    category: 'HTTP Traffic',
    enabled: true,
    threshold: 1,
    windowMinutes: 60,
    description: 'Detects known automated security assessment tool signatures (e.g. sqlmap, nikto, dirbuster, gobuster).',
  },
];

const KNOWN_SCANNER_PATHS = [
  '/.env',
  '/.git',
  '/wp-login.php',
  '/wp-admin',
  '/phpmyadmin',
  '/pma',
  '/actuator',
  '/actuator/env',
  '/actuator/health',
  '/swagger-ui',
  '/cgi-bin',
  '/etc/passwd',
  '/../',
  '/shell',
  '/admin/config',
  '/.aws/credentials',
  '/solr',
  '/jenkins',
];

const KNOWN_SCANNER_AGENTS = [
  'sqlmap',
  'nikto',
  'masscan',
  'dirbuster',
  'gobuster',
  'nmap',
  'zgrab',
  'censys',
  'shodan',
  'acunetix',
];

export function analyzeLogs(
  rawContent: string,
  customRules: DetectionRuleConfig[] = DEFAULT_DETECTION_RULES
): AnalysisResult {
  const lines = rawContent.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const entries: LogEntry[] = [];
  let malformedCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const entry = parseLogLine(lines[i], i + 1);
    if (entry.isMalformed) {
      malformedCount++;
    } else {
      entries.push(entry);
    }
  }

  // Sort chronologically by timestampMs
  entries.sort((a, b) => a.timestampMs - b.timestampMs);

  const totalLines = lines.length;
  const parsedRecords = entries.length;

  let errorCount = 0;
  let warnCount = 0;
  let criticalCount = 0;
  const uniqueIpsSet = new Set<string>();

  for (const e of entries) {
    if (e.ip) uniqueIpsSet.add(e.ip);
    if (e.level === 'ERROR') errorCount++;
    if (e.level === 'WARN') warnCount++;
    if (e.level === 'CRITICAL') criticalCount++;
  }

  // Time Range
  const startMs = entries.length > 0 ? entries[0].timestampMs : Date.now();
  const endMs = entries.length > 0 ? entries[entries.length - 1].timestampMs : Date.now();
  const durationMinutes = Math.max(1, Math.round((endMs - startMs) / 60000));

  // 1. Group Repeated Errors
  const errorGroupsMap = new Map<string, {
    count: number;
    firstSeen: string;
    lastSeen: string;
    sampleMessage: string;
    service: string;
    level: LogLevel;
    stackTrace?: string;
  }>();

  for (const e of entries) {
    if (e.level === 'ERROR' || e.level === 'CRITICAL') {
      // Normalize signature: strip numbers, timestamps, IDs
      const normalized = e.message
        .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<IP>')
        .replace(/\b\d+\b/g, '<N>')
        .replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '<UUID>')
        .substring(0, 120);

      const service = e.service || e.source || 'application';
      const key = `${service}:${normalized}`;

      if (!errorGroupsMap.has(key)) {
        errorGroupsMap.set(key, {
          count: 1,
          firstSeen: e.timestamp,
          lastSeen: e.timestamp,
          sampleMessage: e.message,
          service,
          level: e.level,
          stackTrace: e.stackTrace,
        });
      } else {
        const item = errorGroupsMap.get(key)!;
        item.count++;
        item.lastSeen = e.timestamp;
      }
    }
  }

  const errorGroups: ErrorGroup[] = Array.from(errorGroupsMap.entries()).map(([sig, val], idx) => ({
    id: `err-grp-${idx + 1}`,
    signature: sig,
    service: val.service,
    count: val.count,
    firstSeen: val.firstSeen,
    lastSeen: val.lastSeen,
    sampleMessage: val.sampleMessage,
    stackTrace: val.stackTrace,
    level: val.level,
  })).sort((a, b) => b.count - a.count);

  // 2. Authentication Analysis
  const ipAuthFailures = new Map<string, { count: number; targets: Set<string>; lines: number[] }>();
  const userAuthFailures = new Map<string, { failures: number; successes: number }>();
  const ipAuthSuccesses = new Map<string, number>();
  let totalAuthAttempts = 0;
  let failedAuthAttempts = 0;
  let successfulLogins = 0;

  // Track sequence: failed -> success
  const suspiciousSequences: {
    ip: string;
    user: string;
    failedBeforeSuccess: number;
    timestamp: string;
  }[] = [];

  for (const e of entries) {
    if (e.auth) {
      totalAuthAttempts++;
      const user = e.auth.user || 'unknown';
      const ip = e.ip || 'unknown';

      if (!userAuthFailures.has(user)) {
        userAuthFailures.set(user, { failures: 0, successes: 0 });
      }

      if (e.auth.status === 'FAILURE') {
        failedAuthAttempts++;
        userAuthFailures.get(user)!.failures++;

        if (!ipAuthFailures.has(ip)) {
          ipAuthFailures.set(ip, { count: 0, targets: new Set(), lines: [] });
        }
        const ipRec = ipAuthFailures.get(ip)!;
        ipRec.count++;
        ipRec.targets.add(user);
        ipRec.lines.push(e.lineNumber);
      } else if (e.auth.status === 'SUCCESS') {
        successfulLogins++;
        userAuthFailures.get(user)!.successes++;
        ipAuthSuccesses.set(ip, (ipAuthSuccesses.get(ip) || 0) + 1);

        // Check if this IP previously had multiple failures
        const priorFails = ipAuthFailures.get(ip);
        if (priorFails && priorFails.count >= 2) {
          suspiciousSequences.push({
            ip,
            user,
            failedBeforeSuccess: priorFails.count,
            timestamp: e.timestamp,
          });
        }
      }
    }
  }

  const authStats: AuthStatistics = {
    totalAttempts: totalAuthAttempts,
    failedAttempts: failedAuthAttempts,
    successfulLogins,
    failureRate: totalAuthAttempts > 0 ? Math.round((failedAuthAttempts / totalAuthAttempts) * 100) : 0,
    topTargetedUsers: Array.from(userAuthFailures.entries())
      .map(([user, data]) => ({ user, failures: data.failures, successes: data.successes }))
      .sort((a, b) => b.failures - a.failures)
      .slice(0, 8),
    topFailedIps: Array.from(ipAuthFailures.entries())
      .map(([ip, data]) => ({ ip, count: data.count, targets: Array.from(data.targets) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    suspiciousSequences,
  };

  // 3. HTTP Traffic Analysis
  const statusDist: Record<string, number> = {};
  const path4xxMap = new Map<string, { count: number; ips: Set<string> }>();
  const error5xxMap = new Map<string, { count: number; status: number }>();
  const scannerUaMap = new Map<string, { count: number; ips: Set<string> }>();
  const ipTrafficMap = new Map<string, { total: number; errors: number }>();
  let totalHttpRequests = 0;

  for (const e of entries) {
    if (e.http) {
      totalHttpRequests++;
      const code = String(e.http.status);
      statusDist[code] = (statusDist[code] || 0) + 1;

      const ip = e.ip || 'unknown';
      if (!ipTrafficMap.has(ip)) {
        ipTrafficMap.set(ip, { total: 0, errors: 0 });
      }
      const traffic = ipTrafficMap.get(ip)!;
      traffic.total++;
      if (e.http.status >= 400) traffic.errors++;

      // 4xx tracking
      if (e.http.status >= 400 && e.http.status < 500) {
        if (!path4xxMap.has(e.http.path)) {
          path4xxMap.set(e.http.path, { count: 0, ips: new Set() });
        }
        const rec = path4xxMap.get(e.http.path)!;
        rec.count++;
        rec.ips.add(ip);
      }

      // 5xx tracking
      if (e.http.status >= 500) {
        const key = `${e.http.method} ${e.http.path}`;
        if (!error5xxMap.has(key)) {
          error5xxMap.set(key, { count: 0, status: e.http.status });
        }
        error5xxMap.get(key)!.count++;
      }

      // Scanner User-Agent check
      if (e.http.userAgent) {
        const uaLower = e.http.userAgent.toLowerCase();
        for (const known of KNOWN_SCANNER_AGENTS) {
          if (uaLower.includes(known)) {
            if (!scannerUaMap.has(e.http.userAgent)) {
              scannerUaMap.set(e.http.userAgent, { count: 0, ips: new Set() });
            }
            const uaRec = scannerUaMap.get(e.http.userAgent)!;
            uaRec.count++;
            uaRec.ips.add(ip);
            break;
          }
        }
      }
    }
  }

  const httpStats: HttpStatistics = {
    totalRequests: totalHttpRequests,
    statusDistribution: statusDist,
    top4xxPaths: Array.from(path4xxMap.entries())
      .map(([path, data]) => ({ path, count: data.count, ips: Array.from(data.ips) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    top5xxErrors: Array.from(error5xxMap.entries())
      .map(([path, data]) => ({ path, count: data.count, status: data.status }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    scannerUserAgents: Array.from(scannerUaMap.entries())
      .map(([userAgent, data]) => ({ userAgent, count: data.count, ips: Array.from(data.ips) }))
      .sort((a, b) => b.count - a.count),
    topTalkerIps: Array.from(ipTrafficMap.entries())
      .map(([ip, data]) => ({
        ip,
        count: data.total,
        errorRate: data.total > 0 ? Math.round((data.errors / data.total) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
  };

  // 4. Timeline Aggregation (divide time span into ~12 to 24 buckets)
  const bucketCount = 18;
  const timeStep = Math.max(1000, Math.floor((endMs - startMs) / bucketCount) || 60000);
  const timeline: TimelineBucket[] = [];

  for (let i = 0; i <= bucketCount; i++) {
    const curStart = startMs + i * timeStep;
    const curEnd = curStart + timeStep;
    const d = new Date(curStart);
    const label = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;

    let total = 0;
    let errors = 0;
    let authFailures = 0;
    let warnings = 0;
    let http4xx = 0;
    let http5xx = 0;

    for (const e of entries) {
      if (e.timestampMs >= curStart && e.timestampMs < curEnd) {
        total++;
        if (e.level === 'ERROR' || e.level === 'CRITICAL') errors++;
        if (e.level === 'WARN') warnings++;
        if (e.auth?.status === 'FAILURE') authFailures++;
        if (e.http && e.http.status >= 400 && e.http.status < 500) http4xx++;
        if (e.http && e.http.status >= 500) http5xx++;
      }
    }

    timeline.push({
      bucket: label,
      timestampMs: curStart,
      total,
      errors,
      authFailures,
      warnings,
      http4xx,
      http5xx,
    });
  }

  // 5. Rule-Based Alert System
  const alerts: SecurityAlert[] = [];
  let alertSeq = 1;

  // A. Brute-Force Check
  const bruteRule = customRules.find((r) => r.id === 'RULE_AUTH_BRUTE_FORCE');
  if (bruteRule?.enabled) {
    for (const [ip, data] of ipAuthFailures.entries()) {
      if (data.count >= bruteRule.threshold) {
        alerts.push({
          id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
          timestamp: entries.find((e) => e.ip === ip && e.auth?.status === 'FAILURE')?.timestamp || new Date().toISOString(),
          severity: data.count >= 10 ? 'Critical' : 'High',
          category: 'Authentication',
          title: `Potential Brute-Force Indicator: ${data.count} Failed Attempts from ${ip}`,
          sourceLog: 'auth / sshd',
          lineReferences: data.lines.slice(0, 5),
          evidence: [
            `Observed ${data.count} authentication failures originating from source host ${ip}`,
            `Target accounts attempted: ${Array.from(data.targets).join(', ')}`,
            `Threshold of ${bruteRule.threshold} failures within window was exceeded`,
          ],
          ruleExplanation: 'Consecutive authentication failures from a single IP indicate credential guessing or automated dictionary testing.',
          confidence: 'High',
          recommendedSteps: [
            `Verify whether IP ${ip} belongs to authorized personnel or corporate VPN.`,
            `Investigate if fail2ban or SSH rate limiting is active for this service.`,
            `Review subsequent log lines to confirm if any login succeeded from this source.`,
          ],
          status: 'New',
          occurrences: data.count,
        });
      }
    }
  }

  // B. Credential Spray Check
  const sprayRule = customRules.find((r) => r.id === 'RULE_AUTH_SPRAY');
  if (sprayRule?.enabled) {
    for (const [ip, data] of ipAuthFailures.entries()) {
      if (data.targets.size >= sprayRule.threshold) {
        alerts.push({
          id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
          timestamp: new Date().toISOString(),
          severity: 'High',
          category: 'Authentication',
          title: `Potential Credential Spray: ${data.targets.size} Accounts Targeted by ${ip}`,
          sourceLog: 'auth / sshd',
          lineReferences: data.lines.slice(0, 5),
          evidence: [
            `Source IP ${ip} attempted authentication against ${data.targets.size} distinct usernames`,
            `Target user list: ${Array.from(data.targets).join(', ')}`,
          ],
          ruleExplanation: 'Spraying single passwords across multiple user accounts is commonly employed to evade per-account lockout policies.',
          confidence: 'Medium',
          recommendedSteps: [
            `Inspect whether invalid or non-existent usernames were tested.`,
            `Enforce Multi-Factor Authentication (MFA) on targeted accounts.`,
            `Check if the source IP matches known proxy/exit-node lists.`,
          ],
          status: 'New',
          occurrences: data.targets.size,
        });
      }
    }
  }

  // C. Success After Repeated Failures
  const compromiseRule = customRules.find((r) => r.id === 'RULE_SUCCESS_AFTER_FAILURE');
  if (compromiseRule?.enabled) {
    for (const seq of suspiciousSequences) {
      alerts.push({
        id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
        timestamp: seq.timestamp,
        severity: 'Critical',
        category: 'Authentication',
        title: `High Priority: Successful Login Following ${seq.failedBeforeSuccess} Failures (${seq.user} @ ${seq.ip})`,
        sourceLog: 'auth / sshd',
        lineReferences: ipAuthFailures.get(seq.ip)?.lines.slice(0, 3) || [],
        evidence: [
          `IP ${seq.ip} incurred ${seq.failedBeforeSuccess} failed login attempts prior to a successful authentication for user '${seq.user}'`,
          `Successful authentication timestamp: ${seq.timestamp}`,
        ],
        ruleExplanation: 'A successful login immediately after repeated authentication failures strongly warrants urgent manual verification to ensure credentials were not compromised.',
        confidence: 'High',
        recommendedSteps: [
          `Contact the account owner ('${seq.user}') immediately to verify legitimate session activity.`,
          `Check session history, authorized keys, and command history on the host.`,
          `If unauthorized, terminate active sessions and reset credentials.`,
        ],
        status: 'New',
        occurrences: seq.failedBeforeSuccess + 1,
      });
    }
  }

  // D. Web Path Traversal / Reconnaissance Probe
  const probeRule = customRules.find((r) => r.id === 'RULE_WEB_DIR_TRAVERSAL_PROBE');
  if (probeRule?.enabled) {
    const probeHits = new Map<string, { paths: string[]; lines: number[] }>();
    for (const e of entries) {
      if (e.http) {
        const pathLower = e.http.path.toLowerCase();
        for (const scanPath of KNOWN_SCANNER_PATHS) {
          if (pathLower.includes(scanPath)) {
            const ip = e.ip || 'unknown';
            if (!probeHits.has(ip)) probeHits.set(ip, { paths: [], lines: [] });
            probeHits.get(ip)!.paths.push(e.http.path);
            probeHits.get(ip)!.lines.push(e.lineNumber);
            break;
          }
        }
      }
    }

    for (const [ip, data] of probeHits.entries()) {
      if (data.paths.length >= probeRule.threshold) {
        alerts.push({
          id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
          timestamp: entries.find((e) => e.lineNumber === data.lines[0])?.timestamp || new Date().toISOString(),
          severity: 'Medium',
          category: 'HTTP Traffic',
          title: `Suspicious Web Probing: ${data.paths.length} Sensitive Paths Tested by ${ip}`,
          sourceLog: 'nginx / apache access',
          lineReferences: data.lines.slice(0, 5),
          evidence: [
            `Probed paths include: ${Array.from(new Set(data.paths)).slice(0, 6).join(', ')}`,
            `Source client IP: ${ip}`,
            `Observed frequency exceeds baseline security probe threshold`,
          ],
          ruleExplanation: 'Automated scanners systematically probe for exposed configuration files (.env), admin consoles (phpmyadmin, wp-login), and actuators.',
          confidence: 'High',
          recommendedSteps: [
            `Confirm that web server configuration blocks direct access to hidden files and return 404/403.`,
            `Verify that no sensitive environment files or admin portals are exposed publicly.`,
            `Consider adding the client IP to your edge WAF / CDN block list.`,
          ],
          status: 'New',
          occurrences: data.paths.length,
        });
      }
    }
  }

  // E. 5xx Surge / Gateway Error
  const surgeRule = customRules.find((r) => r.id === 'RULE_HTTP_5XX_SURGE');
  if (surgeRule?.enabled) {
    let total5xx = 0;
    const lines5xx: number[] = [];
    for (const e of entries) {
      if (e.http && e.http.status >= 500) {
        total5xx++;
        lines5xx.push(e.lineNumber);
      }
    }
    if (total5xx >= surgeRule.threshold) {
      alerts.push({
        id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
        timestamp: new Date().toISOString(),
        severity: 'High',
        category: 'Reliability',
        title: `Service Interruption: ${total5xx} HTTP 5xx Responses Recorded`,
        sourceLog: 'nginx / apache access / error',
        lineReferences: lines5xx.slice(0, 5),
        evidence: [
          `Detected ${total5xx} HTTP server-side errors (500/502/503/504)`,
          `Impacted endpoints include: ${Array.from(error5xxMap.keys()).slice(0, 4).join(', ')}`,
        ],
        ruleExplanation: 'High volumes of 5xx errors signal upstream application crashes, unhandled exceptions, or database connection dropouts.',
        confidence: 'High',
        recommendedSteps: [
          `Check backend application process status (e.g. systemctl status or docker ps).`,
          `Inspect application error logs and traceback exceptions around error timestamps.`,
          `Verify upstream reverse-proxy upstream connection health and socket timeouts.`,
        ],
        status: 'New',
        occurrences: total5xx,
      });
    }
  }

  // F. Database / Resource Exhaustion
  const dbRule = customRules.find((r) => r.id === 'RULE_DB_RESOURCE_EXHAUSTION');
  if (dbRule?.enabled) {
    const oomOrDbLines: { line: number; msg: string; ts: string }[] = [];
    for (const e of entries) {
      const msgUpper = e.message.toUpperCase();
      if (
        msgUpper.includes('CONNECTION POOL EXHAUSTED') ||
        msgUpper.includes('TIMEOUT WAITING FOR CONNECTION') ||
        msgUpper.includes('OUT OF MEMORY') ||
        msgUpper.includes('OOM-KILLER') ||
        msgUpper.includes('CANNOT ASSIGN REQUESTED ADDRESS')
      ) {
        oomOrDbLines.push({ line: e.lineNumber, msg: e.message, ts: e.timestamp });
      }
    }

    if (oomOrDbLines.length >= dbRule.threshold) {
      alerts.push({
        id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
        timestamp: oomOrDbLines[0].ts,
        severity: 'Critical',
        category: 'Reliability',
        title: `Resource Depletion Alert: Database Pool or System Memory Constraint`,
        sourceLog: 'python_app / syslog / kernel',
        lineReferences: oomOrDbLines.map((o) => o.line).slice(0, 5),
        evidence: oomOrDbLines.map((o) => `[Line ${o.line}] ${o.msg}`).slice(0, 4),
        ruleExplanation: 'Database connection saturation or system OOM events halt transaction processing and trigger cascading service failures.',
        confidence: 'High',
        recommendedSteps: [
          `Inspect database max_connections limit and pool configuration.`,
          `Check system RAM utilization and dmesg logs for recent process termination.`,
          `Ensure connection leaks are plugged and transactions are committed/rolled back properly.`,
        ],
        status: 'New',
        occurrences: oomOrDbLines.length,
      });
    }
  }

  // G. Scanner User-Agent Alert
  const uaRule = customRules.find((r) => r.id === 'RULE_SCANNER_USER_AGENT');
  if (uaRule?.enabled && httpStats.scannerUserAgents.length > 0) {
    for (const scanner of httpStats.scannerUserAgents) {
      alerts.push({
        id: `ALT-${String(alertSeq++).padStart(3, '0')}`,
        timestamp: new Date().toISOString(),
        severity: 'Medium',
        category: 'HTTP Traffic',
        title: `Automated Security Scanner Detected: ${scanner.userAgent}`,
        sourceLog: 'nginx_access / apache_access',
        lineReferences: [],
        evidence: [
          `Identified known security tool signature: '${scanner.userAgent}'`,
          `Observed requests: ${scanner.count} from IPs: ${scanner.ips.join(', ')}`,
        ],
        ruleExplanation: 'Identifies non-browser automated vulnerability assessment tools profiling the application.',
        confidence: 'High',
        recommendedSteps: [
          `Review requests made by ${scanner.ips.join(', ')} for potential exploit payloads.`,
          `Confirm whether this scan was an authorized internal penetration test or external probe.`,
        ],
        status: 'New',
        occurrences: scanner.count,
      });
    }
  }

  // 6. Statistical Anomalies
  const anomalies: AnomalyFinding[] = [];
  let anomalySeq = 1;

  // Calculate baseline average error rate across buckets
  if (timeline.length > 3) {
    const errorCounts = timeline.map((t) => t.errors);
    const avg = errorCounts.reduce((a, b) => a + b, 0) / errorCounts.length;
    const stdDev = Math.sqrt(
      errorCounts.map((x) => Math.pow(x - avg, 2)).reduce((a, b) => a + b, 0) / errorCounts.length
    );

    for (const b of timeline) {
      if (stdDev > 0 && b.errors > avg + 2 * stdDev && b.errors >= 3) {
        anomalies.push({
          id: `ANOM-${String(anomalySeq++).padStart(3, '0')}`,
          type: 'Statistical Error Spike',
          severity: 'High',
          description: `Sudden surge of ${b.errors} errors in window ${b.bucket} exceeding baseline.`,
          observedValue: `${b.errors} errors / window`,
          baselineValue: `Mean: ${avg.toFixed(1)} (±${stdDev.toFixed(1)})`,
          evidence: [
            `Error count in bucket ${b.bucket} is ${( (b.errors - avg) / stdDev ).toFixed(1)} standard deviations above baseline`,
            `Total events in bucket: ${b.total}`,
          ],
          timestamp: new Date(b.timestampMs).toISOString(),
          score: Math.min(99, Math.round(((b.errors - avg) / stdDev) * 20)),
        });
      }
    }
  }

  // Auth failure anomaly
  if (authStats.failedAttempts >= 5 && authStats.failureRate > 60) {
    anomalies.push({
      id: `ANOM-${String(anomalySeq++).padStart(3, '0')}`,
      type: 'Abnormal Authentication Failure Rate',
      severity: 'Medium',
      description: `Authentication failure rate is unusually elevated at ${authStats.failureRate}%.`,
      observedValue: `${authStats.failedAttempts} fails (${authStats.failureRate}%)`,
      baselineValue: `< 15% normal failure baseline`,
      evidence: [
        `Total login attempts: ${authStats.totalAttempts}, Failed: ${authStats.failedAttempts}`,
        `Top targeted accounts: ${authStats.topTargetedUsers.map((u) => u.user).slice(0, 3).join(', ')}`,
      ],
      timestamp: new Date().toISOString(),
      score: 75,
    });
  }

  // 7. Incident Correlation Module
  const incidents: CorrelatedIncident[] = [];
  let incSeq = 1;

  // Correlate by IP (if an IP triggered multiple alerts or high auth fails + scans)
  for (const [ip, authData] of ipAuthFailures.entries()) {
    if (authData.count >= 4) {
      const relatedLogs = entries.filter((e) => e.ip === ip);
      incidents.push({
        id: `INC-${String(incSeq++).padStart(3, '0')}`,
        title: `Host Correlation: Distributed Authentication Pressure from ${ip}`,
        severity: authData.count >= 10 ? 'Critical' : 'High',
        correlationKey: `IP:${ip}`,
        correlationType: 'IP_ADDRESS',
        eventCount: relatedLogs.length,
        firstSeen: relatedLogs[0]?.timestamp || new Date().toISOString(),
        lastSeen: relatedLogs[relatedLogs.length - 1]?.timestamp || new Date().toISOString(),
        rationale: `Grouped all authentication events from ${ip} due to ${authData.count} failed attempts targeting ${authData.targets.size} accounts.`,
        eventIds: relatedLogs.map((e) => e.id),
        sampleEvents: relatedLogs.slice(0, 5),
        indicators: [
          `Attacker IP: ${ip}`,
          `Target accounts: ${Array.from(authData.targets).join(', ')}`,
          `Total events correlated: ${relatedLogs.length}`,
        ],
      });
    }
  }

  // Correlate Service Degradation / Cascading Failures
  if (errorGroups.length > 0 && (errorCount >= 4 || criticalCount >= 1)) {
    const serviceErrorLogs = entries.filter((e) => e.level === 'ERROR' || e.level === 'CRITICAL');
    const services = Array.from(new Set(serviceErrorLogs.map((e) => e.service || e.source)));

    incidents.push({
      id: `INC-${String(incSeq++).padStart(3, '0')}`,
      title: `Service Interruption: Cascading Error Cluster Across (${services.join(', ')})`,
      severity: criticalCount > 0 ? 'Critical' : 'High',
      correlationKey: `SERVICE:${services.join('_')}`,
      correlationType: 'SERVICE_FAILURE',
      eventCount: serviceErrorLogs.length,
      firstSeen: serviceErrorLogs[0]?.timestamp || new Date().toISOString(),
      lastSeen: serviceErrorLogs[serviceErrorLogs.length - 1]?.timestamp || new Date().toISOString(),
      rationale: `Correlated ${serviceErrorLogs.length} severe error records across ${services.length} services occurring in the observed timeframe.`,
      eventIds: serviceErrorLogs.map((e) => e.id),
      sampleEvents: serviceErrorLogs.slice(0, 5),
      indicators: [
        `Impacted services: ${services.join(', ')}`,
        `Distinct error patterns: ${errorGroups.length}`,
        `Highest frequency signature: ${errorGroups[0]?.signature || 'N/A'}`,
      ],
    });
  }

  const suspiciousPatternsCount = alerts.length + anomalies.length;

  const summary: AnalysisSummary = {
    totalLines,
    parsedRecords,
    malformedRecords: malformedCount,
    errorCount,
    warnCount,
    criticalCount,
    suspiciousPatternsCount,
    uniqueIps: uniqueIpsSet.size,
    timeRange: {
      start: entries.length > 0 ? entries[0].timestamp : 'N/A',
      end: entries.length > 0 ? entries[entries.length - 1].timestamp : 'N/A',
      durationMinutes,
    },
  };

  return {
    summary,
    alerts,
    anomalies,
    incidents,
    errorGroups,
    authStats,
    httpStats,
    timeline,
    entries,
    detectionRules: customRules,
  };
}
