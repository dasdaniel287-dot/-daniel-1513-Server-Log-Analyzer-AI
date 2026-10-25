/**
 * Server Log Analyzer AI - Core Type Definitions
 * Defensive Cybersecurity, SRE & Incident Investigation
 */

export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL' | 'DEBUG' | 'UNKNOWN';

export type LogSource = 
  | 'syslog' 
  | 'auth' 
  | 'nginx_access' 
  | 'nginx_error' 
  | 'apache_access' 
  | 'apache_error' 
  | 'python_app' 
  | 'json' 
  | 'windows_event' 
  | 'custom';

export type AlertSeverity = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export type AlertStatus = 'New' | 'Investigating' | 'Resolved' | 'False Positive';

export interface HttpDetails {
  method: string;
  path: string;
  status: number;
  bytes?: number;
  userAgent?: string;
  referer?: string;
}

export interface AuthDetails {
  user?: string;
  status: 'SUCCESS' | 'FAILURE' | 'DISCONNECT';
  method?: string;
  port?: number;
}

export interface LogEntry {
  id: string;
  lineNumber: number;
  raw: string;
  sanitized: string;
  timestamp: string;
  timestampMs: number;
  level: LogLevel;
  source: LogSource;
  hostname?: string;
  service?: string;
  pid?: number;
  message: string;
  ip?: string;
  http?: HttpDetails;
  auth?: AuthDetails;
  exceptionClass?: string;
  stackTrace?: string;
  isMalformed?: boolean;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: AlertSeverity;
  category: string;
  title: string;
  sourceLog: string;
  lineReferences: number[];
  evidence: string[];
  ruleExplanation: string;
  confidence: 'High' | 'Medium' | 'Low';
  recommendedSteps: string[];
  status: AlertStatus;
  occurrences: number;
}

export interface AnomalyFinding {
  id: string;
  type: string;
  severity: AlertSeverity;
  description: string;
  observedValue: string;
  baselineValue: string;
  evidence: string[];
  timestamp: string;
  score: number;
}

export interface CorrelatedIncident {
  id: string;
  title: string;
  severity: AlertSeverity;
  correlationKey: string;
  correlationType: 'IP_ADDRESS' | 'SERVICE_FAILURE' | 'TIME_WINDOW' | 'TARGET_ACCOUNT';
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  rationale: string;
  eventIds: string[];
  sampleEvents: LogEntry[];
  indicators: string[];
}

export interface ErrorGroup {
  id: string;
  signature: string;
  service: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  sampleMessage: string;
  stackTrace?: string;
  level: LogLevel;
}

export interface AuthStatistics {
  totalAttempts: number;
  failedAttempts: number;
  successfulLogins: number;
  failureRate: number;
  topTargetedUsers: { user: string; failures: number; successes: number }[];
  topFailedIps: { ip: string; count: number; targets: string[] }[];
  suspiciousSequences: {
    ip: string;
    user: string;
    failedBeforeSuccess: number;
    timestamp: string;
  }[];
}

export interface HttpStatistics {
  totalRequests: number;
  statusDistribution: Record<string, number>;
  top4xxPaths: { path: string; count: number; ips: string[] }[];
  top5xxErrors: { path: string; count: number; status: number }[];
  scannerUserAgents: { userAgent: string; count: number; ips: string[] }[];
  topTalkerIps: { ip: string; count: number; errorRate: number }[];
}

export interface TimelineBucket {
  bucket: string;
  timestampMs: number;
  total: number;
  errors: number;
  authFailures: number;
  warnings: number;
  http4xx: number;
  http5xx: number;
}

export interface DetectionRuleConfig {
  id: string;
  name: string;
  category: string;
  enabled: boolean;
  threshold: number;
  windowMinutes: number;
  description: string;
}

export interface AnalysisSummary {
  totalLines: number;
  parsedRecords: number;
  malformedRecords: number;
  errorCount: number;
  warnCount: number;
  criticalCount: number;
  suspiciousPatternsCount: number;
  uniqueIps: number;
  timeRange: {
    start: string;
    end: string;
    durationMinutes: number;
  };
}

export interface AnalysisResult {
  summary: AnalysisSummary;
  alerts: SecurityAlert[];
  anomalies: AnomalyFinding[];
  incidents: CorrelatedIncident[];
  errorGroups: ErrorGroup[];
  authStats: AuthStatistics;
  httpStats: HttpStatistics;
  timeline: TimelineBucket[];
  entries: LogEntry[];
  detectionRules: DetectionRuleConfig[];
}

export interface AiInvestigationResponse {
  assessment: string;
  rootCauseAnalysis: string;
  safeRemediationSteps: string[];
  additionalLogsToReview: string[];
  executiveSummary: string;
  sanitizationReport: {
    maskedIpsCount: number;
    maskedCredentialsCount: number;
    maskedTokensCount: number;
  };
  provider: 'Gemini-3.8-Flash' | 'Local-Rule-Based-Engine';
  timestamp: string;
}
