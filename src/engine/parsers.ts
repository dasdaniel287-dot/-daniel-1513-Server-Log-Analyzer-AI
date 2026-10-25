/**
 * Modular Log Parsers
 * Supports: Syslog, Auth/SSH, Nginx Access/Error, Apache, Python App, JSON, Windows Events
 */

import { HttpDetails, LogEntry, LogLevel, LogSource } from '../types/log';
import { sanitizeLogLine } from './sanitization';

// Helper to normalize timestamp to ISO string and milliseconds
export function parseTimestamp(dateStr: string): { iso: string; ms: number } {
  try {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) {
      return { iso: d.toISOString(), ms: d.getTime() };
    }
  } catch {
    // continue
  }

  // Handle syslog format: "Oct 25 14:32:10"
  const syslogMatch = dateStr.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/);
  if (syslogMatch) {
    const currentYear = 2026;
    const constructed = `${syslogMatch[1]} ${syslogMatch[2]} ${currentYear} ${syslogMatch[3]} UTC`;
    const d = new Date(constructed);
    if (!isNaN(d.getTime())) {
      return { iso: d.toISOString(), ms: d.getTime() };
    }
  }

  // Handle Nginx format: "25/Oct/2026:14:32:10 +0000"
  const nginxMatch = dateStr.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})\s+([+-]\d{4})$/);
  if (nginxMatch) {
    const constructed = `${nginxMatch[2]} ${nginxMatch[1]}, ${nginxMatch[3]} ${nginxMatch[4]} GMT${nginxMatch[5]}`;
    const d = new Date(constructed);
    if (!isNaN(d.getTime())) {
      return { iso: d.toISOString(), ms: d.getTime() };
    }
  }

  // Fallback to now
  const now = Date.now();
  return { iso: new Date(now).toISOString(), ms: now };
}

// Level detection from text
export function detectLogLevel(text: string, httpStatus?: number): LogLevel {
  const upper = text.toUpperCase();
  if (httpStatus && httpStatus >= 500) return 'CRITICAL';
  if (httpStatus && httpStatus >= 400) return 'WARN';

  if (/\b(CRITICAL|FATAL|PANIC|ALERT|EMERGENCY|OOM|KERNEL PANIC)\b/.test(upper)) return 'CRITICAL';
  if (/\b(ERROR|ERR|EXCEPTION|TRACEBACK|FAIL|FAILED|FAILURE)\b/.test(upper)) return 'ERROR';
  if (/\b(WARN|WARNING)\b/.test(upper)) return 'WARN';
  if (/\b(DEBUG)\b/.test(upper)) return 'DEBUG';
  return 'INFO';
}

// 1. SSH / Auth Parser
export function parseAuthLog(line: string, lineNumber: number): LogEntry | null {
  // Oct 25 14:32:10 host sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 52312 ssh2
  // Oct 25 14:32:11 host sshd[12345]: Accepted publickey for ubuntu from 203.0.113.15 port 44321 ssh2: RSA ...
  const regex = /^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s+(.*)$/;
  const match = line.match(regex);
  if (!match) return null;

  const [, rawDate, hostname, service, rawPid, message] = match;
  if (!service.includes('ssh') && !service.includes('sudo') && !service.includes('login') && !service.includes('auth') && !service.includes('pam')) {
    return null; // Not an auth log
  }

  const { iso, ms } = parseTimestamp(rawDate);
  const sanitizedRes = sanitizeLogLine(line);

  let authStatus: 'SUCCESS' | 'FAILURE' | 'DISCONNECT' = 'SUCCESS';
  let user: string | undefined;
  let ip: string | undefined;
  let port: number | undefined;

  const failedMatch = message.match(/Failed (?:password|publickey) for (?:invalid user\s+)?(\w+)\s+from\s+([\d\.:a-fA-F]+)\s+port\s+(\d+)/i);
  if (failedMatch) {
    authStatus = 'FAILURE';
    user = failedMatch[1];
    ip = failedMatch[2];
    port = parseInt(failedMatch[3], 10);
  } else {
    const acceptedMatch = message.match(/Accepted (?:password|publickey) for (\w+)\s+from\s+([\d\.:a-fA-F]+)\s+port\s+(\d+)/i);
    if (acceptedMatch) {
      authStatus = 'SUCCESS';
      user = acceptedMatch[1];
      ip = acceptedMatch[2];
      port = parseInt(acceptedMatch[3], 10);
    } else if (message.includes('Disconnected') || message.includes('Connection closed')) {
      authStatus = 'DISCONNECT';
      const ipMatch = message.match(/from ([\d\.:a-fA-F]+)/);
      if (ipMatch) ip = ipMatch[1];
    }
  }

  const level: LogLevel = authStatus === 'FAILURE' ? 'WARN' : 'INFO';

  return {
    id: `auth-${lineNumber}-${ms}`,
    lineNumber,
    raw: line,
    sanitized: sanitizedRes.text,
    timestamp: iso,
    timestampMs: ms,
    level,
    source: 'auth',
    hostname,
    service,
    pid: rawPid ? parseInt(rawPid, 10) : undefined,
    message,
    ip,
    auth: {
      user,
      status: authStatus,
      port,
      method: message.includes('publickey') ? 'publickey' : 'password',
    },
  };
}

// 2. Nginx / Apache Combined Access Parser
export function parseHttpAccessLog(line: string, lineNumber: number, source: 'nginx_access' | 'apache_access'): LogEntry | null {
  // 198.51.100.42 - - [25/Oct/2026:14:32:10 +0000] "GET /api/v1/users HTTP/1.1" 200 1243 "https://example.com" "Mozilla/5.0..."
  const regex = /^([\d\.:a-fA-F]+)\s+[\w\-]+\s+([\w\-]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  const match = line.match(regex);
  if (!match) return null;

  const [, ip, authUser, rawDate, method, path, , statusStr, bytesStr, referer, userAgent] = match;
  const status = parseInt(statusStr, 10);
  const bytes = bytesStr !== '-' ? parseInt(bytesStr, 10) : 0;
  const { iso, ms } = parseTimestamp(rawDate);
  const sanitizedRes = sanitizeLogLine(line);

  const level = detectLogLevel(line, status);

  return {
    id: `http-${lineNumber}-${ms}`,
    lineNumber,
    raw: line,
    sanitized: sanitizedRes.text,
    timestamp: iso,
    timestampMs: ms,
    level,
    source,
    message: `${method} ${path} -> ${status} (${bytes}B)`,
    ip,
    http: {
      method,
      path,
      status,
      bytes,
      userAgent: userAgent || undefined,
      referer: referer !== '-' ? referer : undefined,
    },
    auth: authUser !== '-' ? { user: authUser, status: 'SUCCESS' } : undefined,
  };
}

// 3. Nginx / Apache Error Log Parser
export function parseHttpErrorLog(line: string, lineNumber: number, source: 'nginx_error' | 'apache_error'): LogEntry | null {
  // 2026/10/25 14:32:10 [error] 1234#0: *57 open() "/usr/share/nginx/html/wp-login.php" failed (2: No such file or directory), client: 198.51.100.42, server: localhost, request: "GET /wp-login.php HTTP/1.1", host: "example.com"
  const nginxRegex = /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[([a-z]+)\]\s+(\d+)#\d+:\s+(.*)$/;
  const match = line.match(nginxRegex);
  if (match) {
    const [, rawDate, rawLevel, pid, message] = match;
    const { iso, ms } = parseTimestamp(rawDate.replace(/\//g, '-'));
    const sanitizedRes = sanitizeLogLine(line);

    const clientIpMatch = message.match(/client:\s+([\d\.:a-fA-F]+)/);
    const requestMatch = message.match(/request:\s+"([A-Z]+)\s+([^\s]+)/);

    let level: LogLevel = 'ERROR';
    if (rawLevel === 'warn') level = 'WARN';
    if (rawLevel === 'crit' || rawLevel === 'alert' || rawLevel === 'emerg') level = 'CRITICAL';

    return {
      id: `http-err-${lineNumber}-${ms}`,
      lineNumber,
      raw: line,
      sanitized: sanitizedRes.text,
      timestamp: iso,
      timestampMs: ms,
      level,
      source,
      service: 'nginx',
      pid: parseInt(pid, 10),
      message,
      ip: clientIpMatch ? clientIpMatch[1] : undefined,
      http: requestMatch ? { method: requestMatch[1], path: requestMatch[2], status: 500 } : undefined,
    };
  }

  return null;
}

// 4. JSON Log Parser
export function parseJsonLog(line: string, lineNumber: number): LogEntry | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return null;

  try {
    const obj = JSON.parse(trimmed);
    const sanitizedRes = sanitizeLogLine(line);
    const rawDate = obj.time || obj.timestamp || obj['@timestamp'] || obj.date || obj.datetime || '';
    const { iso, ms } = parseTimestamp(String(rawDate));

    const rawLevel = String(obj.level || obj.severity || obj.status || 'INFO').toUpperCase();
    let level: LogLevel = 'INFO';
    if (rawLevel.includes('CRIT') || rawLevel.includes('FATAL')) level = 'CRITICAL';
    else if (rawLevel.includes('ERR')) level = 'ERROR';
    else if (rawLevel.includes('WARN')) level = 'WARN';
    else if (rawLevel.includes('DEBUG')) level = 'DEBUG';

    const message = obj.message || obj.msg || obj.log || obj.event || JSON.stringify(obj);
    const ip = obj.ip || obj.client_ip || obj.remote_addr || (obj.req && obj.req.ip);

    let http: HttpDetails | undefined;
    if (obj.http || obj.req || obj.status_code || obj.status) {
      const status = Number(obj.status || obj.status_code || (obj.res && obj.res.statusCode) || 200);
      http = {
        method: obj.method || (obj.req && obj.req.method) || 'GET',
        path: obj.path || obj.url || (obj.req && obj.req.url) || '/',
        status,
        userAgent: obj.userAgent || (obj.req && obj.req.headers && obj.req.headers['user-agent']),
      };
    }

    return {
      id: `json-${lineNumber}-${ms}`,
      lineNumber,
      raw: line,
      sanitized: sanitizedRes.text,
      timestamp: iso,
      timestampMs: ms,
      level,
      source: 'json',
      hostname: obj.host || obj.hostname,
      service: obj.service || obj.app || obj.name,
      message: String(message),
      ip,
      http,
      exceptionClass: obj.error?.name || obj.exception,
      stackTrace: obj.error?.stack || obj.stack_trace,
    };
  } catch {
    return null;
  }
}

// 5. Python Application Log Parser
export function parsePythonAppLog(line: string, lineNumber: number): LogEntry | null {
  // 2026-10-25 14:32:10,123 [ERROR] [app.database] Connection pool exhausted: timeout waiting for connection
  // 2026-10-25 14:32:10 INFO [uvicorn.access] 198.51.100.42:54212 - "POST /api/v1/auth HTTP/1.1" 401
  const pyRegex = /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+(?:\[?([A-Z]+)\]?)\s+(?:\[?([\w\.\-]+)\]?)?:?\s+(.*)$/;
  const match = line.match(pyRegex);
  if (!match) return null;

  const [, rawDate, levelStr, service, message] = match;
  const { iso, ms } = parseTimestamp(rawDate.replace(',', '.'));
  const sanitizedRes = sanitizeLogLine(line);
  const level = detectLogLevel(levelStr);

  const ipMatch = message.match(/([\d\.:a-fA-F]+)(?::\d+)?\s+-\s+"([A-Z]+)\s+([^\s]+)\s+HTTP/);
  let http: HttpDetails | undefined;
  let ip: string | undefined;

  if (ipMatch) {
    ip = ipMatch[1];
    const statusMatch = message.match(/HTTP\/[\d\.]+"\s+(\d{3})/);
    http = {
      method: ipMatch[2],
      path: ipMatch[3],
      status: statusMatch ? parseInt(statusMatch[1], 10) : 200,
    };
  } else {
    const rawIp = message.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (rawIp) ip = rawIp[0];
  }

  let exceptionClass: string | undefined;
  const excMatch = message.match(/([A-Z][a-zA-Z0-9]+(?:Error|Exception|Warning)):/);
  if (excMatch) {
    exceptionClass = excMatch[1];
  }

  return {
    id: `py-${lineNumber}-${ms}`,
    lineNumber,
    raw: line,
    sanitized: sanitizedRes.text,
    timestamp: iso,
    timestampMs: ms,
    level,
    source: 'python_app',
    service: service || 'python_service',
    message,
    ip,
    http,
    exceptionClass,
  };
}

// 6. Syslog Standard (RFC 3164 / RFC 5424) Parser
export function parseSyslog(line: string, lineNumber: number): LogEntry | null {
  // Oct 25 14:32:10 web01 kernel: [ 1042.441] Out of memory: Kill process 1234 (node) score 850
  // 2026-10-25T14:32:10.123Z web01 systemd[1]: Started Daily apt upgrade and clean activities.
  const rfc3164 = /^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:?\s+(.*)$/;
  const rfc5424 = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:?\s+(.*)$/;

  let match = line.match(rfc3164);
  let rawDate = '';
  let hostname = '';
  let service = '';
  let rawPid: string | undefined;
  let message = '';

  if (match) {
    [, rawDate, hostname, service, rawPid, message] = match;
  } else {
    match = line.match(rfc5424);
    if (match) {
      [, rawDate, hostname, service, rawPid, message] = match;
    } else {
      return null;
    }
  }

  const { iso, ms } = parseTimestamp(rawDate);
  const sanitizedRes = sanitizeLogLine(line);
  const level = detectLogLevel(message);

  const ipMatch = message.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);

  return {
    id: `sys-${lineNumber}-${ms}`,
    lineNumber,
    raw: line,
    sanitized: sanitizedRes.text,
    timestamp: iso,
    timestampMs: ms,
    level,
    source: 'syslog',
    hostname,
    service,
    pid: rawPid ? parseInt(rawPid, 10) : undefined,
    message,
    ip: ipMatch ? ipMatch[0] : undefined,
  };
}

// 7. Generic Fallback Parser
export function parseGenericLog(line: string, lineNumber: number): LogEntry {
  const sanitizedRes = sanitizeLogLine(line);
  const level = detectLogLevel(line);

  // Attempt to extract timestamp
  const dateMatch = line.match(/(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
  const rawDate = dateMatch ? dateMatch[1] : '';
  const { iso, ms } = parseTimestamp(rawDate);

  const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);

  return {
    id: `gen-${lineNumber}-${ms}`,
    lineNumber,
    raw: line,
    sanitized: sanitizedRes.text,
    timestamp: iso,
    timestampMs: ms,
    level,
    source: 'custom',
    message: line.trim(),
    ip: ipMatch ? ipMatch[0] : undefined,
  };
}

/**
 * Master Ingestion & Dispatcher:
 * Tries parsers sequentially by specificity.
 */
export function parseLogLine(line: string, lineNumber: number): LogEntry {
  const trimmed = line.trim();
  if (!trimmed) {
    return {
      id: `empty-${lineNumber}`,
      lineNumber,
      raw: line,
      sanitized: '',
      timestamp: new Date().toISOString(),
      timestampMs: Date.now(),
      level: 'INFO',
      source: 'custom',
      message: '',
      isMalformed: true,
    };
  }

  // 1. JSON
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    const jsonParsed = parseJsonLog(line, lineNumber);
    if (jsonParsed) return jsonParsed;
  }

  // 2. Auth / SSH
  const authParsed = parseAuthLog(line, lineNumber);
  if (authParsed) return authParsed;

  // 3. HTTP Access (Nginx or Apache)
  const httpAccessParsed = parseHttpAccessLog(line, lineNumber, 'nginx_access');
  if (httpAccessParsed) return httpAccessParsed;

  // 4. HTTP Error
  const httpErrorParsed = parseHttpErrorLog(line, lineNumber, 'nginx_error');
  if (httpErrorParsed) return httpErrorParsed;

  // 5. Python App
  const pyParsed = parsePythonAppLog(line, lineNumber);
  if (pyParsed) return pyParsed;

  // 6. Syslog standard
  const syslogParsed = parseSyslog(line, lineNumber);
  if (syslogParsed) return syslogParsed;

  // 7. Fallback
  return parseGenericLog(line, lineNumber);
}
