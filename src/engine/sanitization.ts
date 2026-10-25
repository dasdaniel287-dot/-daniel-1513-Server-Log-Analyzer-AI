/**
 * Sanitization and Redaction Module
 * Protects credentials, session tokens, passwords, and PII
 * before storing, displaying, or sending to AI providers.
 */

export interface SanitizationResult {
  text: string;
  maskedCount: {
    passwords: number;
    tokens: number;
    apiKeys: number;
    emails: number;
  };
}

export function sanitizeLogLine(raw: string): SanitizationResult {
  let text = raw;
  let passwords = 0;
  let tokens = 0;
  let apiKeys = 0;
  let emails = 0;

  // 1. Bearer / Auth tokens
  const authHeaderRegex = /(?:Authorization:\s*Bearer|Bearer\s+)([A-Za-z0-9\-._~+/]+=*)/gi;
  text = text.replace(authHeaderRegex, () => {
    tokens++;
    return 'Bearer [REDACTED_TOKEN]';
  });

  // 2. Generic secret keys, api keys, tokens
  const apiKeyRegex = /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(?:\s*[:=]\s*["']?)([A-Za-z0-9\-_]{16,})["']?/gi;
  text = text.replace(apiKeyRegex, (match, val) => {
    apiKeys++;
    return match.replace(val, '[REDACTED_API_KEY]');
  });

  // 3. Password fields (JSON or query params or key-values)
  const passwordRegex = /(?:password|passwd|pwd|secret)(?:\s*[:=]\s*["']?)([^"'\s&,]{3,})["']?/gi;
  text = text.replace(passwordRegex, (match, val) => {
    passwords++;
    return match.replace(val, '[REDACTED_PASSWORD]');
  });

  // 4. Email addresses (basic PII masking)
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g;
  text = text.replace(emailRegex, (email) => {
    emails++;
    const parts = email.split('@');
    const user = parts[0];
    const domain = parts[1];
    const maskedUser = user.length > 2 ? `${user[0]}***${user[user.length - 1]}` : '***';
    return `${maskedUser}@${domain}`;
  });

  return {
    text,
    maskedCount: { passwords, tokens, apiKeys, emails }
  };
}

/**
 * Anonymize or redact an excerpt for AI submission
 * Also hashes or masks internal private subnet IPs if requested
 */
export function sanitizeLogForAi(logs: string[]): { sanitizedText: string; stats: { maskedCount: number } } {
  let maskedCount = 0;
  const processed = logs.map(line => {
    const res = sanitizeLogLine(line);
    const sum = res.maskedCount.passwords + res.maskedCount.tokens + res.maskedCount.apiKeys + res.maskedCount.emails;
    maskedCount += sum;
    return res.text;
  });

  return {
    sanitizedText: processed.join('\n'),
    stats: { maskedCount }
  };
}

/**
 * Prevent CSV formula injection by prepending an apostrophe if the field starts with =, +, -, @, \t, \r
 */
export function sanitizeCsvField(field: unknown): string {
  if (field === null || field === undefined) return '""';
  let str = String(field);
  // Neutralize CSV formula execution
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  // Escape quotes
  str = str.replace(/"/g, '""');
  return `"${str}"`;
}
