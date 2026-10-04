const SECRET_PATTERNS = [
  [/\bsk-(?:or-v1-)?[A-Za-z0-9_-]{20,}\b/g, 'api-key'],
  [/\bsk_[A-Za-z0-9_-]{20,}\b/g, 'api-key'],
  [/\bAIza[0-9A-Za-z_-]{25,}\b/g, 'google-key'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, 'jwt'],
  [/\b\d{7,}:[A-Za-z0-9_-]{25,}\b/g, 'bot-token'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/gi, 'bearer-token'],
  [/\b(?:TG_)?API_HASH\b[\s\S]{0,256}?\b[a-f0-9]{32}\b/gi, 'telegram-api-hash'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, 'private-key'],
];

function sanitizeForMemory(value) {
  let text = String(value || '');
  const findings = [];
  for (const [pattern, type] of SECRET_PATTERNS) {
    text = text.replace(pattern, (match) => {
      findings.push({ type, length: match.length });
      return `[REDACTED:${type}]`;
    });
  }
  text = text.replace(/("(?:apiKey|api_key|secret|token|accessToken|refreshToken|authorization)"\s*:\s*")([^"\r\n]{8,})(")/gi,
    (_, prefix, secret, suffix) => {
      if (secret.startsWith('[REDACTED:')) return `${prefix}${secret}${suffix}`;
      findings.push({ type: 'secret-field', length: secret.length });
      return `${prefix}[REDACTED:secret-field]${suffix}`;
    });
  text = text.replace(/\b([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*)([^\s"'`]{8,})/g,
    (_, prefix, secret) => {
      if (secret.startsWith('[REDACTED:')) return `${prefix}${secret}`;
      findings.push({ type: 'secret-assignment', length: secret.length });
      return `${prefix}[REDACTED:secret-assignment]`;
    });
  return { text, findings, redactions: findings.length };
}

module.exports = { sanitizeForMemory };
