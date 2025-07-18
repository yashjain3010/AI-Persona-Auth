/**
 * Validation Patterns
 *
 * Centralized validation patterns to maintain DRY principles
 * and provide consistent validation across the application.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

/**
 * SQL Injection Detection Patterns
 */
const SQL_INJECTION_PATTERNS = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
  /(\b(OR|AND)\s+\d+\s*=\s*\d+)/i,
  /(\b(OR|AND)\s+['"]\w+['"]\s*=\s*['"]\w+['"])/i,
  /(-{2}|\/\*|\*\/)/,
  /(\bINTO\s+OUTFILE\b)/i,
  /(\bLOAD_FILE\b)/i,
  /(\bBENCHMARK\b)/i,
  /(\bSLEEP\b)/i,
  /(\bWAITFOR\b)/i,
  /(\bINFORMATION_SCHEMA\b)/i,
  /(\bSYS\b)/i,
  /(\bMYSQL\b)/i,
];

/**
 * XSS Attack Detection Patterns
 */
const XSS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
  /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
  /<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi,
  /<link\b[^<]*(?:(?!<\/link>)<[^<]*)*<\/link>/gi,
  /<meta\b[^<]*(?:(?!<\/meta>)<[^<]*)*<\/meta>/gi,
  /<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi,
  /javascript:/i,
  /vbscript:/i,
  /data:text\/html/i,
  /onload\s*=/i,
  /onerror\s*=/i,
  /onclick\s*=/i,
  /onmouseover\s*=/i,
  /onmouseout\s*=/i,
  /onfocus\s*=/i,
  /onblur\s*=/i,
  /onsubmit\s*=/i,
  /onchange\s*=/i,
];

/**
 * Command Injection Detection Patterns
 */
const COMMAND_INJECTION_PATTERNS = [
  /(\||&|;|\$\(|\`|>|<|\${)/,
  /\b(curl|wget|nc|telnet|ssh|ftp|python|perl|ruby|php|node|bash|sh|cmd|powershell|whoami|ls|dir|cat|type|echo|eval|exec)\b/i,
  /(\bsudo\b|\bsu\b)/i,
  /(\bchmod\b|\bchown\b)/i,
  /(\brm\b|\bdel\b)/i,
  /(\bmkdir\b|\brmdir\b)/i,
  /(\bkill\b|\bkillall\b)/i,
  /(\bps\b|\btop\b)/i,
  /(\bnetstat\b|\bifconfig\b)/i,
];

/**
 * Path Traversal Detection Patterns
 */
const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /\.\.[\/\\].*[\/\\]/,
  /[\/\\]\.\.[\\/]/,
  /\%2e\%2e[\/\\]/i,
  /\%2f\%2e\%2e/i,
  /\%5c\%2e\%2e/i,
  /\%252e\%252e/i,
  /\%c0\%ae\%c0\%ae/i,
  /\%c1\%9c\%c1\%9c/i,
  /\.\.%2f/i,
  /\.\.%5c/i,
];

/**
 * Email Validation Pattern
 */
const EMAIL_PATTERN = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

/**
 * Phone Number Patterns
 */
const PHONE_PATTERNS = {
  US: /^(\+1|1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$/,
  INTERNATIONAL: /^\+?[1-9]\d{1,14}$/,
  BASIC: /^[\+]?[1-9][\d]{0,15}$/,
};

/**
 * URL Validation Pattern
 */
const URL_PATTERN =
  /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$/;

/**
 * UUID Patterns
 */
const UUID_PATTERNS = {
  V4: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  ANY: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
};

/**
 * Password Strength Patterns
 */
const PASSWORD_PATTERNS = {
  WEAK: /^.{6,}$/,
  MEDIUM: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/,
  STRONG: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/,
  VERY_STRONG:
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])(?=.*[^A-Za-z0-9]).{12,}$/,
};

/**
 * Common Input Validation Patterns
 */
const INPUT_PATTERNS = {
  ALPHANUMERIC: /^[a-zA-Z0-9]+$/,
  ALPHANUMERIC_SPACES: /^[a-zA-Z0-9\s]+$/,
  NUMBERS_ONLY: /^[0-9]+$/,
  LETTERS_ONLY: /^[a-zA-Z]+$/,
  SLUG: /^[a-z0-9-]+$/,
  USERNAME: /^[a-zA-Z0-9_-]{3,20}$/,
  HEXADECIMAL: /^[0-9a-fA-F]+$/,
  BASE64: /^[A-Za-z0-9+/]*={0,2}$/,
  JSON: /^[\],:{}\s]*$/,
};

/**
 * Date and Time Patterns
 */
const DATE_PATTERNS = {
  ISO_DATE: /^\d{4}-\d{2}-\d{2}$/,
  ISO_DATETIME:
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$/,
  US_DATE: /^(0[1-9]|1[0-2])\/(0[1-9]|[12][0-9]|3[01])\/\d{4}$/,
  EU_DATE: /^(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[0-2])\/\d{4}$/,
  TIME_24H: /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/,
  TIME_12H: /^(0?[1-9]|1[0-2]):[0-5][0-9]\s?(AM|PM)$/i,
};

/**
 * Credit Card Patterns
 */
const CREDIT_CARD_PATTERNS = {
  VISA: /^4[0-9]{12}(?:[0-9]{3})?$/,
  MASTERCARD: /^5[1-5][0-9]{14}$/,
  AMEX: /^3[47][0-9]{13}$/,
  DISCOVER: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
  GENERIC: /^[0-9]{13,19}$/,
};

/**
 * Security Threat Types
 */
const THREAT_TYPES = {
  SQL_INJECTION: "SQL_INJECTION",
  XSS: "XSS",
  COMMAND_INJECTION: "COMMAND_INJECTION",
  PATH_TRAVERSAL: "PATH_TRAVERSAL",
  INVALID_INPUT: "INVALID_INPUT",
  MALICIOUS_CONTENT: "MALICIOUS_CONTENT",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  SUSPICIOUS_ACTIVITY: "SUSPICIOUS_ACTIVITY",
};

/**
 * Validation Severity Levels
 */
const VALIDATION_SEVERITY = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

/**
 * Validation Result Types
 */
const VALIDATION_RESULT = {
  VALID: "valid",
  INVALID: "invalid",
  THREAT: "threat",
  WARNING: "warning",
};

/**
 * Common Field Length Limits
 */
const FIELD_LIMITS = {
  NAME: { min: 1, max: 100 },
  EMAIL: { min: 5, max: 254 },
  PASSWORD: { min: 8, max: 128 },
  USERNAME: { min: 3, max: 20 },
  DESCRIPTION: { min: 0, max: 2000 },
  TITLE: { min: 1, max: 200 },
  URL: { min: 1, max: 2048 },
  PHONE: { min: 10, max: 15 },
  CODE: { min: 4, max: 10 },
};

module.exports = {
  // Security Patterns
  SQL_INJECTION_PATTERNS,
  XSS_PATTERNS,
  COMMAND_INJECTION_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,

  // Input Validation Patterns
  EMAIL_PATTERN,
  PHONE_PATTERNS,
  URL_PATTERN,
  UUID_PATTERNS,
  PASSWORD_PATTERNS,
  INPUT_PATTERNS,
  DATE_PATTERNS,
  CREDIT_CARD_PATTERNS,

  // Constants
  THREAT_TYPES,
  VALIDATION_SEVERITY,
  VALIDATION_RESULT,
  FIELD_LIMITS,
};
