const crypto = require('crypto');

/**
 * Request ID Generation
 * Centralized function to generate unique request IDs
 */
const generateRequestId = () => {
  return crypto.randomUUID();
};

/**
 * Timestamp Generation
 * Centralized function to generate ISO timestamps
 */
const generateTimestamp = () => {
  return new Date().toISOString();
};

/**
 * Memory Usage Formatter
 * Centralized function to format memory usage consistently
 */
const formatMemoryUsage = (bytes) => {
  return `${Math.round(bytes / 1024 / 1024)}MB`;
};

/**
 * Duration Formatter
 * Centralized function to format durations consistently
 */
const formatDuration = (ms) => {
  if (ms < 1000) {
    return `${ms}ms`;
  } else if (ms < 60000) {
    return `${Math.round(ms / 1000)}s`;
  } else {
    return `${Math.round(ms / 60000)}m`;
  }
};

/**
 * Sanitize Sensitive Data
 * Centralized function to remove sensitive fields from objects
 */
const sanitizeSensitiveData = (data, config) => {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const sensitiveFields = [
    'password',
    'passwordHash',
    'secret',
    'token',
    'refreshToken',
    'apiKey',
    'privateKey',
    'salt',
    'resetToken',
    'verificationToken',
  ];

  const sanitized = JSON.parse(JSON.stringify(data));

  const removeSensitiveFields = (obj) => {
    if (Array.isArray(obj)) {
      return obj.map(removeSensitiveFields);
    }

    if (obj && typeof obj === 'object') {
      const cleaned = {};
      for (const [key, value] of Object.entries(obj)) {
        if (!sensitiveFields.includes(key.toLowerCase())) {
          cleaned[key] = removeSensitiveFields(value);
        }
      }
      return cleaned;
    }

    return obj;
  };

  return config.isProduction() ? removeSensitiveFields(sanitized) : sanitized;
};

/**
 * Request Context Builder
 * Centralized function to build request context objects
 */
const buildRequestContext = (req) => {
  return {
    requestId: req.requestId || generateRequestId(),
    timestamp: generateTimestamp(),
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent') || 'Unknown',
    method: req.method,
    url: req.originalUrl,
    userId: req.user?.id,
    workspaceId: req.workspace?.id,
  };
};

module.exports = {
  generateRequestId,
  generateTimestamp,
  formatMemoryUsage,
  formatDuration,
  sanitizeSensitiveData,
  buildRequestContext,
};
