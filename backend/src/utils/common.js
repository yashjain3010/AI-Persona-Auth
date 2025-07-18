/**
 * Common Utilities
 *
 * This module provides shared utilities and patterns to eliminate code duplication
 * and maintain DRY principles across the application.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const crypto = require("crypto");

/**
 * Request ID Generation
 * Centralized function to generate unique request IDs
 */
const generateRequestId = () => {
  return crypto.randomUUID();
};

/**
 * Response ID Generation
 * Centralized function to generate unique response IDs
 */
const generateResponseId = () => {
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
  if (!data || typeof data !== "object") {
    return data;
  }

  const sensitiveFields = [
    "password",
    "passwordHash",
    "secret",
    "token",
    "refreshToken",
    "apiKey",
    "privateKey",
    "salt",
    "resetToken",
    "verificationToken",
  ];

  const sanitized = JSON.parse(JSON.stringify(data));

  const removeSensitiveFields = (obj) => {
    if (Array.isArray(obj)) {
      return obj.map(removeSensitiveFields);
    }

    if (obj && typeof obj === "object") {
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
    userAgent: req.get("User-Agent") || "Unknown",
    method: req.method,
    url: req.originalUrl,
    userId: req.user?.id,
    workspaceId: req.workspace?.id,
  };
};

/**
 * Performance Timer Class
 * Centralized performance timing utility
 */
class PerformanceTimer {
  constructor() {
    this.startTime = Date.now();
    this.startMemory = process.memoryUsage().heapUsed;
  }

  /**
   * Get elapsed time and memory usage
   * @returns {Object} Performance metrics
   */
  getMetrics() {
    const executionTime = Date.now() - this.startTime;
    const memoryUsed = process.memoryUsage().heapUsed - this.startMemory;

    return {
      executionTime,
      memoryUsed,
      formattedExecutionTime: formatDuration(executionTime),
      formattedMemoryUsed:
        memoryUsed > 0 ? formatMemoryUsage(memoryUsed) : "N/A",
    };
  }

  /**
   * Get elapsed time in milliseconds
   * @returns {number} Elapsed time in ms
   */
  getElapsedTime() {
    return Date.now() - this.startTime;
  }

  /**
   * Get memory usage in bytes
   * @returns {number} Memory usage in bytes
   */
  getMemoryUsage() {
    return process.memoryUsage().heapUsed - this.startMemory;
  }

  /**
   * Reset timer
   */
  reset() {
    this.startTime = Date.now();
    this.startMemory = process.memoryUsage().heapUsed;
  }
}

/**
 * Create a new performance timer
 * @returns {PerformanceTimer} Timer instance
 */
const createPerformanceTimer = () => {
  return new PerformanceTimer();
};

/**
 * Performance Metrics Calculator (backward compatibility)
 * Centralized function to calculate performance metrics
 */
const calculatePerformanceMetrics = (startTime, startMemory = 0) => {
  const executionTime = Date.now() - startTime;
  const memoryUsed =
    startMemory > 0 ? process.memoryUsage().heapUsed - startMemory : 0;

  return {
    executionTime,
    memoryUsed,
    formattedExecutionTime: formatDuration(executionTime),
    formattedMemoryUsed: memoryUsed > 0 ? formatMemoryUsage(memoryUsed) : "N/A",
  };
};

/**
 * Error Context Builder
 * Centralized function to build error context objects
 */
const buildErrorContext = (error, req, additionalContext = {}) => {
  const requestContext = buildRequestContext(req);

  return {
    ...requestContext,
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code,
      statusCode: error.statusCode,
    },
    timestamp: generateTimestamp(),
    ...additionalContext,
  };
};

/**
 * Health Check Data Builder
 * Centralized function to build health check data
 */
const buildHealthCheckData = (additionalData = {}) => {
  return {
    timestamp: generateTimestamp(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    pid: process.pid,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || "development",
    ...additionalData,
  };
};

/**
 * Validation Helpers
 * Centralized validation functions using patterns from validation module
 */
const validation = {
  isValidEmail: (email) => {
    const { EMAIL_PATTERN } = require("../validations/patterns");
    return EMAIL_PATTERN.test(email);
  },

  isValidUUID: (uuid) => {
    const { UUID_PATTERNS } = require("../validations/patterns");
    return UUID_PATTERNS.ANY.test(uuid);
  },

  isValidPort: (port) => {
    const portNum = parseInt(port, 10);
    return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
  },

  isValidUrl: (url) => {
    const { URL_PATTERN } = require("../validations/patterns");
    return URL_PATTERN.test(url);
  },
};

/**
 * Async Utilities
 * Centralized async helper functions
 */
const asyncUtils = {
  delay: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),

  timeout: (promise, ms) => {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Operation timed out")), ms)
      ),
    ]);
  },

  retry: async (fn, retries = 3, delay = 1000) => {
    for (let i = 0; i < retries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === retries - 1) throw error;
        await asyncUtils.delay(delay * Math.pow(2, i)); // Exponential backoff
      }
    }
  },
};

/**
 * Object Utilities
 * Centralized object manipulation functions
 */
const objectUtils = {
  deepClone: (obj) => {
    return JSON.parse(JSON.stringify(obj));
  },

  pick: (obj, keys) => {
    return keys.reduce((result, key) => {
      if (key in obj) {
        result[key] = obj[key];
      }
      return result;
    }, {});
  },

  omit: (obj, keys) => {
    return Object.keys(obj).reduce((result, key) => {
      if (!keys.includes(key)) {
        result[key] = obj[key];
      }
      return result;
    }, {});
  },

  isEmpty: (obj) => {
    return Object.keys(obj).length === 0;
  },

  flatten: (obj, prefix = "") => {
    let result = {};
    for (const key in obj) {
      const newKey = prefix ? `${prefix}.${key}` : key;
      if (
        typeof obj[key] === "object" &&
        obj[key] !== null &&
        !Array.isArray(obj[key])
      ) {
        result = { ...result, ...objectUtils.flatten(obj[key], newKey) };
      } else {
        result[newKey] = obj[key];
      }
    }
    return result;
  },
};

module.exports = {
  // ID Generation
  generateRequestId,
  generateResponseId,
  generateTimestamp,

  // Formatters
  formatMemoryUsage,
  formatDuration,
  sanitizeSensitiveData,

  // Builders
  buildRequestContext,
  buildErrorContext,
  buildHealthCheckData,
  calculatePerformanceMetrics,

  // Performance
  PerformanceTimer,
  createPerformanceTimer,

  // Validation
  validation,

  // Async Utilities
  asyncUtils,

  // Object Utilities
  objectUtils,
};
