/**
 * Security Validation Module
 *
 * This module provides comprehensive security validation functionality
 * to detect and prevent common security threats including SQL injection,
 * XSS attacks, command injection, and path traversal.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  SQL_INJECTION_PATTERNS,
  XSS_PATTERNS,
  COMMAND_INJECTION_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  THREAT_TYPES,
  VALIDATION_SEVERITY,
  VALIDATION_RESULT,
} = require("./patterns");

const logger = require("../utils/logger");
const { generateTimestamp, sanitizeSensitiveData } = require("../utils/common");

/**
 * Security Validator Class
 * Handles all security validation with comprehensive threat detection
 */
class SecurityValidator {
  constructor() {
    this.threatMetrics = {
      sqlInjectionAttempts: 0,
      xssAttempts: 0,
      commandInjectionAttempts: 0,
      pathTraversalAttempts: 0,
      totalThreats: 0,
      lastReset: generateTimestamp(),
    };

    this.threatHistory = [];
    this.maxHistorySize = 1000;
  }

  /**
   * Check for SQL injection threats
   * @param {string} value - Value to validate
   * @returns {boolean} Whether threat is detected
   */
  checkSQLInjection(value) {
    if (typeof value !== "string") return false;

    const isThreat = SQL_INJECTION_PATTERNS.some((pattern) =>
      pattern.test(value)
    );

    if (isThreat) {
      this.threatMetrics.sqlInjectionAttempts++;
      this.threatMetrics.totalThreats++;
      this._recordThreat(THREAT_TYPES.SQL_INJECTION, value);
    }

    return isThreat;
  }

  /**
   * Check for XSS threats
   * @param {string} value - Value to validate
   * @returns {boolean} Whether threat is detected
   */
  checkXSS(value) {
    if (typeof value !== "string") return false;

    const isThreat = XSS_PATTERNS.some((pattern) => pattern.test(value));

    if (isThreat) {
      this.threatMetrics.xssAttempts++;
      this.threatMetrics.totalThreats++;
      this._recordThreat(THREAT_TYPES.XSS, value);
    }

    return isThreat;
  }

  /**
   * Check for command injection threats
   * @param {string} value - Value to validate
   * @returns {boolean} Whether threat is detected
   */
  checkCommandInjection(value) {
    if (typeof value !== "string") return false;

    const isThreat = COMMAND_INJECTION_PATTERNS.some((pattern) =>
      pattern.test(value)
    );

    if (isThreat) {
      this.threatMetrics.commandInjectionAttempts++;
      this.threatMetrics.totalThreats++;
      this._recordThreat(THREAT_TYPES.COMMAND_INJECTION, value);
    }

    return isThreat;
  }

  /**
   * Check for path traversal threats
   * @param {string} value - Value to validate
   * @returns {boolean} Whether threat is detected
   */
  checkPathTraversal(value) {
    if (typeof value !== "string") return false;

    const isThreat = PATH_TRAVERSAL_PATTERNS.some((pattern) =>
      pattern.test(value)
    );

    if (isThreat) {
      this.threatMetrics.pathTraversalAttempts++;
      this.threatMetrics.totalThreats++;
      this._recordThreat(THREAT_TYPES.PATH_TRAVERSAL, value);
    }

    return isThreat;
  }

  /**
   * Comprehensive security check
   * @param {string} value - Value to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateSecurity(value, options = {}) {
    const {
      checkSQLInjection = true,
      checkXSS = true,
      checkCommandInjection = true,
      checkPathTraversal = true,
    } = options;

    const threats = [];

    if (checkSQLInjection && this.checkSQLInjection(value)) {
      threats.push({
        type: THREAT_TYPES.SQL_INJECTION,
        severity: VALIDATION_SEVERITY.HIGH,
        message: "Potential SQL injection detected",
      });
    }

    if (checkXSS && this.checkXSS(value)) {
      threats.push({
        type: THREAT_TYPES.XSS,
        severity: VALIDATION_SEVERITY.HIGH,
        message: "Potential XSS attack detected",
      });
    }

    if (checkCommandInjection && this.checkCommandInjection(value)) {
      threats.push({
        type: THREAT_TYPES.COMMAND_INJECTION,
        severity: VALIDATION_SEVERITY.CRITICAL,
        message: "Potential command injection detected",
      });
    }

    if (checkPathTraversal && this.checkPathTraversal(value)) {
      threats.push({
        type: THREAT_TYPES.PATH_TRAVERSAL,
        severity: VALIDATION_SEVERITY.HIGH,
        message: "Potential path traversal detected",
      });
    }

    return {
      isValid: threats.length === 0,
      result:
        threats.length === 0
          ? VALIDATION_RESULT.VALID
          : VALIDATION_RESULT.THREAT,
      threats,
      value: sanitizeSensitiveData(value),
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Validate object recursively for security threats
   * @param {Object} obj - Object to validate
   * @param {Object} options - Validation options
   * @returns {Object|null} Threat details or null if safe
   */
  validateObjectSecurity(obj, options = {}) {
    if (!obj || typeof obj !== "object") return null;

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          const threat = this.validateObjectSecurity(value[i], options);
          if (threat) {
            return {
              ...threat,
              field: `${key}[${i}]${threat.field ? "." + threat.field : ""}`,
            };
          }
        }
      } else if (typeof value === "object" && value !== null) {
        const threat = this.validateObjectSecurity(value, options);
        if (threat) {
          return {
            ...threat,
            field: `${key}${threat.field ? "." + threat.field : ""}`,
          };
        }
      } else if (typeof value === "string") {
        const validation = this.validateSecurity(value, options);
        if (!validation.isValid) {
          return {
            field: key,
            value: validation.value,
            threats: validation.threats,
            type: validation.threats[0]?.type,
            severity: validation.threats[0]?.severity,
            message: validation.threats[0]?.message,
          };
        }
      }
    }

    return null;
  }

  /**
   * Validate multiple values at once
   * @param {Object} values - Key-value pairs to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation results
   */
  validateMultiple(values, options = {}) {
    const results = {};
    let hasThreats = false;

    for (const [key, value] of Object.entries(values)) {
      const result = this.validateSecurity(value, options);
      results[key] = result;

      if (!result.isValid) {
        hasThreats = true;
      }
    }

    return {
      isValid: !hasThreats,
      results,
      summary: {
        total: Object.keys(values).length,
        valid: Object.values(results).filter((r) => r.isValid).length,
        threats: Object.values(results).filter((r) => !r.isValid).length,
      },
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get threat metrics
   * @returns {Object} Current threat metrics
   */
  getMetrics() {
    return {
      ...this.threatMetrics,
      threatHistorySize: this.threatHistory.length,
      averageThreatsPerHour: this._calculateThreatRate(),
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get recent threat history
   * @param {number} limit - Number of threats to return
   * @returns {Array} Recent threats
   */
  getRecentThreats(limit = 50) {
    return this.threatHistory.slice(-limit);
  }

  /**
   * Reset threat metrics
   */
  resetMetrics() {
    this.threatMetrics = {
      sqlInjectionAttempts: 0,
      xssAttempts: 0,
      commandInjectionAttempts: 0,
      pathTraversalAttempts: 0,
      totalThreats: 0,
      lastReset: generateTimestamp(),
    };

    this.threatHistory = [];

    logger.info("Security validation metrics reset", {
      timestamp: generateTimestamp(),
      source: "SecurityValidator",
    });
  }

  /**
   * Record threat for history and analysis
   * @param {string} type - Threat type
   * @param {string} value - Threat value
   * @private
   */
  _recordThreat(type, value) {
    const threat = {
      type,
      value: sanitizeSensitiveData(value),
      timestamp: generateTimestamp(),
    };

    this.threatHistory.push(threat);

    // Limit history size
    if (this.threatHistory.length > this.maxHistorySize) {
      this.threatHistory.shift();
    }

    // Log threat for security monitoring
    logger.security("Security threat detected", {
      type,
      value: sanitizeSensitiveData(value),
      source: "SecurityValidator",
    });
  }

  /**
   * Calculate threat rate per hour
   * @returns {number} Threats per hour
   * @private
   */
  _calculateThreatRate() {
    const now = new Date();
    const lastReset = new Date(this.threatMetrics.lastReset);
    const hoursSinceReset = (now - lastReset) / (1000 * 60 * 60);

    return hoursSinceReset > 0
      ? this.threatMetrics.totalThreats / hoursSinceReset
      : 0;
  }
}

// Create singleton instance
const securityValidator = new SecurityValidator();

/**
 * Convenience functions for direct usage
 */
const checkSQLInjection = (value) => securityValidator.checkSQLInjection(value);
const checkXSS = (value) => securityValidator.checkXSS(value);
const checkCommandInjection = (value) =>
  securityValidator.checkCommandInjection(value);
const checkPathTraversal = (value) =>
  securityValidator.checkPathTraversal(value);

/**
 * Validate security of a single value
 * @param {string} value - Value to validate
 * @param {Object} options - Validation options
 * @returns {Object} Validation result
 */
const validateSecurity = (value, options = {}) => {
  return securityValidator.validateSecurity(value, options);
};

/**
 * Validate security of an object
 * @param {Object} obj - Object to validate
 * @param {Object} options - Validation options
 * @returns {Object|null} Threat details or null if safe
 */
const validateObjectSecurity = (obj, options = {}) => {
  return securityValidator.validateObjectSecurity(obj, options);
};

/**
 * Get security metrics
 * @returns {Object} Security metrics
 */
const getSecurityMetrics = () => {
  return securityValidator.getMetrics();
};

/**
 * Get recent security threats
 * @param {number} limit - Number of threats to return
 * @returns {Array} Recent threats
 */
const getRecentSecurityThreats = (limit = 50) => {
  return securityValidator.getRecentThreats(limit);
};

module.exports = {
  // Main class
  SecurityValidator,

  // Singleton instance
  securityValidator,

  // Individual validation functions
  checkSQLInjection,
  checkXSS,
  checkCommandInjection,
  checkPathTraversal,

  // Composite validation functions
  validateSecurity,
  validateObjectSecurity,

  // Utility functions
  getSecurityMetrics,
  getRecentSecurityThreats,
};
