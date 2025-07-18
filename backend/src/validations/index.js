/**
 * Validation System - Main Entry Point
 *
 * This is the main entry point for the comprehensive validation system.
 * It exports all validation modules and provides a unified API for
 * security, input, business logic, and middleware validation.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

// Import all validation modules
const patterns = require("./patterns");
const security = require("./security");
const input = require("./input");
const business = require("./business");
const middleware = require("./middleware");

// Re-export all patterns for external use
const {
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
} = patterns;

// Re-export security validation functions
const {
  SecurityValidator,
  securityValidator,
  checkSQLInjection,
  checkXSS,
  checkCommandInjection,
  checkPathTraversal,
  validateSecurity,
  validateObjectSecurity,
  getSecurityMetrics,
  getRecentSecurityThreats,
} = security;

// Re-export input validation functions
const {
  InputValidator,
  inputValidator,
  validateEmail,
  validatePhone,
  validateURL,
  validatePassword,
  validateUUID,
  validateUsername,
  getInputMetrics,
  resetInputMetrics,
  validateMultipleInputs,
} = input;

// Re-export business validation functions
const {
  BusinessValidator,
  businessValidator,
  validateUserRegistration,
  validateUserLogin,
  validateUserPermission,
  validateFileUpload,
  validateDataConsistency,
  getBusinessMetrics,
  resetBusinessMetrics,
  updateBusinessRules,
} = business;

// Re-export middleware functions
const {
  ValidationMiddleware,
  validationMiddleware,
  validateSecurity: validateSecurityMiddleware,
  validateInput: validateInputMiddleware,
  validateUserRegistration: validateUserRegistrationMiddleware,
  validateUserLogin: validateUserLoginMiddleware,
  validatePermission: validatePermissionMiddleware,
  validateFileUpload: validateFileUploadMiddleware,
  validateCombined: validateCombinedMiddleware,
  getMiddlewareMetrics,
  resetMiddlewareMetrics,
} = middleware;

const { generateTimestamp } = require("../utils/common");

/**
 * Main Validation Controller
 * Provides a unified interface for all validation operations
 */
class ValidationController {
  constructor() {
    this.security = securityValidator;
    this.input = inputValidator;
    this.business = businessValidator;
    this.middleware = validationMiddleware;

    this.globalMetrics = {
      totalValidations: 0,
      securityValidations: 0,
      inputValidations: 0,
      businessValidations: 0,
      middlewareValidations: 0,
      lastReset: generateTimestamp(),
    };
  }

  /**
   * Validate request comprehensively
   * @param {Object} request - Request object with body, query, params
   * @param {Object} validationConfig - Validation configuration
   * @returns {Object} Comprehensive validation result
   */
  validateRequest(request, validationConfig = {}) {
    const {
      security: securityEnabled = true,
      input: inputSchema = null,
      userRegistration = false,
      userLogin = false,
      permission = null,
      fileUpload = false,
    } = validationConfig;

    const results = {
      isValid: true,
      results: {},
      errors: [],
      warnings: [],
      metrics: {
        totalChecks: 0,
        passedChecks: 0,
        failedChecks: 0,
      },
      timestamp: generateTimestamp(),
    };

    // Security validation
    if (securityEnabled) {
      results.metrics.totalChecks++;
      this.globalMetrics.securityValidations++;

      const securityResult = this.validateRequestSecurity(
        request,
        validationConfig.securityOptions
      );
      results.results.security = securityResult;

      if (!securityResult.isValid) {
        results.isValid = false;
        results.errors.push(...securityResult.errors);
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    // Input validation
    if (inputSchema) {
      results.metrics.totalChecks++;
      this.globalMetrics.inputValidations++;

      const inputResult = validateMultipleInputs(request.body, inputSchema);
      results.results.input = inputResult;

      if (!inputResult.isValid) {
        results.isValid = false;
        results.errors.push(
          ...Object.values(inputResult.results)
            .filter((r) => !r.isValid)
            .map((r) => ({ field: "input", message: r.message }))
        );
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    // User registration validation
    if (userRegistration) {
      results.metrics.totalChecks++;
      this.globalMetrics.businessValidations++;

      const registrationResult = validateUserRegistration(
        request.body,
        validationConfig.userRegistrationOptions
      );
      results.results.userRegistration = registrationResult;

      if (!registrationResult.isValid) {
        results.isValid = false;
        results.errors.push(...registrationResult.errors);
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    // User login validation
    if (userLogin) {
      results.metrics.totalChecks++;
      this.globalMetrics.businessValidations++;

      const loginResult = validateUserLogin(
        request.body,
        validationConfig.userLoginOptions
      );
      results.results.userLogin = loginResult;

      if (!loginResult.isValid) {
        results.isValid = false;
        results.errors.push(...loginResult.errors);
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    // Permission validation
    if (permission) {
      results.metrics.totalChecks++;
      this.globalMetrics.businessValidations++;

      const permissionResult = validateUserPermission(
        permission.userId,
        permission.type,
        permission.resource
      );
      results.results.permission = permissionResult;

      if (!permissionResult.isValid) {
        results.isValid = false;
        results.errors.push(...permissionResult.errors);
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    // File upload validation
    if (fileUpload) {
      results.metrics.totalChecks++;
      this.globalMetrics.businessValidations++;

      const fileResult = validateFileUpload(
        request.file,
        validationConfig.fileUploadOptions
      );
      results.results.fileUpload = fileResult;

      if (!fileResult.isValid) {
        results.isValid = false;
        results.errors.push(...fileResult.errors);
        results.metrics.failedChecks++;
      } else {
        results.metrics.passedChecks++;
      }
    }

    this.globalMetrics.totalValidations++;
    return results;
  }

  /**
   * Validate request security comprehensively
   * @param {Object} request - Request object
   * @param {Object} options - Security options
   * @returns {Object} Security validation result
   */
  validateRequestSecurity(request, options = {}) {
    const errors = [];

    // Check body for security threats
    if (request.body) {
      const bodyThreat = validateObjectSecurity(request.body, options);
      if (bodyThreat) {
        errors.push({
          location: "body",
          field: bodyThreat.field,
          message: bodyThreat.message,
          severity: bodyThreat.severity,
          type: bodyThreat.type,
        });
      }
    }

    // Check query parameters for security threats
    if (request.query) {
      const queryThreat = validateObjectSecurity(request.query, options);
      if (queryThreat) {
        errors.push({
          location: "query",
          field: queryThreat.field,
          message: queryThreat.message,
          severity: queryThreat.severity,
          type: queryThreat.type,
        });
      }
    }

    // Check route parameters for security threats
    if (request.params) {
      const paramsThreat = validateObjectSecurity(request.params, options);
      if (paramsThreat) {
        errors.push({
          location: "params",
          field: paramsThreat.field,
          message: paramsThreat.message,
          severity: paramsThreat.severity,
          type: paramsThreat.type,
        });
      }
    }

    return {
      isValid: errors.length === 0,
      result:
        errors.length === 0
          ? VALIDATION_RESULT.VALID
          : VALIDATION_RESULT.THREAT,
      errors,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get comprehensive validation metrics
   * @returns {Object} All validation metrics
   */
  getAllMetrics() {
    return {
      global: {
        ...this.globalMetrics,
        timestamp: generateTimestamp(),
      },
      security: getSecurityMetrics(),
      input: getInputMetrics(),
      business: getBusinessMetrics(),
      middleware: getMiddlewareMetrics(),
    };
  }

  /**
   * Reset all validation metrics
   */
  resetAllMetrics() {
    this.globalMetrics = {
      totalValidations: 0,
      securityValidations: 0,
      inputValidations: 0,
      businessValidations: 0,
      middlewareValidations: 0,
      lastReset: generateTimestamp(),
    };

    this.security.resetMetrics();
    resetInputMetrics();
    resetBusinessMetrics();
    resetMiddlewareMetrics();
  }

  /**
   * Get system health status
   * @returns {Object} System health information
   */
  getHealthStatus() {
    const metrics = this.getAllMetrics();

    return {
      status: "healthy",
      uptime: Date.now() - new Date(this.globalMetrics.lastReset).getTime(),
      metrics: {
        totalValidations: metrics.global.totalValidations,
        securityThreats: metrics.security.totalThreats,
        inputErrors: metrics.input.failedValidations,
        businessRuleViolations: metrics.business.failedValidations,
        middlewareErrors: metrics.middleware.invalidRequests,
      },
      performance: {
        securitySuccessRate:
          metrics.security.threatHistorySize > 0
            ? (
                (metrics.security.totalThreats /
                  metrics.security.threatHistorySize) *
                100
              ).toFixed(2)
            : 100,
        inputSuccessRate: metrics.input.successRate,
        businessSuccessRate: metrics.business.successRate,
        middlewareSuccessRate: metrics.middleware.successRate,
      },
      timestamp: generateTimestamp(),
    };
  }
}

// Create singleton instance
const validationController = new ValidationController();

// Main exports
module.exports = {
  // Main controller
  ValidationController,
  validationController,

  // Validation classes
  SecurityValidator,
  InputValidator,
  BusinessValidator,
  ValidationMiddleware,

  // Singleton instances
  securityValidator,
  inputValidator,
  businessValidator,
  validationMiddleware,

  // Patterns and constants
  patterns: {
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    EMAIL_PATTERN,
    PHONE_PATTERNS,
    URL_PATTERN,
    UUID_PATTERNS,
    PASSWORD_PATTERNS,
    INPUT_PATTERNS,
    DATE_PATTERNS,
    CREDIT_CARD_PATTERNS,
    THREAT_TYPES,
    VALIDATION_SEVERITY,
    VALIDATION_RESULT,
    FIELD_LIMITS,
  },

  // Security validation functions
  security: {
    checkSQLInjection,
    checkXSS,
    checkCommandInjection,
    checkPathTraversal,
    validateSecurity,
    validateObjectSecurity,
    getSecurityMetrics,
    getRecentSecurityThreats,
  },

  // Input validation functions
  input: {
    validateEmail,
    validatePhone,
    validateURL,
    validatePassword,
    validateUUID,
    validateUsername,
    validateMultipleInputs,
    getInputMetrics,
    resetInputMetrics,
  },

  // Business validation functions
  business: {
    validateUserRegistration,
    validateUserLogin,
    validateUserPermission,
    validateFileUpload,
    validateDataConsistency,
    getBusinessMetrics,
    resetBusinessMetrics,
    updateBusinessRules,
  },

  // Middleware functions
  middleware: {
    validateSecurity: validateSecurityMiddleware,
    validateInput: validateInputMiddleware,
    validateUserRegistration: validateUserRegistrationMiddleware,
    validateUserLogin: validateUserLoginMiddleware,
    validatePermission: validatePermissionMiddleware,
    validateFileUpload: validateFileUploadMiddleware,
    validateCombined: validateCombinedMiddleware,
    getMiddlewareMetrics,
    resetMiddlewareMetrics,
  },

  // Utility functions
  validateRequest: (request, config) =>
    validationController.validateRequest(request, config),
  getAllMetrics: () => validationController.getAllMetrics(),
  resetAllMetrics: () => validationController.resetAllMetrics(),
  getHealthStatus: () => validationController.getHealthStatus(),
};
