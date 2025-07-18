/**
 * Validation Middleware Module
 *
 * This module provides Express middleware wrappers for all validation functions
 * to enable easy integration into routes. It provides comprehensive validation
 * middleware with consistent error handling and response formatting.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  validateSecurity: validateSecurityCore,
  validateObjectSecurity,
} = require("./security");
const { validateMultipleInputs } = require("./input");
const {
  validateUserRegistration: validateUserRegistrationCore,
  validateUserLogin: validateUserLoginCore,
  validateUserPermission: validateUserPermissionCore,
  validateFileUpload: validateFileUploadCore,
} = require("./business");
const { VALIDATION_RESULT, VALIDATION_SEVERITY } = require("./patterns");
const {
  generateRequestId,
  generateTimestamp,
  buildRequestContext,
} = require("../utils/common");
const logger = require("../utils/logger");

/**
 * Validation Middleware Class
 * Provides Express middleware wrappers for all validation functions
 */
class ValidationMiddleware {
  constructor() {
    this.middlewareMetrics = {
      totalRequests: 0,
      validRequests: 0,
      invalidRequests: 0,
      securityThreats: 0,
      businessRuleViolations: 0,
      inputFormatErrors: 0,
      lastReset: generateTimestamp(),
    };
  }

  /**
   * Create security validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  validateSecurityMiddleware(options = {}) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        // Validate request body
        const bodyThreat = validateObjectSecurity(req.body, options);
        if (bodyThreat) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.securityThreats++;

          logger.security("Security threat detected in request body", {
            requestId,
            threat: bodyThreat,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "Security threat detected",
            details: {
              field: bodyThreat.field,
              message: bodyThreat.message,
              severity: bodyThreat.severity,
            },
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        // Validate query parameters
        const queryThreat = validateObjectSecurity(req.query, options);
        if (queryThreat) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.securityThreats++;

          logger.security("Security threat detected in query parameters", {
            requestId,
            threat: queryThreat,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "Security threat detected",
            details: {
              field: queryThreat.field,
              message: queryThreat.message,
              severity: queryThreat.severity,
            },
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        // Validate route parameters
        const paramsThreat = validateObjectSecurity(req.params, options);
        if (paramsThreat) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.securityThreats++;

          logger.security("Security threat detected in route parameters", {
            requestId,
            threat: paramsThreat,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "Security threat detected",
            details: {
              field: paramsThreat.field,
              message: paramsThreat.message,
              severity: paramsThreat.severity,
            },
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        next();
      } catch (error) {
        logger.error("Error in security validation middleware", {
          error: error.message,
          requestId,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create input validation middleware
   * @param {Object} schema - Validation schema
   * @returns {Function} Express middleware
   */
  validateInputMiddleware(schema) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        // Validate request body against schema
        const validation = validateMultipleInputs(req.body, schema);

        if (!validation.isValid) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.inputFormatErrors++;

          logger.warn("Input validation failed", {
            requestId,
            validation,
            context: buildRequestContext(req),
          });

          const errors = Object.entries(validation.results)
            .filter(([_, result]) => !result.isValid)
            .map(([field, result]) => ({
              field,
              message: result.message,
              severity: result.severity,
            }));

          return res.status(400).json({
            success: false,
            error: "Input validation failed",
            details: errors,
            summary: validation.summary,
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        req.validatedData = validation.results;
        next();
      } catch (error) {
        logger.error("Error in input validation middleware", {
          error: error.message,
          requestId,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create user registration validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  validateUserRegistrationMiddleware(options = {}) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        const validation = validateUserRegistrationCore(req.body, options);

        if (!validation.isValid) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.businessRuleViolations++;

          logger.warn("User registration validation failed", {
            requestId,
            validation,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "User registration validation failed",
            details: validation.errors,
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        req.validatedUserData = req.body;
        next();
      } catch (error) {
        logger.error("Error in user registration validation middleware", {
          error: error.message,
          requestId,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create user login validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  validateUserLoginMiddleware(options = {}) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        const validation = validateUserLoginCore(req.body, options);

        if (!validation.isValid) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.businessRuleViolations++;

          logger.warn("User login validation failed", {
            requestId,
            validation,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "User login validation failed",
            details: validation.errors,
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        req.validatedLoginData = req.body;
        next();
      } catch (error) {
        logger.error("Error in user login validation middleware", {
          error: error.message,
          requestId,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create permission validation middleware
   * @param {string} permission - Required permission
   * @param {string} resource - Resource being accessed
   * @returns {Function} Express middleware
   */
  validatePermissionMiddleware(permission, resource) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        const userId = req.user?.id || req.userId;

        if (!userId) {
          this.middlewareMetrics.invalidRequests++;

          logger.warn("Permission validation failed - no user ID", {
            requestId,
            permission,
            resource,
            context: buildRequestContext(req),
          });

          return res.status(401).json({
            success: false,
            error: "Authentication required",
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        const validation = validateUserPermissionCore(
          userId,
          permission,
          resource
        );

        if (!validation.isValid) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.businessRuleViolations++;

          logger.warn("Permission validation failed", {
            requestId,
            userId,
            permission,
            resource,
            validation,
            context: buildRequestContext(req),
          });

          return res.status(403).json({
            success: false,
            error: "Insufficient permissions",
            details: validation.errors,
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        next();
      } catch (error) {
        logger.error("Error in permission validation middleware", {
          error: error.message,
          requestId,
          permission,
          resource,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create file upload validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  validateFileUploadMiddleware(options = {}) {
    return (req, res, next) => {
      const requestId = generateRequestId();
      this.middlewareMetrics.totalRequests++;

      try {
        const fileData = {
          ...req.file,
          userId: req.user?.id || req.userId,
        };

        const validation = validateFileUploadCore(fileData, options);

        if (!validation.isValid) {
          this.middlewareMetrics.invalidRequests++;
          this.middlewareMetrics.businessRuleViolations++;

          logger.warn("File upload validation failed", {
            requestId,
            validation,
            context: buildRequestContext(req),
          });

          return res.status(400).json({
            success: false,
            error: "File upload validation failed",
            details: validation.errors,
            requestId,
            timestamp: generateTimestamp(),
          });
        }

        this.middlewareMetrics.validRequests++;
        req.requestId = requestId;
        req.validatedFile = fileData;
        next();
      } catch (error) {
        logger.error("Error in file upload validation middleware", {
          error: error.message,
          requestId,
          context: buildRequestContext(req),
        });

        res.status(500).json({
          success: false,
          error: "Internal validation error",
          requestId,
          timestamp: generateTimestamp(),
        });
      }
    };
  }

  /**
   * Create combined validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  validateCombinedMiddleware(options = {}) {
    const {
      security = true,
      input = null,
      userRegistration = false,
      userLogin = false,
      permission = null,
      fileUpload = false,
    } = options;

    return (req, res, next) => {
      const requestId = generateRequestId();
      req.requestId = requestId;

      // Chain validations
      const middlewares = [];

      if (security) {
        middlewares.push(
          this.validateSecurityMiddleware(options.securityOptions)
        );
      }

      if (input) {
        middlewares.push(this.validateInputMiddleware(input));
      }

      if (userRegistration) {
        middlewares.push(
          this.validateUserRegistrationMiddleware(
            options.userRegistrationOptions
          )
        );
      }

      if (userLogin) {
        middlewares.push(
          this.validateUserLoginMiddleware(options.userLoginOptions)
        );
      }

      if (permission) {
        middlewares.push(
          this.validatePermissionMiddleware(
            permission.type,
            permission.resource
          )
        );
      }

      if (fileUpload) {
        middlewares.push(
          this.validateFileUploadMiddleware(options.fileUploadOptions)
        );
      }

      // Execute middlewares in sequence
      let currentIndex = 0;
      const executeNext = (error) => {
        if (error) {
          return next(error);
        }

        if (currentIndex >= middlewares.length) {
          return next();
        }

        const middleware = middlewares[currentIndex++];
        middleware(req, res, executeNext);
      };

      executeNext();
    };
  }

  /**
   * Get middleware metrics
   * @returns {Object} Current middleware metrics
   */
  getMetrics() {
    return {
      ...this.middlewareMetrics,
      successRate:
        this.middlewareMetrics.totalRequests > 0
          ? (this.middlewareMetrics.validRequests /
              this.middlewareMetrics.totalRequests) *
            100
          : 0,
      threatRate:
        this.middlewareMetrics.totalRequests > 0
          ? (this.middlewareMetrics.securityThreats /
              this.middlewareMetrics.totalRequests) *
            100
          : 0,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Reset middleware metrics
   */
  resetMetrics() {
    this.middlewareMetrics = {
      totalRequests: 0,
      validRequests: 0,
      invalidRequests: 0,
      securityThreats: 0,
      businessRuleViolations: 0,
      inputFormatErrors: 0,
      lastReset: generateTimestamp(),
    };
  }
}

// Create singleton instance
const validationMiddleware = new ValidationMiddleware();

// Export middleware functions
const validateSecurity = (options) =>
  validationMiddleware.validateSecurityMiddleware(options);
const validateInput = (schema) =>
  validationMiddleware.validateInputMiddleware(schema);
const validateUserRegistration = (options) =>
  validationMiddleware.validateUserRegistrationMiddleware(options);
const validateUserLogin = (options) =>
  validationMiddleware.validateUserLoginMiddleware(options);
const validatePermission = (permission, resource) =>
  validationMiddleware.validatePermissionMiddleware(permission, resource);
const validateFileUpload = (options) =>
  validationMiddleware.validateFileUploadMiddleware(options);
const validateCombined = (options) =>
  validationMiddleware.validateCombinedMiddleware(options);

module.exports = {
  // Main class
  ValidationMiddleware,

  // Singleton instance
  validationMiddleware,

  // Middleware functions
  validateSecurity,
  validateInput,
  validateUserRegistration,
  validateUserLogin,
  validatePermission,
  validateFileUpload,
  validateCombined,

  // Utility functions
  getMiddlewareMetrics: () => validationMiddleware.getMetrics(),
  resetMiddlewareMetrics: () => validationMiddleware.resetMetrics(),
};
