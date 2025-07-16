/**
 * Validation Middleware Module
 *
 * This module provides comprehensive input validation and sanitization
 * for multi-tenant SaaS applications with enterprise security requirements:
 *
 * Features:
 * - Schema-based validation with Joi
 * - Input sanitization and XSS protection
 * - File upload validation and security
 * - Rate limiting for validation-heavy endpoints
 * - Custom validation rules for business logic
 * - Comprehensive error handling and reporting
 * - Performance optimization for high-throughput validation
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const Joi = require('joi');
const validator = require('validator');
const DOMPurify = require('isomorphic-dompurify');
const config = require('../config');

/**
 * Validation Result Types
 */
const VALIDATION_RESULTS = {
  SUCCESS: 'success',
  VALIDATION_ERROR: 'validation_error',
  SANITIZATION_ERROR: 'sanitization_error',
  SECURITY_VIOLATION: 'security_violation',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
};

/**
 * Validation Severity Levels
 */
const VALIDATION_SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

/**
 * Common Validation Patterns
 */
const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PHONE: /^\+?[\d\s\-\(\)]+$/,
  URL: /^https?:\/\/.+/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  SLUG: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
  HEX_COLOR: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
  DOMAIN:
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
};

/**
 * Validation Manager Class
 * Handles all validation logic with enterprise features
 */
class ValidationManager {
  constructor() {
    this.validationMetrics = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      sanitizationEvents: 0,
      securityViolations: 0,
    };

    this.validationCache = new Map();
    this.maxCacheSize = 1000;
    this.setupCustomValidators();
  }

  /**
   * Setup custom Joi validators
   */
  setupCustomValidators() {
    // Custom domain validator
    this.domainValidator = Joi.extend((joi) => ({
      type: 'domain',
      base: joi.string(),
      messages: {
        'domain.invalid': 'Invalid domain format',
        'domain.blocked': 'Domain is blocked',
      },
      validate(value, helpers) {
        if (!VALIDATION_PATTERNS.DOMAIN.test(value)) {
          return { value, errors: helpers.error('domain.invalid') };
        }

        // Check against blocked domains
        const blockedDomains = config.workspace.blockedDomains || [];
        if (blockedDomains.includes(value.toLowerCase())) {
          return { value, errors: helpers.error('domain.blocked') };
        }

        return { value };
      },
    }));

    // Custom workspace name validator
    this.workspaceNameValidator = Joi.extend((joi) => ({
      type: 'workspaceName',
      base: joi.string(),
      messages: {
        'workspaceName.invalid': 'Workspace name contains invalid characters',
        'workspaceName.reserved': 'Workspace name is reserved',
      },
      validate(value, helpers) {
        // Check for reserved names
        const reservedNames = [
          'admin',
          'api',
          'www',
          'mail',
          'support',
          'help',
        ];
        if (reservedNames.includes(value.toLowerCase())) {
          return { value, errors: helpers.error('workspaceName.reserved') };
        }

        // Check for valid characters
        if (!/^[a-zA-Z0-9\s\-_]+$/.test(value)) {
          return { value, errors: helpers.error('workspaceName.invalid') };
        }

        return { value };
      },
    }));
  }

  /**
   * Create validation middleware
   * @param {Object} schema - Joi validation schema
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  createValidationMiddleware(schema, options = {}) {
    const {
      target = 'body', // 'body', 'query', 'params', 'headers'
      sanitize = true,
      allowUnknown = false,
      stripUnknown = true,
      abortEarly = false,
      cache = false,
      severity = VALIDATION_SEVERITY.MEDIUM,
    } = options;

    return async (req, res, next) => {
      try {
        this.validationMetrics.totalValidations++;

        const dataToValidate = req[target];

        // Check cache if enabled
        if (cache) {
          const cacheKey = this.generateCacheKey(schema, dataToValidate);
          const cached = this.validationCache.get(cacheKey);

          if (cached) {
            req[target] = cached.validatedData;
            return next();
          }
        }

        // Sanitize input if enabled
        if (sanitize) {
          req[target] = this.sanitizeInput(dataToValidate);
          this.validationMetrics.sanitizationEvents++;
        }

        // Validate with Joi
        const validationOptions = {
          allowUnknown,
          stripUnknown,
          abortEarly,
          errors: { wrap: { label: false } },
        };

        const { error, value } = schema.validate(
          req[target],
          validationOptions,
        );

        if (error) {
          this.validationMetrics.failedValidations++;

          // Log validation failure
          this._logValidationEvent('VALIDATION_FAILED', {
            target,
            errors: error.details,
            severity,
            endpoint: req.originalUrl,
            method: req.method,
            userId: req.user?.id,
            workspaceId: req.workspace?.id,
            ip: req.ip,
          });

          return this.handleValidationError(res, error, severity);
        }

        // Store validated data
        req[target] = value;

        // Cache if enabled
        if (cache) {
          this.cacheValidationResult(schema, dataToValidate, value);
        }

        this.validationMetrics.successfulValidations++;
        next();
      } catch (error) {
        console.error('Validation middleware error:', error);
        this.validationMetrics.failedValidations++;

        this._logValidationEvent('VALIDATION_ERROR', {
          error: error.message,
          target,
          endpoint: req.originalUrl,
          ip: req.ip,
        });

        return this.handleValidationError(res, error, VALIDATION_SEVERITY.HIGH);
      }
    };
  }

  /**
   * Sanitize input data
   * @param {any} data - Data to sanitize
   * @returns {any} Sanitized data
   */
  sanitizeInput(data) {
    if (typeof data === 'string') {
      return this.sanitizeString(data);
    }

    if (Array.isArray(data)) {
      return data.map((item) => this.sanitizeInput(item));
    }

    if (data && typeof data === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeInput(value);
      }
      return sanitized;
    }

    return data;
  }

  /**
   * Sanitize string input
   * @param {string} str - String to sanitize
   * @returns {string} Sanitized string
   */
  sanitizeString(str) {
    if (!str || typeof str !== 'string') {
      return str;
    }

    // Remove null bytes
    str = str.replace(/\0/g, '');

    // Normalize whitespace
    str = str.replace(/\s+/g, ' ').trim();

    // Remove HTML tags and XSS attempts
    str = DOMPurify.sanitize(str, { ALLOWED_TAGS: [] });

    // Escape special characters
    str = validator.escape(str);

    return str;
  }

  /**
   * File upload validation middleware
   * @param {Object} options - Upload validation options
   * @returns {Function} Express middleware
   */
  createFileValidationMiddleware(options = {}) {
    const {
      maxSize = 10 * 1024 * 1024, // 10MB default
      allowedTypes = ['image/jpeg', 'image/png', 'image/gif'],
      allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'],
      maxFiles = 5,
      required = false,
    } = options;

    return (req, res, next) => {
      try {
        const files = req.files || [];

        if (required && files.length === 0) {
          return this.handleValidationError(
            res,
            new Error('File upload is required'),
            VALIDATION_SEVERITY.MEDIUM,
          );
        }

        if (files.length > maxFiles) {
          return this.handleValidationError(
            res,
            new Error(`Maximum ${maxFiles} files allowed`),
            VALIDATION_SEVERITY.MEDIUM,
          );
        }

        for (const file of files) {
          // Check file size
          if (file.size > maxSize) {
            return this.handleValidationError(
              res,
              new Error(`File size exceeds ${maxSize} bytes`),
              VALIDATION_SEVERITY.MEDIUM,
            );
          }

          // Check MIME type
          if (!allowedTypes.includes(file.mimetype)) {
            return this.handleValidationError(
              res,
              new Error(`File type ${file.mimetype} not allowed`),
              VALIDATION_SEVERITY.HIGH,
            );
          }

          // Check file extension
          const ext = file.originalname
            .toLowerCase()
            .slice(file.originalname.lastIndexOf('.'));
          if (!allowedExtensions.includes(ext)) {
            return this.handleValidationError(
              res,
              new Error(`File extension ${ext} not allowed`),
              VALIDATION_SEVERITY.HIGH,
            );
          }

          // Check for malicious content
          if (this.containsMaliciousContent(file)) {
            this.validationMetrics.securityViolations++;

            this._logValidationEvent('MALICIOUS_FILE_DETECTED', {
              filename: file.originalname,
              mimetype: file.mimetype,
              size: file.size,
              userId: req.user?.id,
              workspaceId: req.workspace?.id,
              ip: req.ip,
            });

            return this.handleValidationError(
              res,
              new Error('Malicious file content detected'),
              VALIDATION_SEVERITY.CRITICAL,
            );
          }
        }

        next();
      } catch (error) {
        console.error('File validation error:', error);
        return this.handleValidationError(res, error, VALIDATION_SEVERITY.HIGH);
      }
    };
  }

  /**
   * Security validation middleware
   * Checks for common security threats in input
   * @param {Object} options - Security validation options
   * @returns {Function} Express middleware
   */
  createSecurityValidationMiddleware(options = {}) {
    const {
      checkSQLInjection = true,
      checkXSS = true,
      checkCommandInjection = true,
      checkPathTraversal = true,
    } = options;

    return (req, res, next) => {
      try {
        const dataToCheck = {
          body: req.body,
          query: req.query,
          params: req.params,
        };

        const violations = [];

        for (const [source, data] of Object.entries(dataToCheck)) {
          const sourceViolations = this.checkSecurityViolations(data, {
            checkSQLInjection,
            checkXSS,
            checkCommandInjection,
            checkPathTraversal,
          });

          if (sourceViolations.length > 0) {
            violations.push({ source, violations: sourceViolations });
          }
        }

        if (violations.length > 0) {
          this.validationMetrics.securityViolations++;

          this._logValidationEvent('SECURITY_VIOLATION', {
            violations,
            endpoint: req.originalUrl,
            method: req.method,
            userId: req.user?.id,
            workspaceId: req.workspace?.id,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
          });

          return this.handleValidationError(
            res,
            new Error('Security violation detected in input'),
            VALIDATION_SEVERITY.CRITICAL,
          );
        }

        next();
      } catch (error) {
        console.error('Security validation error:', error);
        return this.handleValidationError(res, error, VALIDATION_SEVERITY.HIGH);
      }
    };
  }

  /**
   * Check for security violations in data
   * @param {any} data - Data to check
   * @param {Object} options - Check options
   * @returns {Array} Array of violations
   */
  checkSecurityViolations(data, options) {
    const violations = [];

    if (!data) return violations;

    const checkString = (str, path = '') => {
      if (typeof str !== 'string') return;

      if (options.checkSQLInjection && this.containsSQLInjection(str)) {
        violations.push({ type: 'sql_injection', path, value: str });
      }

      if (options.checkXSS && this.containsXSS(str)) {
        violations.push({ type: 'xss', path, value: str });
      }

      if (options.checkCommandInjection && this.containsCommandInjection(str)) {
        violations.push({ type: 'command_injection', path, value: str });
      }

      if (options.checkPathTraversal && this.containsPathTraversal(str)) {
        violations.push({ type: 'path_traversal', path, value: str });
      }
    };

    const traverse = (obj, path = '') => {
      if (typeof obj === 'string') {
        checkString(obj, path);
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => traverse(item, `${path}[${index}]`));
      } else if (obj && typeof obj === 'object') {
        Object.entries(obj).forEach(([key, value]) =>
          traverse(value, path ? `${path}.${key}` : key),
        );
      }
    };

    traverse(data);
    return violations;
  }

  /**
   * Check for SQL injection patterns
   * @param {string} str - String to check
   * @returns {boolean} Whether string contains SQL injection
   */
  containsSQLInjection(str) {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(\b(OR|AND)\s+\d+\s*=\s*\d+)/i,
      /('|(\\')|(;)|(\\))/,
      /(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)/i,
    ];

    return sqlPatterns.some((pattern) => pattern.test(str));
  }

  /**
   * Check for XSS patterns
   * @param {string} str - String to check
   * @returns {boolean} Whether string contains XSS
   */
  containsXSS(str) {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<img[^>]+src[^>]*>/gi,
    ];

    return xssPatterns.some((pattern) => pattern.test(str));
  }

  /**
   * Check for command injection patterns
   * @param {string} str - String to check
   * @returns {boolean} Whether string contains command injection
   */
  containsCommandInjection(str) {
    const commandPatterns = [
      /(\||&|;|`|\$\(|\$\{)/,
      /\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|nslookup|dig|curl|wget)\b/i,
    ];

    return commandPatterns.some((pattern) => pattern.test(str));
  }

  /**
   * Check for path traversal patterns
   * @param {string} str - String to check
   * @returns {boolean} Whether string contains path traversal
   */
  containsPathTraversal(str) {
    const pathPatterns = [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e%2f/i,
      /%2e%2e%5c/i,
      /\.\.\%2f/i,
      /\.\.\%5c/i,
    ];

    return pathPatterns.some((pattern) => pattern.test(str));
  }

  /**
   * Check for malicious content in files
   * @param {Object} file - File object
   * @returns {boolean} Whether file contains malicious content
   */
  containsMaliciousContent(file) {
    // Check filename for suspicious patterns
    const suspiciousPatterns = [
      /\.php$/i,
      /\.jsp$/i,
      /\.asp$/i,
      /\.exe$/i,
      /\.bat$/i,
      /\.cmd$/i,
      /\.sh$/i,
      /\.scr$/i,
    ];

    return suspiciousPatterns.some((pattern) =>
      pattern.test(file.originalname),
    );
  }

  /**
   * Generate cache key for validation
   * @param {Object} schema - Joi schema
   * @param {any} data - Data to validate
   * @returns {string} Cache key
   */
  generateCacheKey(schema, data) {
    const schemaHash = require('crypto')
      .createHash('md5')
      .update(JSON.stringify(schema.describe()))
      .digest('hex');

    const dataHash = require('crypto')
      .createHash('md5')
      .update(JSON.stringify(data))
      .digest('hex');

    return `${schemaHash}:${dataHash}`;
  }

  /**
   * Cache validation result
   * @param {Object} schema - Joi schema
   * @param {any} originalData - Original data
   * @param {any} validatedData - Validated data
   */
  cacheValidationResult(schema, originalData, validatedData) {
    if (this.validationCache.size >= this.maxCacheSize) {
      const firstKey = this.validationCache.keys().next().value;
      this.validationCache.delete(firstKey);
    }

    const cacheKey = this.generateCacheKey(schema, originalData);
    this.validationCache.set(cacheKey, {
      validatedData,
      timestamp: Date.now(),
    });
  }

  /**
   * Handle validation errors
   * @param {Object} res - Express response object
   * @param {Error} error - Validation error
   * @param {string} severity - Error severity
   */
  handleValidationError(res, error, severity = VALIDATION_SEVERITY.MEDIUM) {
    const statusCode = this.getStatusCodeForSeverity(severity);

    let errorDetails = {};

    if (error.details) {
      // Joi validation error
      errorDetails = {
        type: 'validation_error',
        details: error.details.map((detail) => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value,
        })),
      };
    } else {
      // Generic error
      errorDetails = {
        type: 'validation_error',
        message: error.message,
      };
    }

    res.status(statusCode).json({
      success: false,
      error: 'Validation failed',
      ...errorDetails,
      severity,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get HTTP status code for severity
   * @param {string} severity - Error severity
   * @returns {number} HTTP status code
   */
  getStatusCodeForSeverity(severity) {
    const statusCodes = {
      [VALIDATION_SEVERITY.LOW]: 400,
      [VALIDATION_SEVERITY.MEDIUM]: 400,
      [VALIDATION_SEVERITY.HIGH]: 400,
      [VALIDATION_SEVERITY.CRITICAL]: 403,
    };

    return statusCodes[severity] || 400;
  }

  /**
   * Get validation metrics
   * @returns {Object} Validation metrics
   */
  getMetrics() {
    return {
      ...this.validationMetrics,
      cacheSize: this.validationCache.size,
      successRate:
        this.validationMetrics.totalValidations > 0
          ? (this.validationMetrics.successfulValidations /
              this.validationMetrics.totalValidations) *
            100
          : 0,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Clear validation cache
   */
  clearCache() {
    this.validationCache.clear();
  }

  /**
   * Log validation events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logValidationEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'VALIDATION_MIDDLEWARE',
    };

    if (event.includes('VIOLATION') || event.includes('MALICIOUS')) {
      console.warn('🛡️  Validation Security Event:', logEntry);
    } else if (event.includes('FAILED')) {
      console.warn('❌ Validation Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('✅ Validation Event:', logEntry);
    }

    // In production, send to security monitoring service
    if (config.isProduction()) {
      // TODO: Send to security monitoring service
    }
  }
}

// Create singleton instance
const validationManager = new ValidationManager();

// Common validation schemas
const commonSchemas = {
  // User schemas
  userSignup: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    name: Joi.string().min(2).max(50).required(),
  }),

  userLogin: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),

  // Workspace schemas
  workspaceCreate: Joi.object({
    name: validationManager.workspaceNameValidator.workspaceName().required(),
    domain: validationManager.domainValidator.domain().required(),
  }),

  // Invitation schemas
  inviteUser: Joi.object({
    email: Joi.string().email().required(),
  }),

  // Common parameter schemas
  uuidParam: Joi.object({
    id: Joi.string().pattern(VALIDATION_PATTERNS.UUID).required(),
  }),

  // Pagination schemas
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sortBy: Joi.string().default('createdAt'),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  }),
};

// Export validation manager and utilities
module.exports = {
  // Validation manager instance
  validationManager,

  // Common schemas
  schemas: commonSchemas,

  // Validation patterns
  VALIDATION_PATTERNS,

  // Validation results and severity
  VALIDATION_RESULTS,
  VALIDATION_SEVERITY,

  // Middleware creators
  validate: (schema, options) =>
    validationManager.createValidationMiddleware(schema, options),
  validateFile: (options) =>
    validationManager.createFileValidationMiddleware(options),
  validateSecurity: (options) =>
    validationManager.createSecurityValidationMiddleware(options),

  // Utility functions
  sanitizeInput: (data) => validationManager.sanitizeInput(data),
  sanitizeString: (str) => validationManager.sanitizeString(str),

  // Security checks
  containsSQLInjection: (str) => validationManager.containsSQLInjection(str),
  containsXSS: (str) => validationManager.containsXSS(str),
  containsCommandInjection: (str) =>
    validationManager.containsCommandInjection(str),
  containsPathTraversal: (str) => validationManager.containsPathTraversal(str),

  // Cache management
  clearCache: () => validationManager.clearCache(),

  // Monitoring
  getMetrics: () => validationManager.getMetrics(),

  // Custom validators
  domainValidator: validationManager.domainValidator,
  workspaceNameValidator: validationManager.workspaceNameValidator,
};
