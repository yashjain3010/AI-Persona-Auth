/**
 * API Error Utility
 *
 * This module provides comprehensive error handling for a multi-tenant SaaS
 * application with enterprise-grade error management, logging, and response
 * formatting capabilities.
 *
 * Key Features:
 * - Standardized error classes and codes
 * - Multi-tenant error context support
 * - Integration with logging system
 * - Development vs Production error details
 * - Error tracking and metrics
 * - Validation error handling
 * - Database error transformation
 * - Security-focused error responses
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const config = require('../config');
const logger = require('./logger');

/**
 * HTTP Status Codes
 */
const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
};

/**
 * Standard Error Codes
 */
const ERROR_CODES = {
  // Authentication & Authorization
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',

  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',
  INVALID_FORMAT: 'INVALID_FORMAT',

  // Resources
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RESOURCE_ALREADY_EXISTS: 'RESOURCE_ALREADY_EXISTS',
  RESOURCE_CONFLICT: 'RESOURCE_CONFLICT',
  RESOURCE_LOCKED: 'RESOURCE_LOCKED',

  // Workspace & Multi-tenancy
  WORKSPACE_NOT_FOUND: 'WORKSPACE_NOT_FOUND',
  WORKSPACE_ACCESS_DENIED: 'WORKSPACE_ACCESS_DENIED',
  WORKSPACE_LIMIT_EXCEEDED: 'WORKSPACE_LIMIT_EXCEEDED',
  INVALID_WORKSPACE_DOMAIN: 'INVALID_WORKSPACE_DOMAIN',

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',

  // Database
  DATABASE_ERROR: 'DATABASE_ERROR',
  DATABASE_CONNECTION_ERROR: 'DATABASE_CONNECTION_ERROR',
  DUPLICATE_RESOURCE: 'DUPLICATE_RESOURCE',
  FOREIGN_KEY_CONSTRAINT: 'FOREIGN_KEY_CONSTRAINT',

  // File Upload
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  INVALID_FILE_TYPE: 'INVALID_FILE_TYPE',
  UPLOAD_FAILED: 'UPLOAD_FAILED',

  // External Services
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  PAYMENT_FAILED: 'PAYMENT_FAILED',
  EMAIL_DELIVERY_FAILED: 'EMAIL_DELIVERY_FAILED',

  // Security
  SECURITY_VIOLATION: 'SECURITY_VIOLATION',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
  MALICIOUS_REQUEST: 'MALICIOUS_REQUEST',

  // System
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  MAINTENANCE_MODE: 'MAINTENANCE_MODE',

  // Routes
  ROUTE_NOT_FOUND: 'ROUTE_NOT_FOUND',
  METHOD_NOT_ALLOWED: 'METHOD_NOT_ALLOWED',
};

/**
 * Error Severity Levels
 */
const ERROR_SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

/**
 * Base API Error Class
 */
class ApiError extends Error {
  constructor(
    statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR,
    message = 'Internal Server Error',
    code = ERROR_CODES.INTERNAL_ERROR,
    details = null,
    severity = ERROR_SEVERITY.MEDIUM,
  ) {
    super(message);

    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.severity = severity;
    this.timestamp = new Date().toISOString();
    this.isOperational = true; // Distinguishes operational errors from programming errors

    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Convert error to JSON format
   */
  toJSON() {
    const errorObj = {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      severity: this.severity,
      timestamp: this.timestamp,
      isOperational: this.isOperational,
    };

    // Add details if present
    if (this.details) {
      errorObj.details = this.details;
    }

    // Add stack trace in development
    if (config.isDevelopment()) {
      errorObj.stack = this.stack;
    }

    return errorObj;
  }

  /**
   * Get user-friendly error message
   */
  getUserMessage() {
    // Return generic message for security-sensitive errors
    if (
      this.severity === ERROR_SEVERITY.CRITICAL ||
      this.code === ERROR_CODES.SECURITY_VIOLATION
    ) {
      return 'An error occurred while processing your request';
    }

    return this.message;
  }
}

/**
 * Validation Error Class
 */
class ValidationError extends ApiError {
  constructor(message = 'Validation failed', details = null) {
    super(
      HTTP_STATUS.BAD_REQUEST,
      message,
      ERROR_CODES.VALIDATION_ERROR,
      details,
      ERROR_SEVERITY.LOW,
    );
    this.name = 'ValidationError';
  }
}

/**
 * Authentication Error Class
 */
class AuthenticationError extends ApiError {
  constructor(
    message = 'Authentication failed',
    code = ERROR_CODES.UNAUTHORIZED,
  ) {
    super(HTTP_STATUS.UNAUTHORIZED, message, code, null, ERROR_SEVERITY.MEDIUM);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization Error Class
 */
class AuthorizationError extends ApiError {
  constructor(message = 'Access denied', code = ERROR_CODES.FORBIDDEN) {
    super(HTTP_STATUS.FORBIDDEN, message, code, null, ERROR_SEVERITY.MEDIUM);
    this.name = 'AuthorizationError';
  }
}

/**
 * Not Found Error Class
 */
class NotFoundError extends ApiError {
  constructor(resource = 'Resource', code = ERROR_CODES.RESOURCE_NOT_FOUND) {
    super(
      HTTP_STATUS.NOT_FOUND,
      `${resource} not found`,
      code,
      null,
      ERROR_SEVERITY.LOW,
    );
    this.name = 'NotFoundError';
  }
}

/**
 * Conflict Error Class
 */
class ConflictError extends ApiError {
  constructor(
    message = 'Resource conflict',
    code = ERROR_CODES.RESOURCE_CONFLICT,
  ) {
    super(HTTP_STATUS.CONFLICT, message, code, null, ERROR_SEVERITY.LOW);
    this.name = 'ConflictError';
  }
}

/**
 * Rate Limit Error Class
 */
class RateLimitError extends ApiError {
  constructor(message = 'Rate limit exceeded', retryAfter = null) {
    super(
      HTTP_STATUS.TOO_MANY_REQUESTS,
      message,
      ERROR_CODES.RATE_LIMIT_EXCEEDED,
      { retryAfter },
      ERROR_SEVERITY.MEDIUM,
    );
    this.name = 'RateLimitError';
  }
}

/**
 * Database Error Class
 */
class DatabaseError extends ApiError {
  constructor(message = 'Database error', originalError = null) {
    super(
      HTTP_STATUS.INTERNAL_SERVER_ERROR,
      message,
      ERROR_CODES.DATABASE_ERROR,
      config.isDevelopment() ? { originalError: originalError?.message } : null,
      ERROR_SEVERITY.HIGH,
    );
    this.name = 'DatabaseError';
    this.originalError = originalError;
  }
}

/**
 * External Service Error Class
 */
class ExternalServiceError extends ApiError {
  constructor(service, message = 'External service error') {
    super(
      HTTP_STATUS.BAD_GATEWAY,
      message,
      ERROR_CODES.EXTERNAL_SERVICE_ERROR,
      { service },
      ERROR_SEVERITY.HIGH,
    );
    this.name = 'ExternalServiceError';
  }
}

/**
 * Security Error Class
 */
class SecurityError extends ApiError {
  constructor(message = 'Security violation detected', details = null) {
    super(
      HTTP_STATUS.FORBIDDEN,
      message,
      ERROR_CODES.SECURITY_VIOLATION,
      details,
      ERROR_SEVERITY.CRITICAL,
    );
    this.name = 'SecurityError';
  }
}

/**
 * Workspace Error Class
 */
class WorkspaceError extends ApiError {
  constructor(
    message = 'Workspace error',
    code = ERROR_CODES.WORKSPACE_NOT_FOUND,
  ) {
    super(HTTP_STATUS.FORBIDDEN, message, code, null, ERROR_SEVERITY.MEDIUM);
    this.name = 'WorkspaceError';
  }
}

/**
 * Error Factory Class
 */
class ErrorFactory {
  /**
   * Create error from Prisma error
   */
  static fromPrismaError(error) {
    switch (error.code) {
      case 'P2002':
        return new ConflictError(
          'Resource already exists',
          ERROR_CODES.DUPLICATE_RESOURCE,
        );
      case 'P2003':
        return new ValidationError('Foreign key constraint failed', {
          code: ERROR_CODES.FOREIGN_KEY_CONSTRAINT,
        });
      case 'P2025':
        return new NotFoundError('Record');
      case 'P1001':
        return new DatabaseError('Database connection failed', error);
      default:
        return new DatabaseError('Database operation failed', error);
    }
  }

  /**
   * Create error from JWT error
   */
  static fromJWTError(error) {
    switch (error.name) {
      case 'TokenExpiredError':
        return new AuthenticationError(
          'Token has expired',
          ERROR_CODES.TOKEN_EXPIRED,
        );
      case 'JsonWebTokenError':
        return new AuthenticationError(
          'Invalid token',
          ERROR_CODES.INVALID_TOKEN,
        );
      case 'NotBeforeError':
        return new AuthenticationError(
          'Token not active yet',
          ERROR_CODES.INVALID_TOKEN,
        );
      default:
        return new AuthenticationError(
          'Token verification failed',
          ERROR_CODES.INVALID_TOKEN,
        );
    }
  }

  /**
   * Create error from validation error
   */
  static fromValidationError(error) {
    if (error.details) {
      const details = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value,
      }));

      return new ValidationError('Validation failed', { fields: details });
    }

    return new ValidationError(error.message);
  }

  /**
   * Create error from Multer error (file upload)
   */
  static fromMulterError(error) {
    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        return new ValidationError('File too large', {
          code: ERROR_CODES.FILE_TOO_LARGE,
          limit: error.limit,
        });
      case 'LIMIT_FILE_COUNT':
        return new ValidationError('Too many files', {
          code: ERROR_CODES.VALIDATION_ERROR,
          limit: error.limit,
        });
      case 'LIMIT_UNEXPECTED_FILE':
        return new ValidationError('Unexpected file field', {
          code: ERROR_CODES.VALIDATION_ERROR,
          field: error.field,
        });
      default:
        return new ValidationError('File upload failed', {
          code: ERROR_CODES.UPLOAD_FAILED,
        });
    }
  }
}

/**
 * Error Handler Utility
 */
class ErrorHandler {
  /**
   * Handle and transform errors
   */
  static handle(error, req = null) {
    let apiError;

    // If already an ApiError, use as-is
    if (error instanceof ApiError) {
      apiError = error;
    } else {
      // Transform known error types
      switch (error.name) {
        case 'ValidationError':
          apiError = ErrorFactory.fromValidationError(error);
          break;
        case 'JsonWebTokenError':
        case 'TokenExpiredError':
        case 'NotBeforeError':
          apiError = ErrorFactory.fromJWTError(error);
          break;
        case 'MulterError':
          apiError = ErrorFactory.fromMulterError(error);
          break;
        default:
          // Check for Prisma errors
          if (error.code && error.code.startsWith('P')) {
            apiError = ErrorFactory.fromPrismaError(error);
          } else {
            // Generic error
            apiError = new ApiError(
              HTTP_STATUS.INTERNAL_SERVER_ERROR,
              config.isDevelopment() ? error.message : 'Internal Server Error',
              ERROR_CODES.INTERNAL_ERROR,
              config.isDevelopment() ? { originalError: error.message } : null,
              ERROR_SEVERITY.HIGH,
            );
          }
      }
    }

    // Log error with context
    const logContext = {
      error: apiError.toJSON(),
      requestId: req?.requestId,
      userId: req?.user?.id,
      workspaceId: req?.workspace?.id,
      ip: req?.ip,
      userAgent: req?.get?.('User-Agent'),
      method: req?.method,
      url: req?.originalUrl,
    };

    // Log based on severity
    switch (apiError.severity) {
      case ERROR_SEVERITY.CRITICAL:
        logger.error('Critical error occurred', logContext);
        break;
      case ERROR_SEVERITY.HIGH:
        logger.error('High severity error', logContext);
        break;
      case ERROR_SEVERITY.MEDIUM:
        logger.warn('Medium severity error', logContext);
        break;
      case ERROR_SEVERITY.LOW:
        logger.info('Low severity error', logContext);
        break;
      default:
        logger.error('Unknown severity error', logContext);
    }

    return apiError;
  }

  /**
   * Format error response
   */
  static formatResponse(error, req = null) {
    const apiError = this.handle(error, req);

    const response = {
      success: false,
      error: {
        code: apiError.code,
        message: apiError.getUserMessage(),
        statusCode: apiError.statusCode,
        timestamp: apiError.timestamp,
        requestId: req?.requestId,
      },
    };

    // Add details in development or for validation errors
    if (config.isDevelopment() || apiError.name === 'ValidationError') {
      if (apiError.details) {
        response.error.details = apiError.details;
      }
      if (config.isDevelopment()) {
        response.error.stack = apiError.stack;
      }
    }

    return response;
  }

  /**
   * Express error handler middleware
   */
  static middleware() {
    return (error, req, res, next) => {
      const apiError = this.handle(error, req);
      const response = this.formatResponse(apiError, req);

      res.status(apiError.statusCode).json(response);
    };
  }
}

/**
 * Utility functions
 */
const createError = (statusCode, message, code, details, severity) => {
  return new ApiError(statusCode, message, code, details, severity);
};

const createValidationError = (message, details) => {
  return new ValidationError(message, details);
};

const createAuthError = (message, code) => {
  return new AuthenticationError(message, code);
};

const createNotFoundError = (resource) => {
  return new NotFoundError(resource);
};

const createConflictError = (message, code) => {
  return new ConflictError(message, code);
};

const createWorkspaceError = (message, code) => {
  return new WorkspaceError(message, code);
};

const createSecurityError = (message, details) => {
  return new SecurityError(message, details);
};

module.exports = {
  // Classes
  ApiError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  SecurityError,
  WorkspaceError,

  // Utilities
  ErrorFactory,
  ErrorHandler,

  // Constants
  HTTP_STATUS,
  ERROR_CODES,
  ERROR_SEVERITY,

  // Helper functions
  createError,
  createValidationError,
  createAuthError,
  createNotFoundError,
  createConflictError,
  createWorkspaceError,
  createSecurityError,

  // Middleware
  errorHandler: ErrorHandler.middleware(),
};
