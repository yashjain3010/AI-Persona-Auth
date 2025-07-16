/**
 * API Response Utility
 *
 * This module provides standardized response formatting for a multi-tenant SaaS
 * application with enterprise-grade response handling, metadata support, and
 * comprehensive logging integration.
 *
 * Key Features:
 * - Standardized response structure across all endpoints
 * - Support for success and error responses
 * - Pagination metadata handling
 * - Request correlation and tracing
 * - Performance metrics tracking
 * - Multi-tenant context support
 * - Development vs Production response formatting
 * - Integration with logging system
 * - Response caching headers
 * - Security-focused response sanitization
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const config = require('../config');
const logger = require('./logger');

/**
 * Standard Response Status Codes
 */
const RESPONSE_STATUS = {
  SUCCESS: 'success',
  ERROR: 'error',
  FAIL: 'fail',
};

/**
 * Response Types
 */
const RESPONSE_TYPES = {
  SINGLE: 'single',
  LIST: 'list',
  PAGINATED: 'paginated',
  STREAM: 'stream',
  BINARY: 'binary',
};

/**
 * Cache Control Headers
 */
const CACHE_CONTROL = {
  NO_CACHE: 'no-cache, no-store, must-revalidate',
  PUBLIC: 'public, max-age=300', // 5 minutes
  PRIVATE: 'private, max-age=60', // 1 minute
  LONG_TERM: 'public, max-age=86400', // 24 hours
};

/**
 * Base API Response Class
 */
class ApiResponse {
  constructor(
    statusCode = 200,
    data = null,
    message = 'Success',
    metadata = null,
    type = RESPONSE_TYPES.SINGLE,
  ) {
    this.success = statusCode >= 200 && statusCode < 300;
    this.statusCode = statusCode;
    this.message = message;
    this.data = data;
    this.metadata = metadata || {};
    this.type = type;
    this.timestamp = new Date().toISOString();

    // Add response ID for tracking
    this.responseId = require('crypto').randomUUID();
  }

  /**
   * Set request context for correlation
   */
  setRequestContext(req) {
    if (req) {
      this.metadata.requestId = req.requestId;
      this.metadata.correlationId = req.correlationId;
      this.metadata.userId = req.user?.id;
      this.metadata.workspaceId = req.workspace?.id;

      // Add performance metrics
      if (req.startTime) {
        this.metadata.responseTime = Date.now() - req.startTime;
      }
    }
    return this;
  }

  /**
   * Set pagination metadata
   */
  setPagination(pagination) {
    this.type = RESPONSE_TYPES.PAGINATED;
    this.metadata.pagination = {
      page: pagination.page,
      limit: pagination.limit,
      totalCount: pagination.totalCount,
      totalPages: pagination.totalPages,
      hasNextPage: pagination.hasNextPage,
      hasPreviousPage: pagination.hasPreviousPage,
    };
    return this;
  }

  /**
   * Set cache control headers
   */
  setCacheControl(cacheControl) {
    this.metadata.cacheControl = cacheControl;
    return this;
  }

  /**
   * Add custom metadata
   */
  addMetadata(key, value) {
    this.metadata[key] = value;
    return this;
  }

  /**
   * Set response type
   */
  setType(type) {
    this.type = type;
    return this;
  }

  /**
   * Sanitize sensitive data for production
   */
  sanitizeData(data) {
    if (!data || typeof data !== 'object') {
      return data;
    }

    // Fields to remove in production
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
  }

  /**
   * Convert to JSON format
   */
  toJSON() {
    const response = {
      success: this.success,
      statusCode: this.statusCode,
      message: this.message,
      data: this.sanitizeData(this.data),
      timestamp: this.timestamp,
    };

    // Add metadata if present
    if (Object.keys(this.metadata).length > 0) {
      response.metadata = this.metadata;
    }

    // Add response ID in development
    if (config.isDevelopment()) {
      response.responseId = this.responseId;
    }

    return response;
  }

  /**
   * Send response with Express
   */
  send(res, req = null) {
    // Set request context
    this.setRequestContext(req);

    // Set cache control headers
    if (this.metadata.cacheControl) {
      res.setHeader('Cache-Control', this.metadata.cacheControl);
    } else {
      // Default cache control based on response type
      switch (this.type) {
        case RESPONSE_TYPES.SINGLE:
          res.setHeader('Cache-Control', CACHE_CONTROL.PRIVATE);
          break;
        case RESPONSE_TYPES.LIST:
        case RESPONSE_TYPES.PAGINATED:
          res.setHeader('Cache-Control', CACHE_CONTROL.NO_CACHE);
          break;
        default:
          res.setHeader('Cache-Control', CACHE_CONTROL.NO_CACHE);
      }
    }

    // Set security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    // Log response
    this.logResponse(req);

    // Send response
    return res.status(this.statusCode).json(this.toJSON());
  }

  /**
   * Log response details
   */
  logResponse(req) {
    const logData = {
      responseId: this.responseId,
      statusCode: this.statusCode,
      success: this.success,
      message: this.message,
      type: this.type,
      dataSize: this.data ? JSON.stringify(this.data).length : 0,
      metadata: this.metadata,
    };

    if (req) {
      logData.requestId = req.requestId;
      logData.method = req.method;
      logData.url = req.originalUrl;
      logData.userId = req.user?.id;
      logData.workspaceId = req.workspace?.id;
    }

    // Log based on status code
    if (this.statusCode >= 400) {
      logger.warn('API Response (Error)', logData);
    } else {
      logger.info('API Response (Success)', logData);
    }
  }
}

/**
 * Success Response Factory
 */
class SuccessResponse extends ApiResponse {
  constructor(data, message = 'Success', metadata = null) {
    super(200, data, message, metadata, RESPONSE_TYPES.SINGLE);
  }
}

/**
 * Created Response Factory
 */
class CreatedResponse extends ApiResponse {
  constructor(
    data,
    message = 'Resource created successfully',
    metadata = null,
  ) {
    super(201, data, message, metadata, RESPONSE_TYPES.SINGLE);
  }
}

/**
 * No Content Response Factory
 */
class NoContentResponse extends ApiResponse {
  constructor(message = 'Operation completed successfully') {
    super(204, null, message, null, RESPONSE_TYPES.SINGLE);
  }
}

/**
 * List Response Factory
 */
class ListResponse extends ApiResponse {
  constructor(data, message = 'Data retrieved successfully', metadata = null) {
    super(200, data, message, metadata, RESPONSE_TYPES.LIST);
  }
}

/**
 * Paginated Response Factory
 */
class PaginatedResponse extends ApiResponse {
  constructor(
    data,
    pagination,
    message = 'Data retrieved successfully',
    metadata = null,
  ) {
    super(200, data, message, metadata, RESPONSE_TYPES.PAGINATED);
    this.setPagination(pagination);
  }
}

/**
 * Response Builder Class
 */
class ResponseBuilder {
  constructor() {
    this.reset();
  }

  reset() {
    this._statusCode = 200;
    this._data = null;
    this._message = 'Success';
    this._metadata = {};
    this._type = RESPONSE_TYPES.SINGLE;
    this._cacheControl = null;
    return this;
  }

  statusCode(code) {
    this._statusCode = code;
    return this;
  }

  data(data) {
    this._data = data;
    return this;
  }

  message(message) {
    this._message = message;
    return this;
  }

  metadata(metadata) {
    this._metadata = { ...this._metadata, ...metadata };
    return this;
  }

  type(type) {
    this._type = type;
    return this;
  }

  pagination(pagination) {
    this._type = RESPONSE_TYPES.PAGINATED;
    this._metadata.pagination = pagination;
    return this;
  }

  cacheControl(cacheControl) {
    this._cacheControl = cacheControl;
    return this;
  }

  build() {
    const response = new ApiResponse(
      this._statusCode,
      this._data,
      this._message,
      this._metadata,
      this._type,
    );

    if (this._cacheControl) {
      response.setCacheControl(this._cacheControl);
    }

    return response;
  }
}

/**
 * Response Utilities
 */
class ResponseUtils {
  /**
   * Create success response
   */
  static success(data, message = 'Success', metadata = null) {
    return new SuccessResponse(data, message, metadata);
  }

  /**
   * Create created response
   */
  static created(
    data,
    message = 'Resource created successfully',
    metadata = null,
  ) {
    return new CreatedResponse(data, message, metadata);
  }

  /**
   * Create no content response
   */
  static noContent(message = 'Operation completed successfully') {
    return new NoContentResponse(message);
  }

  /**
   * Create list response
   */
  static list(data, message = 'Data retrieved successfully', metadata = null) {
    return new ListResponse(data, message, metadata);
  }

  /**
   * Create paginated response
   */
  static paginated(
    data,
    pagination,
    message = 'Data retrieved successfully',
    metadata = null,
  ) {
    return new PaginatedResponse(data, pagination, message, metadata);
  }

  /**
   * Create response builder
   */
  static builder() {
    return new ResponseBuilder();
  }

  /**
   * Transform service response to API response
   */
  static fromService(serviceResponse, defaultMessage = 'Operation completed') {
    if (!serviceResponse || typeof serviceResponse !== 'object') {
      return new SuccessResponse(serviceResponse, defaultMessage);
    }

    const { success, data, message, metadata, pagination } = serviceResponse;

    if (success === false) {
      // This should be handled by error middleware
      throw new Error(message || 'Service operation failed');
    }

    if (pagination) {
      return new PaginatedResponse(
        data,
        pagination,
        message || defaultMessage,
        metadata,
      );
    }

    if (Array.isArray(data)) {
      return new ListResponse(data, message || defaultMessage, metadata);
    }

    return new SuccessResponse(data, message || defaultMessage, metadata);
  }

  /**
   * Format validation errors
   */
  static validationError(errors, message = 'Validation failed') {
    return new ApiResponse(
      400,
      null,
      message,
      { errors },
      RESPONSE_TYPES.SINGLE,
    );
  }

  /**
   * Format health check response
   */
  static healthCheck(status, checks = {}) {
    const isHealthy = status === 'healthy';
    const statusCode = isHealthy ? 200 : 503;
    const message = isHealthy ? 'System is healthy' : 'System is unhealthy';

    return new ApiResponse(statusCode, { status, checks }, message, {
      timestamp: new Date().toISOString(),
      environment: config.NODE_ENV,
    });
  }
}

/**
 * Express Response Extensions
 */
const extendExpressResponse = (res) => {
  // Add convenience methods to Express response
  res.success = (data, message, metadata) => {
    return ResponseUtils.success(data, message, metadata).send(res, res.req);
  };

  res.created = (data, message, metadata) => {
    return ResponseUtils.created(data, message, metadata).send(res, res.req);
  };

  res.noContent = (message) => {
    return ResponseUtils.noContent(message).send(res, res.req);
  };

  res.list = (data, message, metadata) => {
    return ResponseUtils.list(data, message, metadata).send(res, res.req);
  };

  res.paginated = (data, pagination, message, metadata) => {
    return ResponseUtils.paginated(data, pagination, message, metadata).send(
      res,
      res.req,
    );
  };

  return res;
};

/**
 * Express middleware to extend response object
 */
const responseMiddleware = (req, res, next) => {
  // Add start time for performance tracking
  req.startTime = Date.now();

  // Extend response object
  extendExpressResponse(res);

  next();
};

module.exports = {
  // Main classes
  ApiResponse,
  SuccessResponse,
  CreatedResponse,
  NoContentResponse,
  ListResponse,
  PaginatedResponse,
  ResponseBuilder,

  // Utilities
  ResponseUtils,

  // Constants
  RESPONSE_STATUS,
  RESPONSE_TYPES,
  CACHE_CONTROL,

  // Middleware
  responseMiddleware,
  extendExpressResponse,
};
