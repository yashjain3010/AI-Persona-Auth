const config = require('../config');
const logger = require('./logger');
const {
  generateTimestamp,
} = require('./common');

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
    this.timestamp = generateTimestamp();
    this.responseId = require('crypto').randomUUID();
  }

  setRequestContext(req) {
    if (req) {
      this.metadata.requestId = req.requestId;
      this.metadata.correlationId = req.correlationId;
      this.metadata.userId = req.user?.id;
      this.metadata.workspaceId = req.workspace?.id;
      if (req.startTime) {
        this.metadata.responseTime = Date.now() - req.startTime;
      }
    }
    return this;
  }

  setCacheControl(cacheControl) {
    this.metadata.cacheControl = cacheControl;
    return this;
  }

  sanitizeData(data) {
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
  }

  toJSON() {
    const response = {
      success: this.success,
      statusCode: this.statusCode,
      message: this.message,
      data: this.sanitizeData(this.data),
      timestamp: this.timestamp,
    };
    if (Object.keys(this.metadata).length > 0) {
      response.metadata = this.metadata;
    }
    if (config.isDevelopment()) {
      response.responseId = this.responseId;
    }
    return response;
  }

  send(res, req = null) {
    this.setRequestContext(req);
    if (this.metadata.cacheControl) {
      res.setHeader('Cache-Control', this.metadata.cacheControl);
    } else {
      res.setHeader('Cache-Control', CACHE_CONTROL.PRIVATE);
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    this.logResponse(req);
    return res.status(this.statusCode).json(this.toJSON());
  }

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
    if (this.statusCode >= 400) {
      logger.warn('API Response (Error)', logData);
    } else {
      logger.info('API Response (Success)', logData);
    }
  }
}

class SuccessResponse extends ApiResponse {
  constructor(data, message = 'Success', metadata = null) {
    super(200, data, message, metadata, RESPONSE_TYPES.SINGLE);
  }
}

module.exports = {
  ApiResponse,
  SuccessResponse,
  RESPONSE_STATUS,
  RESPONSE_TYPES,
  CACHE_CONTROL,
};
