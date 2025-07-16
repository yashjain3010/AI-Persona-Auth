/**
 * Logging Utility
 *
 * This module provides a comprehensive logging solution for a multi-tenant SaaS
 * application with enterprise-grade features including structured logging,
 * multiple transports, log rotation, and security event tracking.
 *
 * Key Features:
 * - Structured JSON logging with metadata
 * - Multiple log levels and transports
 * - File rotation and archiving
 * - Request correlation and tracing
 * - Security event logging
 * - Performance metrics logging
 * - Development vs Production optimizations
 * - Multi-tenant context support
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');
const DailyRotateFile = require('winston-daily-rotate-file');
const config = require('../config');

/**
 * Log Levels Configuration
 * Using RFC5424 syslog levels
 */
const LOG_LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
  trace: 5,
};

/**
 * Log Colors for Console Output
 */
const LOG_COLORS = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'cyan',
  trace: 'gray',
};

/**
 * Ensure log directory exists
 */
const LOG_DIR = path.join(__dirname, '../logs');
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * Custom Log Format for Development
 * Includes emojis and colors for better readability
 */
const developmentFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    // Add emoji based on log level
    const emoji =
      {
        error: '❌',
        warn: '⚠️ ',
        info: '✅',
        http: '🌐',
        debug: '🔍',
        trace: '🔬',
      }[level.replace(/\u001b\[[0-9;]*m/g, '')] || '📝';

    let logMessage = `${emoji} [${timestamp}] ${level}: ${message}`;

    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      logMessage += `\n${JSON.stringify(meta, null, 2)}`;
    }

    return logMessage;
  }),
);

/**
 * Custom Log Format for Production
 * Structured JSON format for log aggregation systems
 */
const productionFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => {
    // Ensure consistent structure
    const logEntry = {
      timestamp: info.timestamp,
      level: info.level,
      message: info.message,
      service: 'ai-persona-backend',
      environment: config.NODE_ENV,
      ...info,
    };

    // Remove duplicate fields
    delete logEntry.timestamp;
    delete logEntry.level;
    delete logEntry.message;

    return JSON.stringify({
      timestamp: info.timestamp,
      level: info.level,
      message: info.message,
      ...logEntry,
    });
  }),
);

/**
 * Create File Transport with Rotation
 */
const createFileTransport = (filename, level = 'info') => {
  return new DailyRotateFile({
    filename: path.join(LOG_DIR, `${filename}-%DATE%.log`),
    datePattern: 'YYYY-MM-DD',
    maxSize: '100m',
    maxFiles: '30d',
    level,
    format: productionFormat,
    auditFile: path.join(LOG_DIR, `${filename}-audit.json`),
    createSymlink: true,
    symlinkName: `${filename}-current.log`,
  });
};

/**
 * Create Console Transport
 */
const createConsoleTransport = () => {
  return new winston.transports.Console({
    level: config.isDevelopment() ? 'debug' : 'info',
    format: config.isDevelopment() ? developmentFormat : productionFormat,
    handleExceptions: true,
    handleRejections: true,
  });
};

/**
 * Create HTTP Transport for External Log Aggregation
 */
const createHttpTransport = () => {
  if (!config.logging?.httpEndpoint) {
    return null;
  }

  return new winston.transports.Http({
    host: config.logging.httpHost,
    port: config.logging.httpPort,
    path: config.logging.httpPath,
    level: 'error',
    format: productionFormat,
    ssl: config.logging.httpSsl,
    auth: config.logging.httpAuth,
  });
};

/**
 * Configure Winston Logger
 */
const transports = [
  createConsoleTransport(),
  createFileTransport('combined', 'info'),
  createFileTransport('error', 'error'),
  createFileTransport('security', 'warn'),
];

// Add HTTP transport for production
const httpTransport = createHttpTransport();
if (httpTransport) {
  transports.push(httpTransport);
}

/**
 * Create Winston Logger Instance
 */
const logger = winston.createLogger({
  levels: LOG_LEVELS,
  level: config.logging?.level || (config.isDevelopment() ? 'debug' : 'info'),
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }),
  ),
  transports,
  exitOnError: false,
  silent: config.NODE_ENV === 'test',
});

// Add colors to Winston
winston.addColors(LOG_COLORS);

/**
 * Enhanced Logger Class with Additional Features
 */
class EnhancedLogger {
  constructor(winstonLogger) {
    this.winston = winstonLogger;
    this.requestContext = new Map();
    this.performanceMetrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageResponseTime: 0,
      lastReset: new Date(),
    };
  }

  /**
   * Set request context for correlation
   */
  setRequestContext(requestId, context) {
    this.requestContext.set(requestId, {
      ...context,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get request context
   */
  getRequestContext(requestId) {
    return this.requestContext.get(requestId);
  }

  /**
   * Clear request context
   */
  clearRequestContext(requestId) {
    this.requestContext.delete(requestId);
  }

  /**
   * Create child logger with persistent context
   */
  child(context) {
    const childLogger = Object.create(this);
    childLogger.defaultContext = { ...this.defaultContext, ...context };
    return childLogger;
  }

  /**
   * Enhanced logging methods with context support
   */
  log(level, message, meta = {}) {
    const enrichedMeta = {
      ...this.defaultContext,
      ...meta,
      pid: process.pid,
      hostname: require('os').hostname(),
    };

    // Add request context if available
    if (meta.requestId) {
      const requestContext = this.getRequestContext(meta.requestId);
      if (requestContext) {
        enrichedMeta.request = requestContext;
      }
    }

    this.winston.log(level, message, enrichedMeta);
  }

  /**
   * Standard logging methods
   */
  error(message, meta = {}) {
    this.performanceMetrics.totalErrors++;
    this.log('error', message, { ...meta, severity: 'error' });
  }

  warn(message, meta = {}) {
    this.log('warn', message, { ...meta, severity: 'warning' });
  }

  info(message, meta = {}) {
    this.log('info', message, { ...meta, severity: 'info' });
  }

  http(message, meta = {}) {
    this.log('http', message, { ...meta, category: 'http' });
  }

  debug(message, meta = {}) {
    this.log('debug', message, { ...meta, category: 'debug' });
  }

  trace(message, meta = {}) {
    this.log('trace', message, { ...meta, category: 'trace' });
  }

  /**
   * Security event logging
   */
  security(event, details = {}) {
    this.log('warn', `Security Event: ${event}`, {
      ...details,
      category: 'security',
      event,
      severity: 'security',
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Performance logging
   */
  performance(operation, duration, meta = {}) {
    this.performanceMetrics.totalRequests++;
    this.performanceMetrics.averageResponseTime =
      (this.performanceMetrics.averageResponseTime + duration) / 2;

    this.log('info', `Performance: ${operation}`, {
      ...meta,
      category: 'performance',
      operation,
      duration,
      unit: 'ms',
    });
  }

  /**
   * Database operation logging
   */
  database(operation, query, duration, meta = {}) {
    this.log('debug', `Database: ${operation}`, {
      ...meta,
      category: 'database',
      operation,
      query: config.isDevelopment() ? query : '[REDACTED]',
      duration,
      unit: 'ms',
    });
  }

  /**
   * Authentication event logging
   */
  auth(event, userId, workspaceId, meta = {}) {
    this.log('info', `Auth Event: ${event}`, {
      ...meta,
      category: 'authentication',
      event,
      userId,
      workspaceId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Workspace activity logging
   */
  workspace(action, workspaceId, userId, meta = {}) {
    this.log('info', `Workspace: ${action}`, {
      ...meta,
      category: 'workspace',
      action,
      workspaceId,
      userId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * API request logging
   */
  request(method, url, statusCode, duration, meta = {}) {
    const level = statusCode >= 400 ? 'warn' : 'info';

    this.log(level, `${method} ${url} ${statusCode}`, {
      ...meta,
      category: 'api',
      method,
      url,
      statusCode,
      duration,
      unit: 'ms',
    });
  }

  /**
   * Email event logging
   */
  email(event, recipient, template, meta = {}) {
    this.log('info', `Email: ${event}`, {
      ...meta,
      category: 'email',
      event,
      recipient: config.isDevelopment() ? recipient : '[REDACTED]',
      template,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Background job logging
   */
  job(jobName, status, duration, meta = {}) {
    const level = status === 'failed' ? 'error' : 'info';

    this.log(level, `Job: ${jobName} ${status}`, {
      ...meta,
      category: 'job',
      jobName,
      status,
      duration,
      unit: 'ms',
    });
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    return {
      ...this.performanceMetrics,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      activeContexts: this.requestContext.size,
    };
  }

  /**
   * Reset performance metrics
   */
  resetMetrics() {
    this.performanceMetrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageResponseTime: 0,
      lastReset: new Date(),
    };
  }

  /**
   * Health check for logger
   */
  healthCheck() {
    try {
      this.info('Logger health check', { category: 'health' });
      return {
        status: 'healthy',
        transports: this.winston.transports.length,
        level: this.winston.level,
        metrics: this.getMetrics(),
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
      };
    }
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    this.info('Logger shutting down gracefully');

    return new Promise((resolve) => {
      this.winston.end(() => {
        this.info('Logger shutdown completed');
        resolve();
      });
    });
  }
}

/**
 * Create enhanced logger instance
 */
const enhancedLogger = new EnhancedLogger(logger);

/**
 * Request correlation middleware helper
 */
enhancedLogger.requestMiddleware = (req, res, next) => {
  const requestId = req.requestId || require('crypto').randomUUID();
  const startTime = Date.now();

  // Set request context
  enhancedLogger.setRequestContext(requestId, {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    workspaceId: req.workspace?.id,
  });

  // Log request start
  enhancedLogger.request(req.method, req.originalUrl, 'START', 0, {
    requestId,
    ip: req.ip,
  });

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function (...args) {
    const duration = Date.now() - startTime;

    enhancedLogger.request(
      req.method,
      req.originalUrl,
      res.statusCode,
      duration,
      {
        requestId,
        ip: req.ip,
        userId: req.user?.id,
        workspaceId: req.workspace?.id,
      },
    );

    // Clear request context
    enhancedLogger.clearRequestContext(requestId);

    originalEnd.apply(this, args);
  };

  next();
};

/**
 * Error logging helper
 */
enhancedLogger.errorHandler = (error, req, res, next) => {
  enhancedLogger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id,
    workspaceId: req.workspace?.id,
  });

  next(error);
};

// Handle logger errors
logger.on('error', (error) => {
  console.error('Logger error:', error);
});

// Cleanup on process exit
process.on('beforeExit', async () => {
  await enhancedLogger.shutdown();
});

module.exports = enhancedLogger;
