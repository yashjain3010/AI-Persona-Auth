const config = require('../config');
const logger = require('./logger');
const { ApiError } = require('./apiError');
const { generateTimestamp } = require('./common');

/**
 * Performance Metrics Collector
 */
class PerformanceMetrics {
  constructor() {
    this.metrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageExecutionTime: 0,
      slowestExecution: 0,
      fastestExecution: Infinity,
      timeouts: 0,
      memoryLeaks: 0,
      lastReset: new Date(),
    };
    this.executionTimes = [];
    this.maxExecutionHistory = 1000; // Keep last 1000 executions
  }

  /**
   * Record execution metrics
   */
  recordExecution(duration, error = null) {
    this.metrics.totalRequests++;

    if (error) {
      this.metrics.totalErrors++;
    }

    // Track execution time
    this.executionTimes.push(duration);
    if (this.executionTimes.length > this.maxExecutionHistory) {
      this.executionTimes.shift();
    }

    // Update timing metrics
    this.metrics.slowestExecution = Math.max(
      this.metrics.slowestExecution,
      duration,
    );
    this.metrics.fastestExecution = Math.min(
      this.metrics.fastestExecution,
      duration,
    );

    // Calculate average
    this.metrics.averageExecutionTime =
      this.executionTimes.reduce((sum, time) => sum + time, 0) /
      this.executionTimes.length;
  }

  /**
   * Record timeout
   */
  recordTimeout() {
    this.metrics.timeouts++;
  }

  /**
   * Record memory leak detection
   */
  recordMemoryLeak() {
    this.metrics.memoryLeaks++;
  }

  /**
   * Get current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      errorRate: this.metrics.totalErrors / this.metrics.totalRequests || 0,
      uptime: Date.now() - this.metrics.lastReset.getTime(),
    };
  }

  /**
   * Reset metrics
   */
  reset() {
    this.metrics = {
      totalRequests: 0,
      totalErrors: 0,
      averageExecutionTime: 0,
      slowestExecution: 0,
      fastestExecution: Infinity,
      timeouts: 0,
      memoryLeaks: 0,
      lastReset: new Date(),
    };
    this.executionTimes = [];
  }
}

/**
 * Global performance metrics instance
 */
const performanceMetrics = new PerformanceMetrics();

/**
 * Async Handler Class
 */
class AsyncHandler {
  constructor(options = {}) {
    this.options = {
      enableMetrics: config.isDevelopment() || options.enableMetrics,
      enableTimeouts: options.enableTimeouts !== false,
      defaultTimeout: options.defaultTimeout || 30000, // 30 seconds
      enableMemoryTracking:
        config.isDevelopment() || options.enableMemoryTracking,
      enableCorrelation: options.enableCorrelation !== false,
      enablePerformanceLogging: options.enablePerformanceLogging !== false,
      ...options,
    };
  }

  /**
   * Wrap async function with comprehensive error handling
   */
  wrap(asyncFn, options = {}) {
    const handlerOptions = { ...this.options, ...options };

    return (req, res, next) => {
      // Start performance tracking
      const startTime = Date.now();
      const startMemory = handlerOptions.enableMemoryTracking
        ? process.memoryUsage().heapUsed
        : 0;

      // Set up timeout handling
      let timeoutId;
      if (handlerOptions.enableTimeouts) {
        timeoutId = setTimeout(() => {
          performanceMetrics.recordTimeout();
          logger.warn('Async handler timeout', {
            requestId: req.requestId,
            method: req.method,
            url: req.originalUrl,
            timeout: handlerOptions.defaultTimeout,
            userId: req.user?.id,
            workspaceId: req.workspace?.id,
          });

          const timeoutError = new ApiError(
            408,
            'Request timeout',
            'REQUEST_TIMEOUT',
            { timeout: handlerOptions.defaultTimeout },
            'medium',
          );

          next(timeoutError);
        }, handlerOptions.defaultTimeout);
      }

      // Execute async function
      const executeAsync = async () => {
        try {
          // Add execution context
          if (handlerOptions.enableCorrelation && req) {
            req.executionContext = {
              startTime,
              handlerId: require('crypto').randomUUID(),
              timeout: handlerOptions.defaultTimeout,
            };
          }

          // Execute the wrapped function
          const result = await asyncFn(req, res, next);

          // Clear timeout
          if (timeoutId) {
            clearTimeout(timeoutId);
          }

          // Record successful execution
          const executionTime = Date.now() - startTime;
          if (handlerOptions.enableMetrics) {
            performanceMetrics.recordExecution(executionTime);
          }

          // Log performance metrics
          if (handlerOptions.enablePerformanceLogging) {
            this.logPerformanceMetrics(req, executionTime, startMemory);
          }

          return result;
        } catch (error) {
          // Clear timeout
          if (timeoutId) {
            clearTimeout(timeoutId);
          }

          // Record error execution
          const executionTime = Date.now() - startTime;
          if (handlerOptions.enableMetrics) {
            performanceMetrics.recordExecution(executionTime, error);
          }

          // Check for memory leaks
          if (handlerOptions.enableMemoryTracking) {
            this.checkMemoryLeak(startMemory, req);
          }

          // Log error with context
          this.logError(error, req, executionTime);

          // Pass error to Express error handler
          next(error);
        }
      };

      // Execute with Promise handling
      executeAsync().catch((error) => {
        // This catch block handles any errors in the executeAsync function itself
        logger.error('Critical async handler error', {
          error: error.message,
          stack: error.stack,
          requestId: req?.requestId || 'unknown',
          method: req?.method || 'unknown',
          url: req?.originalUrl || 'unknown',
        });

        // Clear timeout
        if (timeoutId) {
          clearTimeout(timeoutId);
        }

        // Create critical error
        const criticalError = new ApiError(
          500,
          'Internal server error',
          'CRITICAL_ASYNC_ERROR',
          config.isDevelopment() ? { originalError: error.message } : null,
          'critical',
        );

        // Only call next if it exists
        if (next && typeof next === 'function') {
          next(criticalError);
        }
      });
    };
  }

  /**
   * Log performance metrics
   */
  logPerformanceMetrics(req, executionTime, startMemory) {
    const memoryUsed = this.options.enableMemoryTracking
      ? process.memoryUsage().heapUsed - startMemory
      : 0;

    const logData = {
      requestId: req?.requestId || 'unknown',
      method: req?.method || 'unknown',
      url: req?.originalUrl || 'unknown',
      executionTime,
      memoryUsed: memoryUsed > 0 ? `${Math.round(memoryUsed / 1024)}KB` : 'N/A',
      userId: req?.user?.id || 'unknown',
      workspaceId: req?.workspace?.id || 'unknown',
    };

    // Log slow requests
    if (executionTime > 1000) {
      logger.warn('Slow async handler execution', logData);
    } else if (config.isDevelopment()) {
      logger.debug('Async handler performance', logData);
    }

    // Log high memory usage
    if (memoryUsed > 10 * 1024 * 1024) {
      // 10MB threshold
      logger.warn('High memory usage in async handler', logData);
    }
  }

  /**
   * Check for potential memory leaks
   */
  checkMemoryLeak(startMemory, req) {
    const memoryUsed = process.memoryUsage().heapUsed - startMemory;
    const memoryThreshold = 50 * 1024 * 1024; // 50MB threshold

    if (memoryUsed > memoryThreshold) {
      performanceMetrics.recordMemoryLeak();
      logger.warn('Potential memory leak detected', {
        requestId: req.requestId,
        method: req.method,
        url: req.originalUrl,
        memoryUsed: `${Math.round(memoryUsed / 1024 / 1024)}MB`,
        threshold: `${Math.round(memoryThreshold / 1024 / 1024)}MB`,
        userId: req.user?.id,
        workspaceId: req.workspace?.id,
      });
    }
  }

  /**
   * Log error with comprehensive context
   */
  logError(error, req, executionTime) {
    const errorContext = {
      requestId: req?.requestId || 'unknown',
      method: req?.method || 'unknown',
      url: req?.originalUrl || 'unknown',
      executionTime,
      userId: req?.user?.id || 'unknown',
      workspaceId: req?.workspace?.id || 'unknown',
      ip: req?.ip || 'unknown',
      userAgent: req?.get ? req.get('User-Agent') : 'unknown',
      body: config.isDevelopment() ? req?.body : '[REDACTED]',
      query: req?.query,
      params: req?.params,
      headers: config.isDevelopment() ? req?.headers : '[REDACTED]',
      timestamp: generateTimestamp(),
    };

    // Log based on error type
    if (error instanceof ApiError) {
      logger.error('API Error in async handler', {
        ...errorContext,
        error: error.toJSON(),
      });
    } else {
      logger.error('Unhandled error in async handler', {
        ...errorContext,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack,
        },
      });
    }
  }

  /**
   * Get performance metrics
   */
  getMetrics() {
    return performanceMetrics.getMetrics();
  }

  /**
   * Reset performance metrics
   */
  resetMetrics() {
    performanceMetrics.reset();
  }
}

/**
 * Default async handler instance
 */
const defaultAsyncHandler = new AsyncHandler();

/**
 * Main async handler function
 * This is the primary export that wraps async functions
 */
const asyncHandler = (asyncFn, options = {}) => {
  return defaultAsyncHandler.wrap(asyncFn, options);
};

/**
 * Only export asyncHandler and default
 */
module.exports = {
  asyncHandler,
  default: asyncHandler,
};
