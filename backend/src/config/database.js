const { PrismaClient } = require('@prisma/client');
const config = require('./index');
const logger = require('../utils/logger');
const { generateTimestamp } = require('../utils/common');
const { ApiError, DatabaseError, ErrorHandler } = require('../utils/apiError');
const { asyncHandler } = require('../utils/asyncHandler');

/**
 * Database Connection States
 */
const CONNECTION_STATES = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTING: 'disconnecting',
  ERROR: 'error',
  RECONNECTING: 'reconnecting',
};

/**
 * Database Operation Types for logging
 */
const OPERATION_TYPES = {
  QUERY: 'query',
  MUTATION: 'mutation',
  TRANSACTION: 'transaction',
  HEALTH_CHECK: 'health_check',
  CLEANUP: 'cleanup',
};

/**
 * Database Manager Class
 * Manages Prisma client lifecycle and provides enterprise features
 */
class DatabaseManager {
  constructor() {
    this.prisma = null;
    this.connectionState = CONNECTION_STATES.DISCONNECTED;
    this.connectionAttempts = 0;
    this.maxRetries = config.database?.maxRetries || 3;
    this.retryDelay = 5000; // 5 seconds
    this.healthCheckInterval = null;
    this.cleanupInterval = null;
    this.reconnectTimeout = null;

    // Enhanced metrics
    this.metrics = {
      queriesExecuted: 0,
      transactionsExecuted: 0,
      errorsEncountered: 0,
      connectionUptime: null,
      lastHealthCheck: null,
      slowQueries: 0,
      reconnectAttempts: 0,
      cleanupOperations: 0,
    };

    // Performance thresholds
    this.slowQueryThreshold = 1000; // 1 second
    this.connectionTimeout = config.database?.connectionTimeout || 10000;
    this.queryTimeout = config.database?.queryTimeout || 30000;
  }

  /**
   * Initialize Prisma client with enterprise configuration
   * @returns {Promise<PrismaClient>} Configured Prisma client
   */
  async initialize() {
    if (this.prisma && this.connectionState === CONNECTION_STATES.CONNECTED) {
      return this.prisma;
    }

    this.connectionState = CONNECTION_STATES.CONNECTING;
    this.connectionAttempts++;

    try {
      logger.info('Initializing database connection', {
        attempt: this.connectionAttempts,
        maxRetries: this.maxRetries,
        environment: config.NODE_ENV,
        poolSize: config.database?.poolSize,
      });

      // Prisma Client Configuration
      const prismaConfig = {
        // Datasource configuration
        datasources: {
          db: {
            url: config.database?.url || config.DATABASE_URL,
          },
        },

        // Logging configuration based on environment
        log: this._getLogConfig(),

        // Error formatting
        errorFormat: config.isDevelopment() ? 'pretty' : 'minimal',

        // Connection pool settings are configured via DATABASE_URL
        // No connectionLimit parameter needed here
      };

      // Initialize Prisma Client
      this.prisma = new PrismaClient(prismaConfig);

      // Set up query logging and metrics
      this._setupQueryLogging();

      // Set up error handling
      this._setupErrorHandling();

      // Test connection
      await this._testConnection();

      // Set up health monitoring
      this._setupHealthMonitoring();

      // Set up cleanup tasks
      this._setupCleanupTasks();

      this.connectionState = CONNECTION_STATES.CONNECTED;
      this.metrics.connectionUptime = new Date();
      this.connectionAttempts = 0; // Reset on successful connection

      logger.info('Database connected successfully', {
        poolSize: config.database?.poolSize || 'default',
        ssl: config.database?.ssl,
        environment: config.NODE_ENV,
        uptime: 0,
      });

      return this.prisma;
    } catch (error) {
      this.connectionState = CONNECTION_STATES.ERROR;
      this.metrics.errorsEncountered++;

      const dbError = new DatabaseError(
        `Database initialization failed: ${error.message}`,
        error,
      );

      logger.error('Database initialization failed', {
        error: dbError.toJSON(),
        attempt: this.connectionAttempts,
        maxRetries: this.maxRetries,
      });

      // Retry logic for connection failures
      if (this.connectionAttempts < this.maxRetries) {
        logger.warn(`Retrying database connection in ${this.retryDelay}ms`, {
          attempt: this.connectionAttempts,
          maxRetries: this.maxRetries,
        });

        await new Promise((resolve) => setTimeout(resolve, this.retryDelay));
        return this.initialize();
      }

      // Max retries exceeded
      logger.error('Database connection failed after maximum retries', {
        attempts: this.connectionAttempts,
        maxRetries: this.maxRetries,
      });

      throw dbError;
    }
  }

  /**
   * Get logging configuration based on environment
   * @returns {Array} Prisma log configuration
   * @private
   */
  _getLogConfig() {
    // NOTE: In production, avoid enabling 'query' logs unless actively debugging to prevent excessive log volume and performance impact.
    if (config.isDevelopment()) {
      return [
        {
          emit: 'event',
          level: 'query',
        },
        {
          emit: 'event',
          level: 'error',
        },
        {
          emit: 'event',
          level: 'info',
        },
        {
          emit: 'event',
          level: 'warn',
        },
      ];
    }

    return [
      {
        emit: 'event',
        level: 'error',
      },
      {
        emit: 'event',
        level: 'warn',
      },
    ];
  }

  /**
   * Set up query logging and performance monitoring
   * @private
   */
  _setupQueryLogging() {
    // Query performance logging
    this.prisma.$on('query', (e) => {
      this.metrics.queriesExecuted++;

      const duration = e.duration;
      const isSlowQuery = duration > this.slowQueryThreshold;

      if (isSlowQuery) {
        this.metrics.slowQueries++;
        logger.warn('Slow database query detected', {
          duration: `${duration}ms`,
          query:
            e.query.substring(0, 200) + (e.query.length > 200 ? '...' : ''),
          params: config.isDevelopment() ? e.params : '[REDACTED]',
          target: e.target,
          timestamp: e.timestamp,
        });
      }

      // Debug logging in development
      if (config.isDevelopment() && config.LOG_LEVEL === 'debug') {
        logger.debug('Database query executed', {
          duration: `${duration}ms`,
          query: e.query.substring(0, 100) + '...',
          params: e.params,
          target: e.target,
        });
      }
    });

    // Info logging
    this.prisma.$on('info', (e) => {
      logger.info('Database info', {
        message: e.message,
        target: e.target,
        timestamp: e.timestamp,
      });
    });

    // Warning logging
    this.prisma.$on('warn', (e) => {
      logger.warn('Database warning', {
        message: e.message,
        target: e.target,
        timestamp: e.timestamp,
      });
    });
  }

  /**
   * Set up error handling
   * @private
   */
  _setupErrorHandling() {
    this.prisma.$on('error', (e) => {
      this.metrics.errorsEncountered++;

      const dbError = new DatabaseError(`Database error: ${e.message}`, e);

      logger.error('Database error occurred', {
        error: dbError.toJSON(),
        target: e.target,
        timestamp: e.timestamp,
      });

      // Check if this is a connection error
      if (this._isConnectionError(e)) {
        this._handleConnectionError(e);
      }
    });
  }

  /**
   * Check if error is a connection error
   * @param {Error} error - Error to check
   * @returns {boolean} True if connection error
   * @private
   */
  _isConnectionError(error) {
    const connectionErrorCodes = [
      'P1001', // Can't reach database server
      'P1002', // Database server timeout
      'P1003', // Database does not exist
      'P1008', // Operations timed out
      'P1017', // Server closed connection
    ];

    return (
      connectionErrorCodes.includes(error.code) ||
      error.message.includes('connection') ||
      error.message.includes('timeout')
    );
  }

  /**
   * Handle connection errors with reconnection logic
   * @param {Error} error - Connection error
   * @private
   */
  _handleConnectionError(error) {
    if (this.connectionState === CONNECTION_STATES.CONNECTED) {
      this.connectionState = CONNECTION_STATES.RECONNECTING;
      this.metrics.reconnectAttempts++;

      logger.warn('Database connection lost, attempting to reconnect', {
        error: error.message,
        reconnectAttempt: this.metrics.reconnectAttempts,
      });

      // Clear existing timeout
      if (this.reconnectTimeout) {
        clearTimeout(this.reconnectTimeout);
      }

      // Attempt reconnection after delay
      this.reconnectTimeout = setTimeout(async () => {
        try {
          await this.initialize();
          logger.info('Database reconnection successful');
        } catch (reconnectError) {
          logger.error('Database reconnection failed', {
            error: reconnectError.message,
          });
        }
      }, this.retryDelay);
    }
  }

  /**
   * Test database connection
   * @returns {Promise<void>}
   * @private
   */
  async _testConnection() {
    try {
      await this.prisma.$connect();
      const result = await this.prisma.$queryRaw`SELECT 1 as connection_test`;

      if (!result || result.length === 0) {
        throw new Error('Connection test query returned no results');
      }

      logger.debug('Database connection test passed');
    } catch (error) {
      throw new DatabaseError(
        `Database connection test failed: ${error.message}`,
        error,
      );
    }
  }

  /**
   * Set up periodic health monitoring
   * @private
   */
  _setupHealthMonitoring() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    // Health check interval from config
    const interval = config.server?.healthCheckInterval || 30000;

    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.healthCheck();
      } catch (error) {
        logger.error('Database health check failed', {
          error: error.message,
          connectionState: this.connectionState,
        });

        this.connectionState = CONNECTION_STATES.ERROR;
        this._handleConnectionError(error);
      }
    }, interval);

    logger.debug('Database health monitoring started', {
      interval: `${interval}ms`,
    });
  }

  /**
   * Set up periodic cleanup tasks
   * @private
   */
  _setupCleanupTasks() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Cleanup interval from config
    const interval = config.auth?.session?.cleanupInterval || 3600000; // 1 hour

    this.cleanupInterval = setInterval(async () => {
      try {
        await this._runCleanupTasks();
      } catch (error) {
        logger.error('Database cleanup tasks failed', {
          error: error.message,
        });
      }
    }, interval);

    logger.debug('Database cleanup tasks scheduled', {
      interval: `${interval}ms`,
    });
  }

  /**
   * Run cleanup tasks
   * @private
   */
  async _runCleanupTasks() {
    const startTime = Date.now();

    try {
      // Only run cleanup if we have the required tables
      let expiredSessions = 0;
      let expiredInvites = 0;

      try {
        expiredSessions = await this.cleanupExpiredSessions();
      } catch (error) {
        logger.debug('Session cleanup skipped (table may not exist)', {
          error: error.message,
        });
      }

      try {
        expiredInvites = await this.cleanupExpiredInvites();
      } catch (error) {
        logger.debug('Invite cleanup skipped (table may not exist)', {
          error: error.message,
        });
      }

      const duration = Date.now() - startTime;
      this.metrics.cleanupOperations++;

      logger.info('Database cleanup completed', {
        expiredSessions,
        expiredInvites,
        duration: `${duration}ms`,
      });
    } catch (error) {
      logger.error('Database cleanup failed', {
        error: error.message,
        duration: `${Date.now() - startTime}ms`,
      });
      throw error;
    }
  }

  /**
   * Perform database health check
   * @returns {Promise<Object>} Health status object
   */
  async healthCheck() {
    const startTime = Date.now();

    try {
      // Test basic connectivity
      await this.prisma.$queryRaw`SELECT 1 as health_check`;

      const responseTime = Date.now() - startTime;
      const uptime = this.metrics.connectionUptime
        ? Math.floor(
            (Date.now() - this.metrics.connectionUptime.getTime()) / 1000,
          )
        : 0;

      const health = {
        status: 'healthy',
        responseTime: `${responseTime}ms`,
        connectionState: this.connectionState,
        uptime: `${uptime}s`,
        timestamp: generateTimestamp(),
        metrics: {
          queriesExecuted: this.metrics.queriesExecuted,
          transactionsExecuted: this.metrics.transactionsExecuted,
          errorsEncountered: this.metrics.errorsEncountered,
          slowQueries: this.metrics.slowQueries,
        },
      };

      this.metrics.lastHealthCheck = new Date();
      return health;
    } catch (error) {
      const responseTime = Date.now() - startTime;

      const health = {
        status: 'unhealthy',
        error: error.message,
        responseTime: `${responseTime}ms`,
        connectionState: this.connectionState,
        timestamp: generateTimestamp(),
      };

      throw new DatabaseError('Database health check failed', error);
    }
  }

  /**
   * Get comprehensive database metrics
   * @returns {Promise<Object>} Database metrics
   */
  async getMetrics() {
    try {
      // Try to get metrics, but handle cases where tables don't exist
      const metrics = {
        connection: {
          state: this.connectionState,
          uptime: this.metrics.connectionUptime
            ? Math.floor(
                (Date.now() - this.metrics.connectionUptime.getTime()) / 1000,
              )
            : 0,
          lastHealthCheck: this.metrics.lastHealthCheck,
        },
        performance: {
          queriesExecuted: this.metrics.queriesExecuted,
          transactionsExecuted: this.metrics.transactionsExecuted,
          slowQueries: this.metrics.slowQueries,
        },
        errors: {
          total: this.metrics.errorsEncountered,
          reconnectAttempts: this.metrics.reconnectAttempts,
        },
        data: {
          users: 0,
          workspaces: 0,
          memberships: 0,
          activeSessions: 0,
        },
        cleanup: {
          operations: this.metrics.cleanupOperations,
        },
        timestamp: generateTimestamp(),
      };

      // Try to get data counts (may fail if tables don't exist)
      try {
        const [userCount, workspaceCount, membershipCount, activeSessionCount] =
          await Promise.all([
            this.prisma.user?.count() || 0,
            this.prisma.workspace?.count() || 0,
            this.prisma.membership?.count() || 0,
            this.prisma.session?.count({ where: { isActive: true } }) || 0,
          ]);

        metrics.data = {
          users: userCount,
          workspaces: workspaceCount,
          memberships: membershipCount,
          activeSessions: activeSessionCount,
        };
      } catch (error) {
        logger.debug('Could not get table counts (tables may not exist)', {
          error: error.message,
        });
      }

      return metrics;
    } catch (error) {
      logger.error('Failed to get database metrics', {
        error: error.message,
      });

      return {
        error: error.message,
        timestamp: generateTimestamp(),
      };
    }
  }

  /**
   * Execute database transaction with retry logic and monitoring
   * @param {Function} callback - Transaction callback function
   * @param {Object} options - Transaction options
   * @returns {Promise<any>} Transaction result
   */
  async transaction(callback, options = {}) {
    const {
      maxRetries = 3,
      retryDelay = 1000,
      timeout = this.queryTimeout,
      isolationLevel,
    } = options;

    const startTime = Date.now();
    let attempt = 0;

    while (attempt < maxRetries) {
      attempt++;

      try {
        const result = await this.prisma.$transaction(callback, {
          timeout,
          isolationLevel,
        });

        const duration = Date.now() - startTime;
        this.metrics.transactionsExecuted++;

        logger.debug('Database transaction completed', {
          attempt,
          duration: `${duration}ms`,
          success: true,
        });

        return result;
      } catch (error) {
        const duration = Date.now() - startTime;

        logger.warn('Database transaction failed', {
          attempt,
          maxRetries,
          duration: `${duration}ms`,
          error: error.message,
        });

        // Check if error is retryable
        if (attempt === maxRetries || !this._isRetryableError(error)) {
          const dbError = new DatabaseError(
            `Transaction failed after ${attempt} attempts: ${error.message}`,
            error,
          );

          logger.error('Database transaction failed permanently', {
            error: dbError.toJSON(),
            attempts: attempt,
          });

          throw dbError;
        }

        // Wait before retry
        await new Promise((resolve) =>
          setTimeout(resolve, retryDelay * attempt),
        );
      }
    }
  }

  /**
   * Check if error is retryable
   * @param {Error} error - Error to check
   * @returns {boolean} True if retryable
   * @private
   */
  _isRetryableError(error) {
    const retryableErrorCodes = [
      'P2034', // Transaction conflict
      'P1008', // Operations timed out
      'P1001', // Can't reach database server
      'P1002', // Database server timeout
    ];

    return (
      retryableErrorCodes.includes(error.code) ||
      error.message.includes('timeout') ||
      error.message.includes('connection') ||
      error.message.includes('conflict')
    );
  }

  /**
   * Clean up expired sessions
   * @returns {Promise<number>} Number of cleaned sessions
   */
  async cleanupExpiredSessions() {
    try {
      const result = await this.prisma.session.deleteMany({
        where: {
          OR: [{ expiresAt: { lt: new Date() } }, { isActive: false }],
        },
      });

      if (result.count > 0) {
        logger.info('Expired sessions cleaned up', {
          count: result.count,
        });
      }

      return result.count;
    } catch (error) {
      const dbError = new DatabaseError(
        `Session cleanup failed: ${error.message}`,
        error,
      );

      logger.error('Session cleanup failed', {
        error: dbError.toJSON(),
      });

      throw dbError;
    }
  }

  /**
   * Clean up expired invites
   * @returns {Promise<number>} Number of cleaned invites
   */
  async cleanupExpiredInvites() {
    try {
      const result = await this.prisma.invite.deleteMany({
        where: {
          OR: [{ expiresAt: { lt: new Date() } }, { used: true }],
        },
      });

      if (result.count > 0) {
        logger.info('Expired invites cleaned up', {
          count: result.count,
        });
      }

      return result.count;
    } catch (error) {
      const dbError = new DatabaseError(
        `Invite cleanup failed: ${error.message}`,
        error,
      );

      logger.error('Invite cleanup failed', {
        error: dbError.toJSON(),
      });

      throw dbError;
    }
  }

  /**
   * Graceful shutdown of database connection
   * @returns {Promise<void>}
   */
  async gracefulShutdown() {
    logger.info('Initiating database graceful shutdown');

    this.connectionState = CONNECTION_STATES.DISCONNECTING;

    // Clear intervals and timeouts
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    // Disconnect from database
    try {
      if (this.prisma) {
        await this.prisma.$disconnect();
        logger.info('Database disconnected successfully');
      }
    } catch (error) {
      logger.error('Error during database disconnection', {
        error: error.message,
      });
    } finally {
      this.connectionState = CONNECTION_STATES.DISCONNECTED;
      this.prisma = null;
    }
  }

  /**
   * Get connection information (safe for logging)
   * @returns {Object} Connection information
   */
  getConnectionInfo() {
    return {
      url:
        config.database?.url || config.DATABASE_URL
          ? (config.database?.url || config.DATABASE_URL).replace(
              /:[^:@]*@/,
              ':***@',
            )
          : 'Not configured',
      environment: config.NODE_ENV,
      state: this.connectionState,
      poolSize: config.database?.poolSize || 'default',
      ssl: config.database?.ssl,
      uptime: this.metrics.connectionUptime
        ? Math.floor(
            (Date.now() - this.metrics.connectionUptime.getTime()) / 1000,
          )
        : 0,
      lastHealthCheck: this.metrics.lastHealthCheck,
    };
  }
}

// Create singleton instance
const databaseManager = new DatabaseManager();

/**
 * Wrapped database operations with async handling
 */
const wrappedOperations = {
  // Initialize database
  initialize: asyncHandler(async () => {
    return await databaseManager.initialize();
  }),

  // Health check
  healthCheck: asyncHandler(async () => {
    return await databaseManager.healthCheck();
  }),

  // Get metrics
  getMetrics: asyncHandler(async () => {
    return await databaseManager.getMetrics();
  }),

  // Transaction
  transaction: asyncHandler(async (callback, options) => {
    return await databaseManager.transaction(callback, options);
  }),

  // Cleanup operations
  cleanupExpiredSessions: asyncHandler(async () => {
    return await databaseManager.cleanupExpiredSessions();
  }),

  cleanupExpiredInvites: asyncHandler(async () => {
    return await databaseManager.cleanupExpiredInvites();
  }),

  // Graceful shutdown
  gracefulShutdown: asyncHandler(async () => {
    return await databaseManager.gracefulShutdown();
  }),
};

// Auto-initialize database (except in test environment)
let initializationPromise;
if (config.NODE_ENV !== 'test') {
  initializationPromise = databaseManager.initialize().catch((error) => {
    logger.error('Database auto-initialization failed', {
      error: error.message,
    });
    // Don't exit process in development - let it continue with warnings
    if (config.NODE_ENV === 'production') {
      process.exit(1);
    }
  });
}

// Export database interface with backward compatibility
module.exports = {
  // Main database client (lazy-loaded)
  get client() {
    if (!databaseManager.prisma) {
      throw new ApiError(
        500,
        'Database not initialized. Call initialize() first.',
        'DATABASE_NOT_INITIALIZED',
      );
    }
    return databaseManager.prisma;
  },

  // Backward compatibility aliases
  get prisma() {
    return databaseManager.prisma;
  },

  get prismaAvailable() {
    return databaseManager.connectionState === CONNECTION_STATES.CONNECTED;
  },

  // Legacy methods for compatibility
  connectDatabase: wrappedOperations.initialize,
  disconnectDatabase: wrappedOperations.gracefulShutdown,
  checkDatabaseHealth: wrappedOperations.healthCheck,

  // Database manager instance
  manager: databaseManager,

  // Connection states
  CONNECTION_STATES,
  OPERATION_TYPES,

  // Wrapped operations
  ...wrappedOperations,

  // Backward compatibility methods for server.js
  connectDB: wrappedOperations.initialize,
  disconnectDB: wrappedOperations.gracefulShutdown,

  // Utility methods
  getConnectionInfo: () => databaseManager.getConnectionInfo(),

  // Initialization promise for startup coordination
  ready: initializationPromise,
};
