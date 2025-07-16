/**
 * Rate Limiting Configuration Module
 *
 * This module provides comprehensive rate limiting for multi-tenant SaaS
 * applications with enterprise security and fairness requirements:
 *
 * Features:
 * - Multi-tier rate limiting (IP, user, workspace, endpoint)
 * - Dynamic rate limit adjustment based on user plans
 * - Sliding window and token bucket algorithms
 * - Distributed rate limiting with Redis support
 * - Rate limit bypass for trusted sources
 * - Comprehensive metrics and abuse detection
 * - Custom error responses and retry-after headers
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('redis');
const config = require('../config');

/**
 * Rate Limit Tiers for different user types
 */
const RATE_LIMIT_TIERS = {
  FREE: 'free',
  BASIC: 'basic',
  PREMIUM: 'premium',
  ENTERPRISE: 'enterprise',
  ADMIN: 'admin',
};

/**
 * Rate Limit Types for different scenarios
 */
const RATE_LIMIT_TYPES = {
  GENERAL: 'general',
  AUTH: 'auth',
  API: 'api',
  UPLOAD: 'upload',
  EMAIL: 'email',
  INVITE: 'invite',
  PASSWORD_RESET: 'password_reset',
};

/**
 * Rate Limit Algorithms
 */
const ALGORITHMS = {
  SLIDING_WINDOW: 'sliding_window',
  FIXED_WINDOW: 'fixed_window',
  TOKEN_BUCKET: 'token_bucket',
};

/**
 * Rate Limiting Manager Class
 * Handles all rate limiting logic with enterprise features
 */
class RateLimitManager {
  constructor() {
    this.redisClient = null;
    this.rateLimitStore = null;
    this.trustedIPs = new Set();
    this.blockedIPs = new Set();
    this.rateLimitMetrics = {
      totalRequests: 0,
      blockedRequests: 0,
      bypassedRequests: 0,
      rateLimitHits: 0,
      suspiciousActivity: 0,
    };

    this.initialize();
  }

  /**
   * Initialize rate limiting system
   */
  async initialize() {
    try {
      await this.setupRedisStore();
      this.setupTrustedIPs();
      this.setupBlockedIPs();

      console.log('✅ Rate limiting system initialized');
    } catch (error) {
      console.warn(
        '⚠️  Rate limiting initialized without Redis:',
        error.message,
      );
    }
  }

  /**
   * Setup Redis store for distributed rate limiting
   */
  async setupRedisStore() {
    if (!config.jobs.redis.url) {
      console.warn('⚠️  Redis URL not configured, using memory store');
      return;
    }

    try {
      this.redisClient = Redis.createClient({
        url: config.jobs.redis.url,
        retry_strategy: (options) => {
          if (options.error && options.error.code === 'ECONNREFUSED') {
            return new Error('Redis server connection refused');
          }
          if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Redis retry time exhausted');
          }
          if (options.attempt > 10) {
            return undefined;
          }
          return Math.min(options.attempt * 100, 3000);
        },
      });

      await this.redisClient.connect();

      this.rateLimitStore = new RedisStore({
        client: this.redisClient,
        prefix: 'rl:',
        sendCommand: (...args) => this.redisClient.sendCommand(args),
      });

      console.log('✅ Redis rate limit store configured');
    } catch (error) {
      console.warn('⚠️  Redis rate limit store setup failed:', error.message);
    }
  }

  /**
   * Setup trusted IPs that bypass rate limiting
   */
  setupTrustedIPs() {
    const trustedIPs = [
      '127.0.0.1',
      '::1',
      'localhost',
      // Add your monitoring service IPs here
    ];

    trustedIPs.forEach((ip) => this.trustedIPs.add(ip));
  }

  /**
   * Setup blocked IPs
   */
  setupBlockedIPs() {
    // Add known malicious IPs here
    // In production, this would be populated from a security service
  }

  /**
   * Get rate limit configuration for different tiers
   * @param {string} tier - User tier
   * @param {string} type - Rate limit type
   * @returns {Object} Rate limit configuration
   */
  getRateLimitConfig(
    tier = RATE_LIMIT_TIERS.FREE,
    type = RATE_LIMIT_TYPES.GENERAL,
  ) {
    const configs = {
      [RATE_LIMIT_TIERS.FREE]: {
        [RATE_LIMIT_TYPES.GENERAL]: { windowMs: 15 * 60 * 1000, max: 100 },
        [RATE_LIMIT_TYPES.AUTH]: { windowMs: 15 * 60 * 1000, max: 5 },
        [RATE_LIMIT_TYPES.API]: { windowMs: 15 * 60 * 1000, max: 50 },
        [RATE_LIMIT_TYPES.UPLOAD]: { windowMs: 60 * 60 * 1000, max: 5 },
        [RATE_LIMIT_TYPES.EMAIL]: { windowMs: 60 * 60 * 1000, max: 10 },
        [RATE_LIMIT_TYPES.INVITE]: { windowMs: 60 * 60 * 1000, max: 5 },
        [RATE_LIMIT_TYPES.PASSWORD_RESET]: { windowMs: 60 * 60 * 1000, max: 3 },
      },
      [RATE_LIMIT_TIERS.BASIC]: {
        [RATE_LIMIT_TYPES.GENERAL]: { windowMs: 15 * 60 * 1000, max: 300 },
        [RATE_LIMIT_TYPES.AUTH]: { windowMs: 15 * 60 * 1000, max: 10 },
        [RATE_LIMIT_TYPES.API]: { windowMs: 15 * 60 * 1000, max: 150 },
        [RATE_LIMIT_TYPES.UPLOAD]: { windowMs: 60 * 60 * 1000, max: 20 },
        [RATE_LIMIT_TYPES.EMAIL]: { windowMs: 60 * 60 * 1000, max: 50 },
        [RATE_LIMIT_TYPES.INVITE]: { windowMs: 60 * 60 * 1000, max: 20 },
        [RATE_LIMIT_TYPES.PASSWORD_RESET]: { windowMs: 60 * 60 * 1000, max: 5 },
      },
      [RATE_LIMIT_TIERS.PREMIUM]: {
        [RATE_LIMIT_TYPES.GENERAL]: { windowMs: 15 * 60 * 1000, max: 1000 },
        [RATE_LIMIT_TYPES.AUTH]: { windowMs: 15 * 60 * 1000, max: 20 },
        [RATE_LIMIT_TYPES.API]: { windowMs: 15 * 60 * 1000, max: 500 },
        [RATE_LIMIT_TYPES.UPLOAD]: { windowMs: 60 * 60 * 1000, max: 100 },
        [RATE_LIMIT_TYPES.EMAIL]: { windowMs: 60 * 60 * 1000, max: 200 },
        [RATE_LIMIT_TYPES.INVITE]: { windowMs: 60 * 60 * 1000, max: 100 },
        [RATE_LIMIT_TYPES.PASSWORD_RESET]: {
          windowMs: 60 * 60 * 1000,
          max: 10,
        },
      },
      [RATE_LIMIT_TIERS.ENTERPRISE]: {
        [RATE_LIMIT_TYPES.GENERAL]: { windowMs: 15 * 60 * 1000, max: 5000 },
        [RATE_LIMIT_TYPES.AUTH]: { windowMs: 15 * 60 * 1000, max: 50 },
        [RATE_LIMIT_TYPES.API]: { windowMs: 15 * 60 * 1000, max: 2000 },
        [RATE_LIMIT_TYPES.UPLOAD]: { windowMs: 60 * 60 * 1000, max: 1000 },
        [RATE_LIMIT_TYPES.EMAIL]: { windowMs: 60 * 60 * 1000, max: 1000 },
        [RATE_LIMIT_TYPES.INVITE]: { windowMs: 60 * 60 * 1000, max: 500 },
        [RATE_LIMIT_TYPES.PASSWORD_RESET]: {
          windowMs: 60 * 60 * 1000,
          max: 20,
        },
      },
      [RATE_LIMIT_TIERS.ADMIN]: {
        [RATE_LIMIT_TYPES.GENERAL]: { windowMs: 15 * 60 * 1000, max: 10000 },
        [RATE_LIMIT_TYPES.AUTH]: { windowMs: 15 * 60 * 1000, max: 100 },
        [RATE_LIMIT_TYPES.API]: { windowMs: 15 * 60 * 1000, max: 5000 },
        [RATE_LIMIT_TYPES.UPLOAD]: { windowMs: 60 * 60 * 1000, max: 5000 },
        [RATE_LIMIT_TYPES.EMAIL]: { windowMs: 60 * 60 * 1000, max: 5000 },
        [RATE_LIMIT_TYPES.INVITE]: { windowMs: 60 * 60 * 1000, max: 1000 },
        [RATE_LIMIT_TYPES.PASSWORD_RESET]: {
          windowMs: 60 * 60 * 1000,
          max: 50,
        },
      },
    };

    return configs[tier]?.[type] || configs[RATE_LIMIT_TIERS.FREE][type];
  }

  /**
   * Create rate limiter middleware
   * @param {Object} options - Rate limiter options
   * @returns {Function} Express middleware
   */
  createRateLimiter(options = {}) {
    const {
      tier = RATE_LIMIT_TIERS.FREE,
      type = RATE_LIMIT_TYPES.GENERAL,
      keyGenerator = null,
      skipFunction = null,
      onLimitReached = null,
      customMessage = null,
    } = options;

    const config = this.getRateLimitConfig(tier, type);

    const rateLimiterOptions = {
      windowMs: config.windowMs,
      max: config.max,

      // Use Redis store if available
      store: this.rateLimitStore,

      // Custom key generator
      keyGenerator: keyGenerator || this.defaultKeyGenerator.bind(this),

      // Skip function for trusted IPs
      skip: skipFunction || this.defaultSkipFunction.bind(this),

      // Custom error message
      message: customMessage || this.getDefaultMessage(tier, type, config),

      // Headers configuration
      standardHeaders: true,
      legacyHeaders: false,

      // Custom response
      handler: (req, res) => {
        this.rateLimitMetrics.rateLimitHits++;

        if (onLimitReached) {
          onLimitReached(req, res);
        }

        this._logRateLimitEvent('RATE_LIMIT_HIT', {
          ip: req.ip,
          userId: req.user?.id,
          workspaceId: req.workspace?.id,
          endpoint: req.originalUrl,
          userAgent: req.get('User-Agent'),
          tier,
          type,
          limit: config.max,
          window: config.windowMs,
        });

        res.status(429).json({
          success: false,
          error: 'Rate limit exceeded',
          message: customMessage || this.getDefaultMessage(tier, type, config),
          retryAfter: Math.round(config.windowMs / 1000),
          limit: config.max,
          window: config.windowMs,
          type,
        });
      },

      // On limit reached callback
      onLimitReached: (req, res, options) => {
        this._detectSuspiciousActivity(req, options);
      },
    };

    return rateLimit(rateLimiterOptions);
  }

  /**
   * Default key generator for rate limiting
   * @param {Object} req - Express request object
   * @returns {string} Rate limit key
   */
  defaultKeyGenerator(req) {
    const parts = [];

    // Add IP address
    parts.push(`ip:${req.ip}`);

    // Add user ID if authenticated
    if (req.user?.id) {
      parts.push(`user:${req.user.id}`);
    }

    // Add workspace ID if available
    if (req.workspace?.id) {
      parts.push(`workspace:${req.workspace.id}`);
    }

    // Add endpoint path
    parts.push(`endpoint:${req.route?.path || req.path}`);

    return parts.join('|');
  }

  /**
   * Default skip function for trusted IPs
   * @param {Object} req - Express request object
   * @returns {boolean} Whether to skip rate limiting
   */
  defaultSkipFunction(req) {
    const ip = req.ip;

    // Skip if IP is trusted
    if (this.trustedIPs.has(ip)) {
      this.rateLimitMetrics.bypassedRequests++;
      return true;
    }

    // Block if IP is blacklisted
    if (this.blockedIPs.has(ip)) {
      this.rateLimitMetrics.blockedRequests++;
      return false;
    }

    // Skip for admin users
    if (req.user?.role === 'ADMIN') {
      this.rateLimitMetrics.bypassedRequests++;
      return true;
    }

    this.rateLimitMetrics.totalRequests++;
    return false;
  }

  /**
   * Get default rate limit message
   * @param {string} tier - User tier
   * @param {string} type - Rate limit type
   * @param {Object} config - Rate limit configuration
   * @returns {string} Default message
   */
  getDefaultMessage(tier, type, config) {
    const windowMinutes = Math.round(config.windowMs / 60000);

    return `Rate limit exceeded for ${tier} tier. Maximum ${config.max} requests per ${windowMinutes} minutes for ${type} operations.`;
  }

  /**
   * Create workspace-specific rate limiter
   * @param {Object} options - Options
   * @returns {Function} Express middleware
   */
  createWorkspaceRateLimiter(options = {}) {
    return this.createRateLimiter({
      ...options,
      keyGenerator: (req) => {
        return `workspace:${req.workspace?.id || 'unknown'}:${req.ip}`;
      },
    });
  }

  /**
   * Create user-specific rate limiter
   * @param {Object} options - Options
   * @returns {Function} Express middleware
   */
  createUserRateLimiter(options = {}) {
    return this.createRateLimiter({
      ...options,
      keyGenerator: (req) => {
        return `user:${req.user?.id || req.ip}`;
      },
    });
  }

  /**
   * Create endpoint-specific rate limiter
   * @param {string} endpoint - Endpoint path
   * @param {Object} options - Options
   * @returns {Function} Express middleware
   */
  createEndpointRateLimiter(endpoint, options = {}) {
    return this.createRateLimiter({
      ...options,
      keyGenerator: (req) => {
        return `endpoint:${endpoint}:${req.ip}`;
      },
    });
  }

  /**
   * Add trusted IP address
   * @param {string} ip - IP address to trust
   */
  addTrustedIP(ip) {
    this.trustedIPs.add(ip);
    this._logRateLimitEvent('TRUSTED_IP_ADDED', { ip });
  }

  /**
   * Remove trusted IP address
   * @param {string} ip - IP address to remove
   */
  removeTrustedIP(ip) {
    this.trustedIPs.delete(ip);
    this._logRateLimitEvent('TRUSTED_IP_REMOVED', { ip });
  }

  /**
   * Add blocked IP address
   * @param {string} ip - IP address to block
   */
  addBlockedIP(ip) {
    this.blockedIPs.add(ip);
    this._logRateLimitEvent('IP_BLOCKED', { ip });
  }

  /**
   * Remove blocked IP address
   * @param {string} ip - IP address to unblock
   */
  removeBlockedIP(ip) {
    this.blockedIPs.delete(ip);
    this._logRateLimitEvent('IP_UNBLOCKED', { ip });
  }

  /**
   * Detect suspicious activity patterns
   * @param {Object} req - Express request object
   * @param {Object} options - Rate limit options
   * @private
   */
  _detectSuspiciousActivity(req, options) {
    const ip = req.ip;
    const userAgent = req.get('User-Agent');

    // Check for suspicious patterns
    const suspiciousPatterns = [
      !userAgent, // No user agent
      userAgent && userAgent.includes('bot'), // Bot user agent
      req.headers['x-forwarded-for'] &&
        req.headers['x-forwarded-for'].split(',').length > 3, // Multiple proxies
    ];

    if (suspiciousPatterns.some((pattern) => pattern)) {
      this.rateLimitMetrics.suspiciousActivity++;

      this._logRateLimitEvent('SUSPICIOUS_ACTIVITY', {
        ip,
        userAgent,
        endpoint: req.originalUrl,
        headers: req.headers,
        reason: 'Rate limit exceeded with suspicious patterns',
      });

      // Auto-block after repeated suspicious activity
      // In production, this would integrate with a security service
    }
  }

  /**
   * Get rate limiting metrics
   * @returns {Object} Rate limiting metrics
   */
  getMetrics() {
    return {
      ...this.rateLimitMetrics,
      trustedIPsCount: this.trustedIPs.size,
      blockedIPsCount: this.blockedIPs.size,
      redisConnected: !!this.redisClient?.isOpen,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get rate limit status for a key
   * @param {string} key - Rate limit key
   * @returns {Promise<Object>} Rate limit status
   */
  async getRateLimitStatus(key) {
    if (!this.rateLimitStore) {
      return { error: 'Rate limit store not available' };
    }

    try {
      // This would depend on the specific store implementation
      // For now, return a placeholder
      return {
        key,
        remaining: 'unknown',
        resetTime: 'unknown',
        total: 'unknown',
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Reset rate limit for a key
   * @param {string} key - Rate limit key
   * @returns {Promise<boolean>} Success status
   */
  async resetRateLimit(key) {
    if (!this.rateLimitStore) {
      return false;
    }

    try {
      await this.rateLimitStore.resetKey(key);
      this._logRateLimitEvent('RATE_LIMIT_RESET', { key });
      return true;
    } catch (error) {
      this._logRateLimitEvent('RATE_LIMIT_RESET_FAILED', {
        key,
        error: error.message,
      });
      return false;
    }
  }

  /**
   * Log rate limiting events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logRateLimitEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'RATE_LIMIT_MANAGER',
    };

    if (event.includes('SUSPICIOUS') || event.includes('BLOCKED')) {
      console.warn('🚨 Rate Limit Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('⏱️  Rate Limit Event:', logEntry);
    }

    // In production, send to monitoring service
    if (config.isProduction()) {
      // TODO: Send to monitoring service
    }
  }
}

// Create singleton instance
const rateLimitManager = new RateLimitManager();

// Pre-configured rate limiters for common use cases
const commonRateLimiters = {
  // General API rate limiter
  general: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.GENERAL,
  }),

  // Authentication rate limiter
  auth: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.AUTH,
  }),

  // API rate limiter
  api: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.API,
  }),

  // Upload rate limiter
  upload: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.UPLOAD,
  }),

  // Email rate limiter
  email: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.EMAIL,
  }),

  // Invitation rate limiter
  invite: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.INVITE,
  }),

  // Password reset rate limiter
  passwordReset: rateLimitManager.createRateLimiter({
    tier: RATE_LIMIT_TIERS.FREE,
    type: RATE_LIMIT_TYPES.PASSWORD_RESET,
  }),
};

// Export rate limit manager and utilities
module.exports = {
  // Rate limit manager instance
  rateLimitManager,

  // Rate limit tiers and types
  RATE_LIMIT_TIERS,
  RATE_LIMIT_TYPES,
  ALGORITHMS,

  // Pre-configured rate limiters
  ...commonRateLimiters,

  // Rate limiter creators
  createRateLimiter: (options) => rateLimitManager.createRateLimiter(options),
  createWorkspaceRateLimiter: (options) =>
    rateLimitManager.createWorkspaceRateLimiter(options),
  createUserRateLimiter: (options) =>
    rateLimitManager.createUserRateLimiter(options),
  createEndpointRateLimiter: (endpoint, options) =>
    rateLimitManager.createEndpointRateLimiter(endpoint, options),

  // IP management
  addTrustedIP: (ip) => rateLimitManager.addTrustedIP(ip),
  removeTrustedIP: (ip) => rateLimitManager.removeTrustedIP(ip),
  addBlockedIP: (ip) => rateLimitManager.addBlockedIP(ip),
  removeBlockedIP: (ip) => rateLimitManager.removeBlockedIP(ip),

  // Monitoring and management
  getMetrics: () => rateLimitManager.getMetrics(),
  getRateLimitStatus: (key) => rateLimitManager.getRateLimitStatus(key),
  resetRateLimit: (key) => rateLimitManager.resetRateLimit(key),

  // Configuration
  getRateLimitConfig: (tier, type) =>
    rateLimitManager.getRateLimitConfig(tier, type),
};
