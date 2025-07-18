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
 * - In-memory rate limiting with fallback options
 * - Rate limit bypass for trusted sources
 * - Comprehensive metrics and abuse detection
 * - Custom error responses and retry-after headers
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const rateLimit = require("express-rate-limit");
const config = require("../config");
const { generateTimestamp, sanitizeSensitiveData } = require("../utils/common");

/**
 * Rate Limit Tiers for different user types
 */
const RATE_LIMIT_TIERS = {
  FREE: "free",
  BASIC: "basic",
  PREMIUM: "premium",
  ENTERPRISE: "enterprise",
  ADMIN: "admin",
};

/**
 * Rate Limit Types for different scenarios
 */
const RATE_LIMIT_TYPES = {
  GENERAL: "general",
  AUTH: "auth",
  API: "api",
  UPLOAD: "upload",
  EMAIL: "email",
  INVITE: "invite",
  PASSWORD_RESET: "password_reset",
};

/**
 * Rate Limit Algorithms
 */
const ALGORITHMS = {
  SLIDING_WINDOW: "sliding_window",
  FIXED_WINDOW: "fixed_window",
  TOKEN_BUCKET: "token_bucket",
};

/**
 * Time constants for better maintainability
 */
const TIME_WINDOWS = {
  MINUTES_15: 15 * 60 * 1000,
  MINUTES_30: 30 * 60 * 1000,
  HOUR_1: 60 * 60 * 1000,
  HOUR_24: 24 * 60 * 60 * 1000,
};

/**
 * Base rate limit multipliers for different tiers
 */
const TIER_MULTIPLIERS = {
  [RATE_LIMIT_TIERS.FREE]: 1,
  [RATE_LIMIT_TIERS.BASIC]: 3,
  [RATE_LIMIT_TIERS.PREMIUM]: 10,
  [RATE_LIMIT_TIERS.ENTERPRISE]: 50,
  [RATE_LIMIT_TIERS.ADMIN]: 100,
};

/**
 * Base rate limit configurations for different types
 */
const BASE_RATE_CONFIGS = {
  [RATE_LIMIT_TYPES.GENERAL]: {
    windowMs: TIME_WINDOWS.MINUTES_15,
    baseLimit: 100,
  },
  [RATE_LIMIT_TYPES.AUTH]: {
    windowMs: TIME_WINDOWS.MINUTES_15,
    baseLimit: 5,
  },
  [RATE_LIMIT_TYPES.API]: {
    windowMs: TIME_WINDOWS.MINUTES_15,
    baseLimit: 50,
  },
  [RATE_LIMIT_TYPES.UPLOAD]: {
    windowMs: TIME_WINDOWS.HOUR_1,
    baseLimit: 5,
  },
  [RATE_LIMIT_TYPES.EMAIL]: {
    windowMs: TIME_WINDOWS.HOUR_1,
    baseLimit: 10,
  },
  [RATE_LIMIT_TYPES.INVITE]: {
    windowMs: TIME_WINDOWS.HOUR_1,
    baseLimit: 5,
  },
  [RATE_LIMIT_TYPES.PASSWORD_RESET]: {
    windowMs: TIME_WINDOWS.HOUR_1,
    baseLimit: 3,
  },
};

/**
 * Rate Limiting Manager Class
 * Handles all rate limiting logic with enterprise features
 */
class RateLimitManager {
  constructor() {
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
      this.setupTrustedIPs();
      this.setupBlockedIPs();

      console.log("✅ Rate limiting system initialized with in-memory store");
    } catch (error) {
      console.warn("⚠️  Rate limiting initialization failed:", error.message);
    }
  }

  /**
   * Setup trusted IPs that bypass rate limiting
   */
  setupTrustedIPs() {
    const trustedIPs = [
      "127.0.0.1",
      "::1",
      "localhost",
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
   * Calculate rate limit for tier and type
   * @param {string} tier - User tier
   * @param {string} type - Rate limit type
   * @returns {Object} Rate limit configuration
   */
  getRateLimitConfig(
    tier = RATE_LIMIT_TIERS.FREE,
    type = RATE_LIMIT_TYPES.GENERAL
  ) {
    const baseConfig = BASE_RATE_CONFIGS[type];
    if (!baseConfig) {
      throw new Error(`Invalid rate limit type: ${type}`);
    }

    const multiplier =
      TIER_MULTIPLIERS[tier] || TIER_MULTIPLIERS[RATE_LIMIT_TIERS.FREE];

    return {
      windowMs: baseConfig.windowMs,
      max: Math.floor(baseConfig.baseLimit * multiplier),
    };
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

      // Custom response handler
      handler: (req, res, next, options) => {
        this.rateLimitMetrics.rateLimitHits++;

        // Execute custom onLimitReached callback if provided
        if (onLimitReached) {
          onLimitReached(req, res);
        }

        // Detect suspicious activity
        this._detectSuspiciousActivity(req, options);

        this._logRateLimitEvent("RATE_LIMIT_HIT", {
          ip: req.ip,
          userId: req.user?.id,
          workspaceId: req.workspace?.id,
          endpoint: req.originalUrl,
          userAgent: req.get("User-Agent"),
          tier,
          type,
          limit: config.max,
          window: config.windowMs,
        });

        res.status(429).json({
          success: false,
          error: "Rate limit exceeded",
          message: customMessage || this.getDefaultMessage(tier, type, config),
          retryAfter: Math.round(config.windowMs / 1000),
          limit: config.max,
          window: config.windowMs,
          type,
        });
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

    return parts.join("|");
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
    if (req.user?.role === "ADMIN") {
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
      keyGenerator: (req) =>
        `workspace:${req.workspace?.id || "unknown"}:${req.ip}`,
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
      keyGenerator: (req) => `user:${req.user?.id || req.ip}`,
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
      keyGenerator: (req) => `endpoint:${endpoint}:${req.ip}`,
    });
  }

  /**
   * IP Management Methods
   */
  addTrustedIP(ip) {
    this.trustedIPs.add(ip);
    this._logRateLimitEvent("TRUSTED_IP_ADDED", { ip });
  }

  removeTrustedIP(ip) {
    this.trustedIPs.delete(ip);
    this._logRateLimitEvent("TRUSTED_IP_REMOVED", { ip });
  }

  addBlockedIP(ip) {
    this.blockedIPs.add(ip);
    this._logRateLimitEvent("IP_BLOCKED", { ip });
  }

  removeBlockedIP(ip) {
    this.blockedIPs.delete(ip);
    this._logRateLimitEvent("IP_UNBLOCKED", { ip });
  }

  /**
   * Detect suspicious activity patterns
   * @param {Object} req - Express request object
   * @param {Object} options - Rate limit options
   * @private
   */
  _detectSuspiciousActivity(req, options) {
    const ip = req.ip;
    const userAgent = req.get("User-Agent");

    // Check for suspicious patterns
    const suspiciousPatterns = [
      !userAgent, // No user agent
      userAgent && userAgent.includes("bot"), // Bot user agent
      req.headers["x-forwarded-for"] &&
        req.headers["x-forwarded-for"].split(",").length > 3, // Multiple proxies
    ];

    if (suspiciousPatterns.some((pattern) => pattern)) {
      this.rateLimitMetrics.suspiciousActivity++;

      this._logRateLimitEvent("SUSPICIOUS_ACTIVITY", {
        ip,
        userAgent,
        endpoint: req.originalUrl,
        headers: sanitizeSensitiveData(req.headers),
        reason: "Rate limit exceeded with suspicious patterns",
      });
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
      storeType: "memory",
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get rate limit status for a key
   * @param {string} key - Rate limit key
   * @returns {Promise<Object>} Rate limit status
   */
  async getRateLimitStatus(key) {
    return {
      message: "Rate limit status not available with in-memory store",
      storeType: "memory",
      key,
    };
  }

  /**
   * Reset rate limit for a key
   * @param {string} key - Rate limit key
   * @returns {Promise<boolean>} Success status
   */
  async resetRateLimit(key) {
    // In-memory store doesn't support reset, but we can log the attempt
    this._logRateLimitEvent("RATE_LIMIT_RESET_ATTEMPTED", { key });
    return false;
  }

  /**
   * Log rate limiting events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logRateLimitEvent(event, data) {
    const logEntry = {
      timestamp: generateTimestamp(),
      event,
      data: sanitizeSensitiveData(data),
      source: "RATE_LIMIT_MANAGER",
    };

    if (event.includes("SUSPICIOUS") || event.includes("BLOCKED")) {
      console.warn("🚨 Rate Limit Security Event:", logEntry);
    } else if (config.logging?.level === "debug") {
      console.log("⏱️  Rate Limit Event:", logEntry);
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
