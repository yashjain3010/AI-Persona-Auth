/**
 * CORS Configuration Module
 *
 * This module provides comprehensive Cross-Origin Resource Sharing (CORS)
 * configuration for multi-tenant SaaS applications with enterprise security:
 *
 * Features:
 * - Dynamic origin validation with whitelist/blacklist support
 * - Workspace-specific CORS policies
 * - Environment-aware configuration
 * - Security headers optimization
 * - Preflight request handling
 * - Custom domain support for workspaces
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const cors = require("cors");
const config = require("../config");
const { generateTimestamp, sanitizeSensitiveData } = require("../utils/common");

/**
 * CORS Policy Types
 */
const CORS_POLICIES = {
  STRICT: "strict", // Only configured origins
  PERMISSIVE: "permissive", // Allow common development origins
  CUSTOM: "custom", // Workspace-specific origins
};

/**
 * Base CORS configuration template
 */
const BASE_CORS_CONFIG = {
  credentials: true,
  optionsSuccessStatus: 200,
  preflightContinue: false,
  allowedHeaders: [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
    "X-API-Key",
    "X-Workspace-ID",
    "X-Device-ID",
    "X-Request-ID",
    "Cache-Control",
    "Pragma",
  ],
  exposedHeaders: [
    "X-Total-Count",
    "X-Page-Count",
    "X-Current-Page",
    "X-Per-Page",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "X-Request-ID",
  ],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
  maxAge: 86400, // 24 hours
};

/**
 * CORS Manager Class
 * Handles dynamic CORS configuration with enterprise features
 */
class CORSManager {
  constructor() {
    this.corsMetrics = {
      allowedRequests: 0,
      blockedRequests: 0,
      preflightRequests: 0,
      customDomainRequests: 0,
    };

    this.corsCache = new Map(); // Cache for workspace-specific CORS policies
    this.allowedOrigins = this.buildAllowedOrigins();
    this.blockedOrigins = this.buildBlockedOrigins();
  }

  /**
   * Build allowed origins list from configuration
   * @returns {Array<string>} Array of allowed origins
   */
  buildAllowedOrigins() {
    const origins = [];

    // Add configured origins
    if (config.security?.cors?.origin) {
      origins.push(...config.security.cors.origin);
    }

    // Add environment-specific origins
    if (config.isDevelopment()) {
      origins.push(
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002"
      );
    }

    // Add client URL from config
    if (config.app?.clientUrl) {
      origins.push(config.app.clientUrl);
    }

    // Add frontend URL from config
    if (config.FRONTEND_URL) {
      origins.push(config.FRONTEND_URL);
    }

    // Remove duplicates and empty values
    return [...new Set(origins.filter(Boolean))];
  }

  /**
   * Build blocked origins list (security blacklist)
   * @returns {Array<string>} Array of blocked origins
   */
  buildBlockedOrigins() {
    return [
      // Add known malicious domains or patterns here
      "null", // Block null origin
      "file://", // Block file protocol
    ];
  }

  /**
   * Check if origin matches pattern (with wildcard support)
   * @param {string} origin - Origin to check
   * @param {string} pattern - Pattern to match against
   * @returns {boolean} Whether origin matches pattern
   */
  matchesPattern(origin, pattern) {
    if (pattern.includes("*")) {
      const regexPattern = pattern.replace(/\*/g, ".*");
      return new RegExp(`^${regexPattern}$`).test(origin);
    }
    return origin === pattern;
  }

  /**
   * Check if origin is explicitly blocked
   * @param {string} origin - Origin to check
   * @returns {boolean} Whether origin is blocked
   */
  isOriginBlocked(origin) {
    return this.blockedOrigins.some((blocked) =>
      this.matchesPattern(origin, blocked)
    );
  }

  /**
   * Check if origin is in allowed list
   * @param {string} origin - Origin to check
   * @returns {boolean} Whether origin is allowed
   */
  isOriginAllowed(origin) {
    return this.allowedOrigins.some((allowed) =>
      this.matchesPattern(origin, allowed)
    );
  }

  /**
   * Check if origin is a custom domain for a workspace
   * @param {string} origin - Origin to check
   * @param {Object} req - Express request object
   * @returns {boolean} Whether custom domain is allowed
   */
  isCustomDomainAllowed(origin, req) {
    // TODO: Implement workspace custom domain validation
    // This would check against a database of workspace custom domains
    // For now, return false to maintain security
    return false;
  }

  /**
   * Validate origin against allowed/blocked lists
   * @param {string} origin - Origin to validate
   * @param {Object} req - Express request object
   * @returns {boolean} Whether origin is allowed
   */
  validateOrigin(origin, req) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return true;
    }

    // Check blocked origins first
    if (this.isOriginBlocked(origin)) {
      this.corsMetrics.blockedRequests++;
      this._logCORSEvent("ORIGIN_BLOCKED", {
        origin,
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        referer: req.get("Referer"),
      });
      return false;
    }

    // Check allowed origins
    if (this.isOriginAllowed(origin)) {
      this.corsMetrics.allowedRequests++;
      return true;
    }

    // Check workspace-specific custom domains
    if (this.isCustomDomainAllowed(origin, req)) {
      this.corsMetrics.customDomainRequests++;
      return true;
    }

    // Block unknown origins
    this.corsMetrics.blockedRequests++;
    this._logCORSEvent("ORIGIN_REJECTED", {
      origin,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      referer: req.get("Referer"),
    });

    return false;
  }

  /**
   * Create CORS configuration with custom overrides
   * @param {Object} overrides - Configuration overrides
   * @returns {Object} CORS configuration
   */
  _createCORSConfig(overrides = {}) {
    const baseConfig = {
      ...BASE_CORS_CONFIG,
      origin: (origin, callback) => {
        const isAllowed = this.validateOrigin(origin, callback.req);
        callback(null, isAllowed);
      },
    };

    return { ...baseConfig, ...overrides };
  }

  /**
   * Get CORS configuration object
   * @returns {Object} CORS configuration
   */
  getCORSConfig() {
    return this._createCORSConfig();
  }

  /**
   * Get strict CORS configuration for production
   * @returns {Object} Strict CORS configuration
   */
  getStrictCORSConfig() {
    return this._createCORSConfig({
      // More restrictive in production
      methods: ["GET", "POST", "PUT", "DELETE"],
      // Reduced allowed headers
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Workspace-ID",
      ],
      // Shorter preflight cache
      maxAge: 3600, // 1 hour
      // Stricter origin validation
      origin: (origin, callback) => {
        if (!origin) {
          return callback(new Error("Origin header required"));
        }

        const isAllowed = this.validateOrigin(origin, callback.req);
        if (!isAllowed) {
          return callback(new Error("Origin not allowed by CORS policy"));
        }

        callback(null, true);
      },
    });
  }

  /**
   * Get permissive CORS configuration for development
   * @returns {Object} Permissive CORS configuration
   */
  getPermissiveCORSConfig() {
    return this._createCORSConfig({
      // Allow all origins in development
      origin: true,
      // Allow all methods
      methods: "*",
      // Allow all headers
      allowedHeaders: "*",
      // Longer preflight cache for development
      maxAge: 86400, // 24 hours
    });
  }

  /**
   * Add allowed origin dynamically
   * @param {string} origin - Origin to add
   */
  addAllowedOrigin(origin) {
    if (!this.allowedOrigins.includes(origin)) {
      this.allowedOrigins.push(origin);
      this._logCORSEvent("ORIGIN_ADDED", { origin });
    }
  }

  /**
   * Remove allowed origin dynamically
   * @param {string} origin - Origin to remove
   */
  removeAllowedOrigin(origin) {
    const index = this.allowedOrigins.indexOf(origin);
    if (index > -1) {
      this.allowedOrigins.splice(index, 1);
      this._logCORSEvent("ORIGIN_REMOVED", { origin });
    }
  }

  /**
   * Add blocked origin dynamically
   * @param {string} origin - Origin to block
   */
  addBlockedOrigin(origin) {
    if (!this.blockedOrigins.includes(origin)) {
      this.blockedOrigins.push(origin);
      this._logCORSEvent("ORIGIN_BLOCKED_ADDED", { origin });
    }
  }

  /**
   * Get CORS metrics
   * @returns {Object} CORS metrics
   */
  getMetrics() {
    return {
      ...this.corsMetrics,
      allowedOriginsCount: this.allowedOrigins.length,
      blockedOriginsCount: this.blockedOrigins.length,
      cacheSize: this.corsCache.size,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get current CORS configuration info
   * @returns {Object} CORS configuration info
   */
  getConfigInfo() {
    return {
      allowedOrigins: this.allowedOrigins,
      blockedOrigins: this.blockedOrigins,
      policy: config.isProduction()
        ? CORS_POLICIES.STRICT
        : CORS_POLICIES.PERMISSIVE,
      environment: config.app?.env || process.env.NODE_ENV,
      credentialsEnabled: config.security?.cors?.credentials ?? true,
    };
  }

  /**
   * Log CORS events for security monitoring
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logCORSEvent(event, data) {
    const logEntry = {
      timestamp: generateTimestamp(),
      event,
      data: sanitizeSensitiveData(data),
      source: "CORS_MANAGER",
    };

    // Log security events
    if (event.includes("BLOCKED") || event.includes("REJECTED")) {
      console.warn("🚫 CORS Security Event:", logEntry);
    } else if (config.logging?.level === "debug") {
      console.log("🌐 CORS Event:", logEntry);
    }

    // In production, send to security monitoring service
    if (config.isProduction()) {
      // TODO: Send to security monitoring service
    }
  }
}

// Create singleton instance
const corsManager = new CORSManager();

// Export CORS configuration based on environment
const getCORSMiddleware = () => {
  if (config.isProduction()) {
    return cors(corsManager.getStrictCORSConfig());
  } else if (config.isDevelopment()) {
    return cors(corsManager.getPermissiveCORSConfig());
  } else {
    return cors(corsManager.getCORSConfig());
  }
};

// Export CORS manager and utilities
module.exports = {
  // CORS middleware (main export)
  corsMiddleware: getCORSMiddleware(),

  // CORS manager instance
  corsManager,

  // CORS policies
  CORS_POLICIES,

  // Configuration methods
  getCORSConfig: () => corsManager.getCORSConfig(),
  getStrictCORSConfig: () => corsManager.getStrictCORSConfig(),
  getPermissiveCORSConfig: () => corsManager.getPermissiveCORSConfig(),

  // Dynamic origin management
  addAllowedOrigin: (origin) => corsManager.addAllowedOrigin(origin),
  removeAllowedOrigin: (origin) => corsManager.removeAllowedOrigin(origin),
  addBlockedOrigin: (origin) => corsManager.addBlockedOrigin(origin),

  // Monitoring
  getMetrics: () => corsManager.getMetrics(),
  getConfigInfo: () => corsManager.getConfigInfo(),

  // Validation utilities
  validateOrigin: (origin, req) => corsManager.validateOrigin(origin, req),
  isOriginAllowed: (origin) => corsManager.isOriginAllowed(origin),
  isOriginBlocked: (origin) => corsManager.isOriginBlocked(origin),
};
