/**
 * Helmet Security Headers Configuration Module
 *
 * This module provides comprehensive HTTP security headers configuration
 * for multi-tenant SaaS applications with enterprise security requirements:
 *
 * Features:
 * - Content Security Policy (CSP) with nonce support
 * - HTTP Strict Transport Security (HSTS)
 * - X-Frame-Options protection against clickjacking
 * - XSS Protection and content type sniffing prevention
 * - Referrer Policy and Permissions Policy
 * - Environment-specific security configurations
 * - Security headers monitoring and reporting
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const helmet = require('helmet');
const crypto = require('crypto');
const config = require('../config');

/**
 * Security Policy Levels
 */
const SECURITY_LEVELS = {
  STRICT: 'strict', // Maximum security for production
  BALANCED: 'balanced', // Good security with usability
  PERMISSIVE: 'permissive', // Development-friendly
};

/**
 * CSP Directive Types
 */
const CSP_DIRECTIVES = {
  DEFAULT_SRC: 'default-src',
  SCRIPT_SRC: 'script-src',
  STYLE_SRC: 'style-src',
  IMG_SRC: 'img-src',
  FONT_SRC: 'font-src',
  CONNECT_SRC: 'connect-src',
  MEDIA_SRC: 'media-src',
  OBJECT_SRC: 'object-src',
  FRAME_SRC: 'frame-src',
  WORKER_SRC: 'worker-src',
  MANIFEST_SRC: 'manifest-src',
};

/**
 * Security Headers Manager Class
 * Handles dynamic security headers configuration
 */
class SecurityHeadersManager {
  constructor() {
    this.securityMetrics = {
      cspViolations: 0,
      xssAttempts: 0,
      clickjackingAttempts: 0,
      httpsUpgrades: 0,
      securityHeadersServed: 0,
    };

    this.nonceCache = new Map();
    this.cspReports = [];
    this.maxCspReports = 1000;
  }

  /**
   * Get Content Security Policy configuration
   * @param {Object} options - CSP options
   * @returns {Object} CSP configuration
   */
  getCSPConfig(options = {}) {
    const { level = SECURITY_LEVELS.BALANCED, nonce, workspaceId } = options;

    const baseDirectives = {
      [CSP_DIRECTIVES.DEFAULT_SRC]: ["'self'"],
      [CSP_DIRECTIVES.SCRIPT_SRC]: this.getScriptSrcDirectives(level, nonce),
      [CSP_DIRECTIVES.STYLE_SRC]: this.getStyleSrcDirectives(level, nonce),
      [CSP_DIRECTIVES.IMG_SRC]: this.getImgSrcDirectives(level),
      [CSP_DIRECTIVES.FONT_SRC]: this.getFontSrcDirectives(level),
      [CSP_DIRECTIVES.CONNECT_SRC]: this.getConnectSrcDirectives(level),
      [CSP_DIRECTIVES.MEDIA_SRC]: this.getMediaSrcDirectives(level),
      [CSP_DIRECTIVES.OBJECT_SRC]: ["'none'"],
      [CSP_DIRECTIVES.FRAME_SRC]: this.getFrameSrcDirectives(level),
      [CSP_DIRECTIVES.WORKER_SRC]: ["'self'"],
      [CSP_DIRECTIVES.MANIFEST_SRC]: ["'self'"],
    };

    // Add workspace-specific directives if needed
    if (workspaceId) {
      baseDirectives[CSP_DIRECTIVES.CONNECT_SRC].push(
        `https://${workspaceId}.${config.app.domain || 'localhost'}`,
      );
    }

    return {
      directives: baseDirectives,
      reportOnly: config.isDevelopment(),
      reportUri: '/api/v1/security/csp-report',
      upgradeInsecureRequests: config.isProduction(),
      blockAllMixedContent: config.isProduction(),
    };
  }

  /**
   * Get script-src directives based on security level
   * @param {string} level - Security level
   * @param {string} nonce - CSP nonce
   * @returns {Array} Script source directives
   */
  getScriptSrcDirectives(level, nonce) {
    const directives = ["'self'"];

    if (nonce) {
      directives.push(`'nonce-${nonce}'`);
    }

    switch (level) {
      case SECURITY_LEVELS.STRICT:
        // Strict: Only self and nonce
        break;

      case SECURITY_LEVELS.BALANCED:
        // Balanced: Add common CDNs
        directives.push(
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
          'https://unpkg.com',
        );
        break;

      case SECURITY_LEVELS.PERMISSIVE:
        // Permissive: Add unsafe-inline for development
        directives.push(
          "'unsafe-inline'",
          "'unsafe-eval'",
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
          'https://unpkg.com',
        );
        break;
    }

    return directives;
  }

  /**
   * Get style-src directives based on security level
   * @param {string} level - Security level
   * @param {string} nonce - CSP nonce
   * @returns {Array} Style source directives
   */
  getStyleSrcDirectives(level, nonce) {
    const directives = ["'self'"];

    if (nonce) {
      directives.push(`'nonce-${nonce}'`);
    }

    switch (level) {
      case SECURITY_LEVELS.STRICT:
        directives.push("'unsafe-hashes'"); // For styled-components hashes
        break;

      case SECURITY_LEVELS.BALANCED:
        directives.push(
          "'unsafe-inline'", // Often needed for CSS-in-JS
          'https://fonts.googleapis.com',
          'https://cdn.jsdelivr.net',
        );
        break;

      case SECURITY_LEVELS.PERMISSIVE:
        directives.push(
          "'unsafe-inline'",
          "'unsafe-eval'",
          'https://fonts.googleapis.com',
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com',
        );
        break;
    }

    return directives;
  }

  /**
   * Get img-src directives based on security level
   * @param {string} level - Security level
   * @returns {Array} Image source directives
   */
  getImgSrcDirectives(level) {
    const directives = ["'self'", 'data:', 'blob:'];

    switch (level) {
      case SECURITY_LEVELS.STRICT:
        // Strict: Only self, data, and blob
        break;

      case SECURITY_LEVELS.BALANCED:
      case SECURITY_LEVELS.PERMISSIVE:
        directives.push(
          'https:',
          'https://images.unsplash.com',
          'https://avatars.githubusercontent.com',
          'https://lh3.googleusercontent.com', // Google profile images
        );
        break;
    }

    return directives;
  }

  /**
   * Get font-src directives based on security level
   * @param {string} level - Security level
   * @returns {Array} Font source directives
   */
  getFontSrcDirectives(level) {
    const directives = ["'self'", 'data:'];

    if (level !== SECURITY_LEVELS.STRICT) {
      directives.push(
        'https://fonts.gstatic.com',
        'https://fonts.googleapis.com',
      );
    }

    return directives;
  }

  /**
   * Get connect-src directives based on security level
   * @param {string} level - Security level
   * @returns {Array} Connect source directives
   */
  getConnectSrcDirectives(level) {
    const directives = ["'self'"];

    // Add API URL
    if (config.app.apiUrl) {
      directives.push(config.app.apiUrl);
    }

    switch (level) {
      case SECURITY_LEVELS.STRICT:
        // Strict: Only self and API
        break;

      case SECURITY_LEVELS.BALANCED:
        directives.push(
          'https://api.github.com',
          'https://accounts.google.com',
        );
        break;

      case SECURITY_LEVELS.PERMISSIVE:
        directives.push('https:', 'wss:', 'ws:');
        break;
    }

    return directives;
  }

  /**
   * Get media-src directives based on security level
   * @param {string} level - Security level
   * @returns {Array} Media source directives
   */
  getMediaSrcDirectives(level) {
    const directives = ["'self'", 'blob:', 'data:'];

    if (level !== SECURITY_LEVELS.STRICT) {
      directives.push('https:');
    }

    return directives;
  }

  /**
   * Get frame-src directives based on security level
   * @param {string} level - Security level
   * @returns {Array} Frame source directives
   */
  getFrameSrcDirectives(level) {
    const directives = ["'self'"];

    switch (level) {
      case SECURITY_LEVELS.STRICT:
        // Strict: Only self
        break;

      case SECURITY_LEVELS.BALANCED:
        directives.push(
          'https://accounts.google.com',
          'https://login.microsoftonline.com',
        );
        break;

      case SECURITY_LEVELS.PERMISSIVE:
        directives.push('https:');
        break;
    }

    return directives;
  }

  /**
   * Get HSTS configuration
   * @returns {Object} HSTS configuration
   */
  getHSTSConfig() {
    return {
      maxAge: config.isProduction() ? 31536000 : 0, // 1 year in production, 0 in dev
      includeSubDomains: config.isProduction(),
      preload: config.isProduction(),
    };
  }

  /**
   * Get X-Frame-Options configuration
   * @returns {Object} X-Frame-Options configuration
   */
  getFrameOptionsConfig() {
    return {
      action: config.isProduction() ? 'deny' : 'sameorigin',
    };
  }

  /**
   * Get Referrer Policy configuration
   * @returns {Object} Referrer Policy configuration
   */
  getReferrerPolicyConfig() {
    return {
      policy: config.isProduction()
        ? 'strict-origin-when-cross-origin'
        : 'no-referrer-when-downgrade',
    };
  }

  /**
   * Get Permissions Policy configuration
   * @returns {Object} Permissions Policy configuration
   */
  getPermissionsPolicyConfig() {
    return {
      features: {
        camera: ["'self'"],
        microphone: ["'self'"],
        geolocation: ["'self'"],
        gyroscope: ["'none'"],
        magnetometer: ["'none'"],
        payment: ["'self'"],
        usb: ["'none'"],
        fullscreen: ["'self'"],
        autoplay: ["'self'"],
      },
    };
  }

  /**
   * Generate CSP nonce for request
   * @param {Object} req - Express request object
   * @returns {string} Generated nonce
   */
  generateNonce(req) {
    const nonce = crypto.randomBytes(16).toString('base64');

    // Cache nonce for request
    this.nonceCache.set(req.id || req.sessionID, nonce);

    // Clean up old nonces
    if (this.nonceCache.size > 1000) {
      const keys = Array.from(this.nonceCache.keys());
      const oldKeys = keys.slice(0, 500);
      oldKeys.forEach((key) => this.nonceCache.delete(key));
    }

    return nonce;
  }

  /**
   * Get comprehensive Helmet configuration
   * @param {Object} options - Configuration options
   * @returns {Object} Helmet configuration
   */
  getHelmetConfig(options = {}) {
    const {
      level = config.isProduction()
        ? SECURITY_LEVELS.STRICT
        : SECURITY_LEVELS.BALANCED,
      nonce,
      workspaceId,
    } = options;

    const helmetConfig = {
      // Content Security Policy
      contentSecurityPolicy: config.security.helmet.contentSecurityPolicy
        ? this.getCSPConfig({ level, nonce, workspaceId })
        : false,

      // HTTP Strict Transport Security
      hsts: config.security.helmet.hsts ? this.getHSTSConfig() : false,

      // X-Frame-Options
      frameguard: config.security.helmet.frameguard
        ? this.getFrameOptionsConfig()
        : false,

      // X-Content-Type-Options
      noSniff: true,

      // X-XSS-Protection
      xssFilter: true,

      // Referrer Policy
      referrerPolicy: this.getReferrerPolicyConfig(),

      // Permissions Policy
      permissionsPolicy: this.getPermissionsPolicyConfig(),

      // Hide X-Powered-By header
      hidePoweredBy: true,

      // DNS Prefetch Control
      dnsPrefetchControl: {
        allow: !config.isProduction(),
      },

      // Expect-CT
      expectCt: config.isProduction()
        ? {
            maxAge: 86400,
            enforce: true,
          }
        : false,

      // Cross-Origin Embedder Policy
      crossOriginEmbedderPolicy: config.isProduction()
        ? {
            policy: 'require-corp',
          }
        : false,

      // Cross-Origin Opener Policy
      crossOriginOpenerPolicy: {
        policy: 'same-origin',
      },

      // Cross-Origin Resource Policy
      crossOriginResourcePolicy: {
        policy: 'cross-origin',
      },
    };

    this.securityMetrics.securityHeadersServed++;

    return helmetConfig;
  }

  /**
   * Get strict production Helmet configuration
   * @returns {Object} Strict Helmet configuration
   */
  getStrictHelmetConfig() {
    return this.getHelmetConfig({ level: SECURITY_LEVELS.STRICT });
  }

  /**
   * Get permissive development Helmet configuration
   * @returns {Object} Permissive Helmet configuration
   */
  getPermissiveHelmetConfig() {
    return this.getHelmetConfig({ level: SECURITY_LEVELS.PERMISSIVE });
  }

  /**
   * Process CSP violation report
   * @param {Object} report - CSP violation report
   */
  processCspReport(report) {
    this.securityMetrics.cspViolations++;

    // Store report (limit to prevent memory issues)
    this.cspReports.push({
      ...report,
      timestamp: new Date().toISOString(),
    });

    if (this.cspReports.length > this.maxCspReports) {
      this.cspReports.shift();
    }

    // Log security violation
    this._logSecurityEvent('CSP_VIOLATION', {
      blockedUri: report['blocked-uri'],
      documentUri: report['document-uri'],
      violatedDirective: report['violated-directive'],
      originalPolicy: report['original-policy'],
    });
  }

  /**
   * Create nonce middleware
   * @returns {Function} Express middleware
   */
  createNonceMiddleware() {
    return (req, res, next) => {
      const nonce = this.generateNonce(req);
      req.nonce = nonce;
      res.locals.nonce = nonce;
      next();
    };
  }

  /**
   * Create CSP report handler middleware
   * @returns {Function} Express middleware
   */
  createCspReportHandler() {
    return (req, res, next) => {
      if (req.body && req.body['csp-report']) {
        this.processCspReport(req.body['csp-report']);
      }
      res.status(204).send();
    };
  }

  /**
   * Get security metrics
   * @returns {Object} Security metrics
   */
  getMetrics() {
    return {
      ...this.securityMetrics,
      cspReportsCount: this.cspReports.length,
      nonceCacheSize: this.nonceCache.size,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get recent CSP reports
   * @param {number} limit - Number of reports to return
   * @returns {Array} Recent CSP reports
   */
  getRecentCspReports(limit = 50) {
    return this.cspReports.slice(-limit);
  }

  /**
   * Log security events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logSecurityEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'SECURITY_HEADERS_MANAGER',
    };

    console.warn('🛡️  Security Event:', logEntry);

    // In production, send to security monitoring service
    if (config.isProduction()) {
      // TODO: Send to security monitoring service
    }
  }
}

// Create singleton instance
const securityHeadersManager = new SecurityHeadersManager();

// Export Helmet middleware based on environment
const getHelmetMiddleware = (options = {}) => {
  const helmetConfig = securityHeadersManager.getHelmetConfig(options);
  return helmet(helmetConfig);
};

// Export security headers manager and utilities
module.exports = {
  // Helmet middleware (main export)
  helmetMiddleware: getHelmetMiddleware(),

  // Security headers manager instance
  securityHeadersManager,

  // Security levels
  SECURITY_LEVELS,

  // CSP directives
  CSP_DIRECTIVES,

  // Configuration methods
  getHelmetConfig: (options) => securityHeadersManager.getHelmetConfig(options),
  getStrictHelmetConfig: () => securityHeadersManager.getStrictHelmetConfig(),
  getPermissiveHelmetConfig: () =>
    securityHeadersManager.getPermissiveHelmetConfig(),

  // Middleware creators
  createNonceMiddleware: () => securityHeadersManager.createNonceMiddleware(),
  createCspReportHandler: () => securityHeadersManager.createCspReportHandler(),

  // Nonce management
  generateNonce: (req) => securityHeadersManager.generateNonce(req),

  // CSP reporting
  processCspReport: (report) => securityHeadersManager.processCspReport(report),
  getRecentCspReports: (limit) =>
    securityHeadersManager.getRecentCspReports(limit),

  // Monitoring
  getMetrics: () => securityHeadersManager.getMetrics(),

  // Dynamic configuration
  getHelmetMiddleware,
};
