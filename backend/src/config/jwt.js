/**
 * JWT Token Management Module
 *
 * This module provides a comprehensive JWT token management system for
 * multi-tenant SaaS applications with enterprise security requirements.
 * Integrated with the enhanced configuration system, logger, error handling,
 * and async utilities for production-ready token management.
 *
 * Features:
 * - Secure token generation with workspace context
 * - Token validation with blacklist support
 * - Refresh token management with rotation
 * - Multi-tenant token scoping
 * - Token introspection and analytics
 * - Security event logging
 * - Integration with enhanced systems
 * - Performance monitoring and metrics
 * - Graceful error handling and recovery
 * - Redis-ready token blacklist management
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('./index');
const logger = require('../utils/logger');
const {
  ApiError,
  SecurityError,
  AuthenticationError,
  ErrorHandler,
} = require('../utils/apiError');
const { asyncHandler } = require('../utils/asyncHandler');

/**
 * Token Types for different use cases
 */
const TOKEN_TYPES = {
  ACCESS: 'access',
  REFRESH: 'refresh',
  EMAIL_VERIFICATION: 'email_verification',
  PASSWORD_RESET: 'password_reset',
  INVITATION: 'invitation',
  API_KEY: 'api_key',
  WORKSPACE_INVITE: 'workspace_invite',
};

/**
 * Token Audiences for different clients
 */
const TOKEN_AUDIENCES = {
  WEB_APP: 'web-app',
  API_CLIENT: 'api-client',
  ADMIN_PANEL: 'admin-panel',
  MOBILE_APP: 'mobile-app',
  WEBHOOK: 'webhook',
};

/**
 * Token Status for tracking
 */
const TOKEN_STATUS = {
  ACTIVE: 'active',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  BLACKLISTED: 'blacklisted',
  INVALID: 'invalid',
};

/**
 * JWT Security Events
 */
const JWT_EVENTS = {
  TOKEN_GENERATED: 'TOKEN_GENERATED',
  TOKEN_VALIDATED: 'TOKEN_VALIDATED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  TOKEN_BLACKLISTED: 'TOKEN_BLACKLISTED',
  TOKEN_REFRESHED: 'TOKEN_REFRESHED',
  SECURITY_VIOLATION: 'SECURITY_VIOLATION',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
  CLEANUP_COMPLETED: 'CLEANUP_COMPLETED',
};

/**
 * JWT Manager Class
 * Handles all JWT operations with enterprise-grade security
 */
class JWTManager {
  constructor() {
    this.secret = config.auth.jwt.secret;
    this.refreshSecret = config.auth.jwt.refreshSecret;
    this.issuer = config.auth.jwt.issuer;
    this.audience = config.auth.jwt.audience;
    this.algorithm = 'HS256';

    // Token storage (Redis in production, Map for development)
    this.tokenBlacklist = new Map(); // Will be replaced with Redis
    this.tokenMetrics = new Map(); // Token usage metrics

    // Performance and security metrics
    this.metrics = {
      tokensGenerated: 0,
      tokensValidated: 0,
      tokensRevoked: 0,
      validationFailures: 0,
      securityViolations: 0,
      refreshOperations: 0,
      cleanupOperations: 0,
      averageValidationTime: 0,
      lastCleanup: null,
      startTime: new Date(),
    };

    // Security thresholds
    this.securityThresholds = {
      maxValidationFailures: 10,
      maxTokensPerUser: 50,
      suspiciousActivityThreshold: 5,
      validationTimeWarning: 100, // ms
    };

    // Cleanup configuration
    this.cleanupInterval = null;
    this.cleanupIntervalMs = 3600000; // 1 hour

    // Initialize cleanup if not in test environment
    if (config.NODE_ENV !== 'test') {
      this._initializeCleanup();
    }

    logger.info('JWT Manager initialized', {
      issuer: this.issuer,
      audience: this.audience,
      algorithm: this.algorithm,
      environment: config.NODE_ENV,
    });
  }

  /**
   * Generate access and refresh token pair
   * @param {Object} payload - Token payload
   * @param {Object} options - Token generation options
   * @returns {Promise<Object>} Token pair with metadata
   */
  async generateTokenPair(payload, options = {}) {
    const startTime = Date.now();

    try {
      // Validate required payload
      this._validateTokenPayload(payload);

      const {
        userId,
        email,
        workspaceId,
        role = 'MEMBER',
        audience = TOKEN_AUDIENCES.WEB_APP,
        deviceId = null,
        ipAddress = null,
        sessionId = null,
        permissions = [],
      } = payload;

      const now = Math.floor(Date.now() / 1000);
      const jti = this._generateJTI();

      // Check security limits
      await this._checkSecurityLimits(userId, ipAddress);

      // Base payload for both tokens
      const basePayload = {
        iss: this.issuer,
        aud: audience,
        sub: userId,
        jti,
        iat: now,

        // Custom claims
        user: {
          id: userId,
          email,
          role,
          permissions,
        },
        workspace: {
          id: workspaceId,
        },

        // Security context
        ...(deviceId && { deviceId }),
        ...(ipAddress && { ipAddress }),
        ...(sessionId && { sessionId }),

        // Security fingerprint
        fingerprint: this._generateFingerprint(userId, deviceId, ipAddress),
      };

      // Generate access token
      const accessTokenPayload = {
        ...basePayload,
        type: TOKEN_TYPES.ACCESS,
        exp: now + this._parseExpiry(config.auth.jwt.accessTokenExpiry),
      };

      // Generate refresh token
      const refreshTokenPayload = {
        ...basePayload,
        type: TOKEN_TYPES.REFRESH,
        exp: now + this._parseExpiry(config.auth.jwt.refreshTokenExpiry),
      };

      // Sign tokens
      const accessToken = jwt.sign(accessTokenPayload, this.secret, {
        algorithm: this.algorithm,
      });

      const refreshToken = jwt.sign(refreshTokenPayload, this.refreshSecret, {
        algorithm: this.algorithm,
      });

      // Update metrics
      this.metrics.tokensGenerated += 2;
      this._updateValidationTime(Date.now() - startTime);

      // Store token metadata
      this._storeTokenMetadata(jti, {
        userId,
        workspaceId,
        type: 'pair',
        createdAt: new Date(),
        ipAddress,
        deviceId,
        audience,
      });

      // Log token generation (security audit)
      this._logSecurityEvent(JWT_EVENTS.TOKEN_GENERATED, {
        userId,
        workspaceId,
        audience,
        jti,
        deviceId,
        ipAddress,
        sessionId,
        tokenTypes: [TOKEN_TYPES.ACCESS, TOKEN_TYPES.REFRESH],
      });

      const tokenPair = {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: this._parseExpiry(config.auth.jwt.accessTokenExpiry),
        metadata: {
          jti,
          issuedAt: new Date(now * 1000).toISOString(),
          expiresAt: new Date(
            (now + this._parseExpiry(config.auth.jwt.accessTokenExpiry)) * 1000,
          ).toISOString(),
          audience,
          workspaceId,
          userId,
          fingerprint: accessTokenPayload.fingerprint,
        },
      };

      return tokenPair;
    } catch (error) {
      this.metrics.validationFailures++;

      const securityError = new SecurityError(
        `Token generation failed: ${error.message}`,
        { userId: payload.userId, ipAddress: payload.ipAddress },
      );

      this._logSecurityEvent(JWT_EVENTS.SECURITY_VIOLATION, {
        event: 'TOKEN_GENERATION_FAILED',
        error: error.message,
        userId: payload.userId,
        ipAddress: payload.ipAddress,
      });

      throw securityError;
    }
  }

  /**
   * Generate special purpose token (email verification, password reset, etc.)
   * @param {Object} payload - Token payload
   * @param {string} type - Token type
   * @param {string} expiresIn - Token expiration
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Generated token
   */
  async generateSpecialToken(payload, type, expiresIn = '1h', options = {}) {
    const startTime = Date.now();

    try {
      // Validate token type
      if (!Object.values(TOKEN_TYPES).includes(type)) {
        throw new ApiError(
          400,
          `Invalid token type: ${type}`,
          'INVALID_TOKEN_TYPE',
        );
      }

      const now = Math.floor(Date.now() / 1000);
      const jti = this._generateJTI();
      const { audience = this.audience, ipAddress = null } = options;

      const tokenPayload = {
        iss: this.issuer,
        aud: audience,
        jti,
        iat: now,
        exp: now + this._parseExpiry(expiresIn),
        type,
        fingerprint: this._generateFingerprint(
          payload.userId,
          payload.deviceId,
          ipAddress,
        ),
        ...payload,
      };

      // Use appropriate secret based on token type
      const secret = this._getSecretForTokenType(type);
      const token = jwt.sign(tokenPayload, secret, {
        algorithm: this.algorithm,
      });

      this.metrics.tokensGenerated++;
      this._updateValidationTime(Date.now() - startTime);

      // Store token metadata
      this._storeTokenMetadata(jti, {
        userId: payload.userId,
        type,
        createdAt: new Date(),
        expiresAt: new Date((now + this._parseExpiry(expiresIn)) * 1000),
        ipAddress,
        audience,
      });

      this._logSecurityEvent(JWT_EVENTS.TOKEN_GENERATED, {
        type,
        jti,
        expiresIn,
        userId: payload.userId,
        audience,
        ipAddress,
      });

      return token;
    } catch (error) {
      this.metrics.validationFailures++;

      this._logSecurityEvent(JWT_EVENTS.SECURITY_VIOLATION, {
        event: 'SPECIAL_TOKEN_GENERATION_FAILED',
        type,
        error: error.message,
        userId: payload.userId,
      });

      throw new SecurityError(
        `Special token generation failed: ${error.message}`,
        { type, userId: payload.userId },
      );
    }
  }

  /**
   * Validate and decode JWT token
   * @param {string} token - JWT token to validate
   * @param {Object} options - Validation options
   * @returns {Promise<Object>} Decoded token payload
   */
  async validateToken(token, options = {}) {
    const startTime = Date.now();

    try {
      if (!token || typeof token !== 'string') {
        throw new AuthenticationError(
          'Invalid token format',
          'INVALID_TOKEN_FORMAT',
        );
      }

      const {
        audience = this.audience,
        ignoreExpiration = false,
        requiredType = null,
        ipAddress = null,
        deviceId = null,
      } = options;

      // Check if token is blacklisted
      if (await this._isTokenBlacklisted(token)) {
        throw new AuthenticationError(
          'Token has been revoked',
          'TOKEN_REVOKED',
        );
      }

      // Determine secret based on token type
      let secret = this.secret;
      try {
        const decoded = jwt.decode(token);
        if (decoded?.type) {
          secret = this._getSecretForTokenType(decoded.type);
        }
      } catch (decodeError) {
        // Continue with default secret
      }

      // Verify token
      const decoded = jwt.verify(token, secret, {
        issuer: this.issuer,
        audience,
        algorithms: [this.algorithm],
        ignoreExpiration,
      });

      // Validate token type if specified
      if (requiredType && decoded.type !== requiredType) {
        throw new AuthenticationError(
          `Invalid token type. Expected: ${requiredType}, Got: ${decoded.type}`,
          'INVALID_TOKEN_TYPE',
        );
      }

      // Validate token structure
      this._validateTokenStructure(decoded);

      // Security fingerprint validation
      if (decoded.fingerprint && (ipAddress || deviceId)) {
        const currentFingerprint = this._generateFingerprint(
          decoded.sub,
          deviceId || decoded.deviceId,
          ipAddress || decoded.ipAddress,
        );

        if (decoded.fingerprint !== currentFingerprint) {
          this._logSecurityEvent(JWT_EVENTS.SUSPICIOUS_ACTIVITY, {
            event: 'FINGERPRINT_MISMATCH',
            userId: decoded.sub,
            jti: decoded.jti,
            expectedFingerprint: decoded.fingerprint,
            actualFingerprint: currentFingerprint,
            ipAddress,
            deviceId,
          });

          throw new SecurityError(
            'Token security validation failed',
            'TOKEN_SECURITY_VIOLATION',
          );
        }
      }

      // Update metrics
      this.metrics.tokensValidated++;
      this._updateValidationTime(Date.now() - startTime);

      // Log successful validation
      this._logSecurityEvent(JWT_EVENTS.TOKEN_VALIDATED, {
        userId: decoded.sub,
        workspaceId: decoded.workspace?.id,
        type: decoded.type,
        jti: decoded.jti,
        audience: decoded.aud,
        ipAddress,
        deviceId,
        validationTime: Date.now() - startTime,
      });

      return decoded;
    } catch (error) {
      this.metrics.validationFailures++;
      this._updateValidationTime(Date.now() - startTime);

      // Log validation failure
      this._logSecurityEvent(JWT_EVENTS.SECURITY_VIOLATION, {
        event: 'TOKEN_VALIDATION_FAILED',
        error: error.message,
        tokenPreview: token ? token.substring(0, 20) + '...' : 'null',
        ipAddress,
        deviceId,
        validationTime: Date.now() - startTime,
      });

      // Transform JWT errors to API errors
      if (error.name === 'TokenExpiredError') {
        throw new AuthenticationError('Token has expired', 'TOKEN_EXPIRED');
      } else if (error.name === 'JsonWebTokenError') {
        throw new AuthenticationError('Invalid token', 'INVALID_TOKEN');
      } else if (error.name === 'NotBeforeError') {
        throw new AuthenticationError(
          'Token not active yet',
          'TOKEN_NOT_ACTIVE',
        );
      } else if (error instanceof ApiError) {
        throw error;
      }

      throw new AuthenticationError(
        `Token validation failed: ${error.message}`,
        'TOKEN_VALIDATION_FAILED',
      );
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} context - Request context
   * @returns {Promise<Object>} New token pair
   */
  async refreshAccessToken(refreshToken, context = {}) {
    const startTime = Date.now();

    try {
      // Validate refresh token
      const decoded = await this.validateToken(refreshToken, {
        requiredType: TOKEN_TYPES.REFRESH,
        ipAddress: context.ipAddress,
        deviceId: context.deviceId,
      });

      // Check if refresh token is still valid and not close to expiry
      const now = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = decoded.exp - now;

      if (timeUntilExpiry < 300) {
        // Less than 5 minutes
        throw new AuthenticationError(
          'Refresh token is too close to expiry',
          'REFRESH_TOKEN_EXPIRED',
        );
      }

      // Security check: validate context matches token
      if (
        context.ipAddress &&
        decoded.ipAddress &&
        context.ipAddress !== decoded.ipAddress
      ) {
        this._logSecurityEvent(JWT_EVENTS.SUSPICIOUS_ACTIVITY, {
          event: 'IP_ADDRESS_MISMATCH',
          userId: decoded.sub,
          jti: decoded.jti,
          tokenIp: decoded.ipAddress,
          requestIp: context.ipAddress,
        });

        throw new SecurityError(
          'Token security validation failed',
          'IP_ADDRESS_MISMATCH',
        );
      }

      // Revoke old refresh token (token rotation)
      await this.revokeToken(refreshToken);

      // Generate new token pair
      const newTokenPair = await this.generateTokenPair({
        userId: decoded.sub,
        email: decoded.user.email,
        workspaceId: decoded.workspace.id,
        role: decoded.user.role,
        permissions: decoded.user.permissions || [],
        audience: decoded.aud,
        deviceId: decoded.deviceId || context.deviceId,
        ipAddress: context.ipAddress,
        sessionId: decoded.sessionId,
      });

      this.metrics.refreshOperations++;

      this._logSecurityEvent(JWT_EVENTS.TOKEN_REFRESHED, {
        userId: decoded.sub,
        workspaceId: decoded.workspace.id,
        oldJti: decoded.jti,
        newJti: newTokenPair.metadata.jti,
        ipAddress: context.ipAddress,
        deviceId: context.deviceId,
        refreshTime: Date.now() - startTime,
      });

      return newTokenPair;
    } catch (error) {
      this.metrics.validationFailures++;

      this._logSecurityEvent(JWT_EVENTS.SECURITY_VIOLATION, {
        event: 'TOKEN_REFRESH_FAILED',
        error: error.message,
        ipAddress: context.ipAddress,
        deviceId: context.deviceId,
      });

      if (error instanceof ApiError) {
        throw error;
      }

      throw new AuthenticationError(
        `Token refresh failed: ${error.message}`,
        'TOKEN_REFRESH_FAILED',
      );
    }
  }

  /**
   * Revoke a token (add to blacklist)
   * @param {string} token - Token to revoke
   * @param {Object} context - Revocation context
   * @returns {Promise<boolean>} Success status
   */
  async revokeToken(token, context = {}) {
    try {
      const decoded = jwt.decode(token);

      if (decoded && decoded.jti) {
        // Add to blacklist with TTL
        const ttl = decoded.exp ? decoded.exp * 1000 - Date.now() : 86400000; // 24 hours default
        await this._addToBlacklist(token, decoded.jti, ttl);

        this.metrics.tokensRevoked++;

        this._logSecurityEvent(JWT_EVENTS.TOKEN_REVOKED, {
          userId: decoded.sub,
          jti: decoded.jti,
          type: decoded.type,
          workspaceId: decoded.workspace?.id,
          reason: context.reason || 'manual_revocation',
          revokedBy: context.revokedBy,
          ipAddress: context.ipAddress,
        });

        return true;
      }

      return false;
    } catch (error) {
      logger.error('Token revocation failed', {
        error: error.message,
        tokenPreview: token ? token.substring(0, 20) + '...' : 'null',
      });
      return false;
    }
  }

  /**
   * Revoke all tokens for a user
   * @param {string} userId - User ID
   * @param {Object} context - Revocation context
   * @returns {Promise<number>} Number of tokens revoked
   */
  async revokeAllUserTokens(userId, context = {}) {
    try {
      let revokedCount = 0;

      // Get all tokens for user from metadata store
      const userTokens = this._getUserTokens(userId);

      for (const tokenData of userTokens) {
        if (tokenData.token) {
          const success = await this.revokeToken(tokenData.token, {
            ...context,
            reason: 'bulk_revocation',
          });
          if (success) revokedCount++;
        }
      }

      this._logSecurityEvent(JWT_EVENTS.TOKEN_REVOKED, {
        userId,
        count: revokedCount,
        reason: context.reason || 'user_token_revocation',
        revokedBy: context.revokedBy,
        ipAddress: context.ipAddress,
      });

      return revokedCount;
    } catch (error) {
      logger.error('Bulk token revocation failed', {
        userId,
        error: error.message,
      });
      return 0;
    }
  }

  /**
   * Get token introspection data
   * @param {string} token - Token to introspect
   * @returns {Promise<Object>} Token introspection data
   */
  async introspectToken(token) {
    try {
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded) {
        return { active: false, error: 'Invalid token format' };
      }

      const now = Math.floor(Date.now() / 1000);
      const isExpired = decoded.payload.exp < now;
      const isRevoked = await this._isTokenBlacklisted(token);

      const introspection = {
        active: !isExpired && !isRevoked,
        token_type: decoded.payload.type || TOKEN_TYPES.ACCESS,
        client_id: decoded.payload.aud,
        username: decoded.payload.user?.email,
        sub: decoded.payload.sub,
        exp: decoded.payload.exp,
        iat: decoded.payload.iat,
        jti: decoded.payload.jti,
        workspace_id: decoded.payload.workspace?.id,
        role: decoded.payload.user?.role,
        permissions: decoded.payload.user?.permissions || [],
        device_id: decoded.payload.deviceId,
        session_id: decoded.payload.sessionId,
        fingerprint: decoded.payload.fingerprint,
        revoked: isRevoked,
        expired: isExpired,
        issuer: decoded.payload.iss,
        audience: decoded.payload.aud,
        algorithm: decoded.header.alg,
      };

      // Add metadata if available
      const metadata = this._getTokenMetadata(decoded.payload.jti);
      if (metadata) {
        introspection.metadata = {
          created_at: metadata.createdAt,
          ip_address: metadata.ipAddress,
          user_agent: metadata.userAgent,
        };
      }

      return introspection;
    } catch (error) {
      logger.error('Token introspection failed', {
        error: error.message,
        tokenPreview: token ? token.substring(0, 20) + '...' : 'null',
      });

      return {
        active: false,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Get comprehensive JWT manager metrics
   * @returns {Object} Metrics data
   */
  getMetrics() {
    const uptime = Date.now() - this.metrics.startTime.getTime();
    const errorRate =
      this.metrics.validationFailures / (this.metrics.tokensValidated || 1);

    return {
      // Basic metrics
      tokensGenerated: this.metrics.tokensGenerated,
      tokensValidated: this.metrics.tokensValidated,
      tokensRevoked: this.metrics.tokensRevoked,
      validationFailures: this.metrics.validationFailures,
      securityViolations: this.metrics.securityViolations,
      refreshOperations: this.metrics.refreshOperations,
      cleanupOperations: this.metrics.cleanupOperations,

      // Performance metrics
      averageValidationTime: this.metrics.averageValidationTime,
      errorRate: Math.round(errorRate * 10000) / 100, // Percentage with 2 decimals

      // Storage metrics
      blacklistedTokens: this.tokenBlacklist.size,
      storedMetadata: this.tokenMetrics.size,

      // System metrics
      uptime: Math.round(uptime / 1000), // seconds
      lastCleanup: this.metrics.lastCleanup,

      // Health indicators
      status: errorRate < 0.1 ? 'healthy' : 'degraded',

      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    const metrics = this.getMetrics();
    const isHealthy =
      metrics.status === 'healthy' &&
      metrics.errorRate < 10 &&
      metrics.averageValidationTime < 200;

    return {
      status: isHealthy ? 'healthy' : 'degraded',
      checks: {
        errorRate: {
          status: metrics.errorRate < 10 ? 'pass' : 'fail',
          value: `${metrics.errorRate}%`,
          threshold: '10%',
        },
        validationTime: {
          status: metrics.averageValidationTime < 200 ? 'pass' : 'fail',
          value: `${metrics.averageValidationTime}ms`,
          threshold: '200ms',
        },
        blacklistSize: {
          status: metrics.blacklistedTokens < 10000 ? 'pass' : 'warn',
          value: metrics.blacklistedTokens,
          threshold: 10000,
        },
      },
      metrics: {
        uptime: metrics.uptime,
        tokensGenerated: metrics.tokensGenerated,
        tokensValidated: metrics.tokensValidated,
        errorRate: metrics.errorRate,
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Clean up expired tokens from blacklist and metadata
   * @returns {Promise<Object>} Cleanup results
   */
  async cleanupExpiredTokens() {
    const startTime = Date.now();
    let cleanedBlacklist = 0;
    let cleanedMetadata = 0;

    try {
      const now = Date.now();

      // Clean blacklist
      for (const [token, data] of this.tokenBlacklist.entries()) {
        if (data.expiresAt && data.expiresAt < now) {
          this.tokenBlacklist.delete(token);
          cleanedBlacklist++;
        }
      }

      // Clean metadata
      for (const [jti, data] of this.tokenMetrics.entries()) {
        if (data.expiresAt && data.expiresAt < new Date()) {
          this.tokenMetrics.delete(jti);
          cleanedMetadata++;
        }
      }

      this.metrics.cleanupOperations++;
      this.metrics.lastCleanup = new Date();

      const duration = Date.now() - startTime;

      this._logSecurityEvent(JWT_EVENTS.CLEANUP_COMPLETED, {
        cleanedBlacklist,
        cleanedMetadata,
        duration,
        remainingBlacklist: this.tokenBlacklist.size,
        remainingMetadata: this.tokenMetrics.size,
      });

      logger.info('JWT cleanup completed', {
        cleanedBlacklist,
        cleanedMetadata,
        duration: `${duration}ms`,
        remainingBlacklist: this.tokenBlacklist.size,
        remainingMetadata: this.tokenMetrics.size,
      });

      return {
        success: true,
        cleanedBlacklist,
        cleanedMetadata,
        duration,
        remainingBlacklist: this.tokenBlacklist.size,
        remainingMetadata: this.tokenMetrics.size,
      };
    } catch (error) {
      logger.error('JWT cleanup failed', {
        error: error.message,
        duration: Date.now() - startTime,
      });

      return {
        success: false,
        error: error.message,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Graceful shutdown
   * @returns {Promise<void>}
   */
  async gracefulShutdown() {
    logger.info('JWT Manager shutting down gracefully');

    // Clear cleanup interval
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    // Perform final cleanup
    await this.cleanupExpiredTokens();

    // Clear in-memory stores
    this.tokenBlacklist.clear();
    this.tokenMetrics.clear();

    logger.info('JWT Manager shutdown completed', {
      finalMetrics: this.getMetrics(),
    });
  }

  // === Private Methods ===

  /**
   * Initialize cleanup interval
   * @private
   */
  _initializeCleanup() {
    this.cleanupInterval = setInterval(async () => {
      try {
        await this.cleanupExpiredTokens();
      } catch (error) {
        logger.error('Scheduled JWT cleanup failed', {
          error: error.message,
        });
      }
    }, this.cleanupIntervalMs);

    logger.debug('JWT cleanup scheduled', {
      interval: `${this.cleanupIntervalMs}ms`,
    });
  }

  /**
   * Validate token payload
   * @param {Object} payload - Token payload to validate
   * @private
   */
  _validateTokenPayload(payload) {
    const requiredFields = ['userId', 'email', 'workspaceId'];

    for (const field of requiredFields) {
      if (!payload[field]) {
        throw new ApiError(
          400,
          `Missing required token payload field: ${field}`,
          'INVALID_TOKEN_PAYLOAD',
        );
      }
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(payload.email)) {
      throw new ApiError(
        400,
        'Invalid email format in token payload',
        'INVALID_EMAIL_FORMAT',
      );
    }
  }

  /**
   * Check security limits
   * @param {string} userId - User ID
   * @param {string} ipAddress - IP address
   * @private
   */
  async _checkSecurityLimits(userId, ipAddress) {
    // Check token generation rate
    const userTokens = this._getUserTokens(userId);
    if (userTokens.length > this.securityThresholds.maxTokensPerUser) {
      this.metrics.securityViolations++;

      this._logSecurityEvent(JWT_EVENTS.SUSPICIOUS_ACTIVITY, {
        event: 'EXCESSIVE_TOKEN_GENERATION',
        userId,
        ipAddress,
        tokenCount: userTokens.length,
        threshold: this.securityThresholds.maxTokensPerUser,
      });

      throw new SecurityError(
        'Token generation rate limit exceeded',
        'RATE_LIMIT_EXCEEDED',
      );
    }
  }

  /**
   * Generate unique JWT ID
   * @returns {string} Unique JTI
   * @private
   */
  _generateJTI() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate security fingerprint
   * @param {string} userId - User ID
   * @param {string} deviceId - Device ID
   * @param {string} ipAddress - IP address
   * @returns {string} Security fingerprint
   * @private
   */
  _generateFingerprint(userId, deviceId, ipAddress) {
    const data = `${userId}:${deviceId || 'unknown'}:${ipAddress || 'unknown'}`;
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Parse expiry string to seconds
   * @param {string} expiryString - Expiry string (e.g., '7d', '1h')
   * @returns {number} Seconds until expiry
   * @private
   */
  _parseExpiry(expiryString) {
    const units = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
      w: 604800,
    };

    const match = expiryString.match(/^(\d+)([smhdw])$/);
    if (!match) {
      throw new ApiError(
        400,
        `Invalid expiry format: ${expiryString}`,
        'INVALID_EXPIRY_FORMAT',
      );
    }

    const [, amount, unit] = match;
    return parseInt(amount) * units[unit];
  }

  /**
   * Get secret for token type
   * @param {string} tokenType - Token type
   * @returns {string} Secret for token type
   * @private
   */
  _getSecretForTokenType(tokenType) {
    switch (tokenType) {
      case TOKEN_TYPES.REFRESH:
        return this.refreshSecret;
      case TOKEN_TYPES.ACCESS:
      case TOKEN_TYPES.EMAIL_VERIFICATION:
      case TOKEN_TYPES.PASSWORD_RESET:
      case TOKEN_TYPES.INVITATION:
      case TOKEN_TYPES.WORKSPACE_INVITE:
      default:
        return this.secret;
    }
  }

  /**
   * Validate token structure
   * @param {Object} decoded - Decoded token
   * @private
   */
  _validateTokenStructure(decoded) {
    const requiredFields = ['sub', 'iat', 'exp', 'jti', 'iss', 'aud'];

    for (const field of requiredFields) {
      if (!decoded[field]) {
        throw new AuthenticationError(
          `Missing required token field: ${field}`,
          'INVALID_TOKEN_STRUCTURE',
        );
      }
    }

    // Validate workspace context for access tokens
    if (decoded.type === TOKEN_TYPES.ACCESS && !decoded.workspace?.id) {
      throw new AuthenticationError(
        'Missing workspace context in access token',
        'MISSING_WORKSPACE_CONTEXT',
      );
    }
  }

  /**
   * Store token metadata
   * @param {string} jti - JWT ID
   * @param {Object} metadata - Token metadata
   * @private
   */
  _storeTokenMetadata(jti, metadata) {
    this.tokenMetrics.set(jti, {
      ...metadata,
      createdAt: new Date(),
    });
  }

  /**
   * Get token metadata
   * @param {string} jti - JWT ID
   * @returns {Object|null} Token metadata
   * @private
   */
  _getTokenMetadata(jti) {
    return this.tokenMetrics.get(jti) || null;
  }

  /**
   * Get user tokens
   * @param {string} userId - User ID
   * @returns {Array} User tokens
   * @private
   */
  _getUserTokens(userId) {
    const userTokens = [];

    for (const [jti, metadata] of this.tokenMetrics.entries()) {
      if (metadata.userId === userId) {
        userTokens.push({ jti, ...metadata });
      }
    }

    return userTokens;
  }

  /**
   * Add token to blacklist
   * @param {string} token - Token to blacklist
   * @param {string} jti - JWT ID
   * @param {number} ttl - Time to live in milliseconds
   * @private
   */
  async _addToBlacklist(token, jti, ttl) {
    const expiresAt = Date.now() + ttl;

    this.tokenBlacklist.set(token, {
      jti,
      blacklistedAt: new Date(),
      expiresAt,
    });
  }

  /**
   * Check if token is blacklisted
   * @param {string} token - Token to check
   * @returns {Promise<boolean>} True if blacklisted
   * @private
   */
  async _isTokenBlacklisted(token) {
    const blacklistEntry = this.tokenBlacklist.get(token);

    if (!blacklistEntry) {
      return false;
    }

    // Check if blacklist entry has expired
    if (blacklistEntry.expiresAt && blacklistEntry.expiresAt < Date.now()) {
      this.tokenBlacklist.delete(token);
      return false;
    }

    return true;
  }

  /**
   * Update validation time metrics
   * @param {number} time - Validation time in milliseconds
   * @private
   */
  _updateValidationTime(time) {
    this.metrics.averageValidationTime =
      (this.metrics.averageValidationTime + time) / 2;

    if (time > this.securityThresholds.validationTimeWarning) {
      logger.warn('Slow JWT validation detected', {
        validationTime: `${time}ms`,
        threshold: `${this.securityThresholds.validationTimeWarning}ms`,
      });
    }
  }

  /**
   * Log security events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logSecurityEvent(event, data) {
    const logEntry = {
      event,
      timestamp: new Date().toISOString(),
      data,
      source: 'JWT_MANAGER',
      environment: config.NODE_ENV,
    };

    // Use logger's security method for security events
    logger.security(event, logEntry);

    // Debug logging in development
    if (config.isDevelopment() && config.logging.level === 'debug') {
      logger.debug('JWT Security Event', logEntry);
    }
  }
}

// Create singleton instance
const jwtManager = new JWTManager();

// Wrapped operations with async handling
const wrappedOperations = {
  generateTokenPair: asyncHandler(async (payload, options) => {
    return await jwtManager.generateTokenPair(payload, options);
  }),

  generateSpecialToken: asyncHandler(
    async (payload, type, expiresIn, options) => {
      return await jwtManager.generateSpecialToken(
        payload,
        type,
        expiresIn,
        options,
      );
    },
  ),

  validateToken: asyncHandler(async (token, options) => {
    return await jwtManager.validateToken(token, options);
  }),

  refreshAccessToken: asyncHandler(async (refreshToken, context) => {
    return await jwtManager.refreshAccessToken(refreshToken, context);
  }),

  revokeToken: asyncHandler(async (token, context) => {
    return await jwtManager.revokeToken(token, context);
  }),

  revokeAllUserTokens: asyncHandler(async (userId, context) => {
    return await jwtManager.revokeAllUserTokens(userId, context);
  }),

  introspectToken: asyncHandler(async (token) => {
    return await jwtManager.introspectToken(token);
  }),

  cleanupExpiredTokens: asyncHandler(async () => {
    return await jwtManager.cleanupExpiredTokens();
  }),
};

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  await jwtManager.gracefulShutdown();
});

process.on('SIGINT', async () => {
  await jwtManager.gracefulShutdown();
});

// Export JWT manager and utilities
module.exports = {
  // Main JWT manager instance
  jwtManager,

  // Constants
  TOKEN_TYPES,
  TOKEN_AUDIENCES,
  TOKEN_STATUS,
  JWT_EVENTS,

  // Wrapped operations (maintaining backward compatibility)
  ...wrappedOperations,

  // Convenience methods (backward compatibility)
  generateTokenPair: wrappedOperations.generateTokenPair,
  generateSpecialToken: wrappedOperations.generateSpecialToken,
  validateToken: wrappedOperations.validateToken,
  refreshAccessToken: wrappedOperations.refreshAccessToken,
  revokeToken: wrappedOperations.revokeToken,
  revokeAllUserTokens: wrappedOperations.revokeAllUserTokens,
  introspectToken: wrappedOperations.introspectToken,

  // Utility functions
  decodeToken: (token) => jwt.decode(token),
  isTokenExpired: (token) => {
    try {
      const decoded = jwt.decode(token);
      return decoded.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  },

  // Health and metrics
  getMetrics: () => jwtManager.getMetrics(),
  getHealthStatus: () => jwtManager.getHealthStatus(),
  cleanupExpiredTokens: wrappedOperations.cleanupExpiredTokens,

  // Management
  gracefulShutdown: () => jwtManager.gracefulShutdown(),
};
