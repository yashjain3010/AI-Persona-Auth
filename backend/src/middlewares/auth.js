/**
 * Authentication Middleware Module
 *
 * This module provides comprehensive authentication middleware for
 * multi-tenant SaaS applications with enterprise security requirements:
 *
 * Features:
 * - JWT token validation with workspace context
 * - User authentication and authorization
 * - Role-based access control (RBAC)
 * - Workspace membership validation
 * - Session management and token refresh
 * - Security event logging and monitoring
 * - Graceful error handling with proper HTTP status codes
 *
 * @author AI-Persona Backend Team
 * @version 1.0.0
 */

const { validateToken, TOKEN_TYPES, revokeToken } = require('../config/jwt');
const { client: prisma } = require('../config/database');
const config = require('../config');

/**
 * Authentication Result Types
 */
const AUTH_RESULTS = {
  SUCCESS: 'success',
  INVALID_TOKEN: 'invalid_token',
  EXPIRED_TOKEN: 'expired_token',
  USER_NOT_FOUND: 'user_not_found',
  USER_INACTIVE: 'user_inactive',
  NO_WORKSPACE_ACCESS: 'no_workspace_access',
  INSUFFICIENT_PERMISSIONS: 'insufficient_permissions',
  TOKEN_REVOKED: 'token_revoked',
};

/**
 * User Roles with hierarchical permissions
 */
const USER_ROLES = {
  ADMIN: 'ADMIN',
  MEMBER: 'MEMBER',
};

/**
 * Role hierarchy for permission checking
 */
const ROLE_HIERARCHY = {
  [USER_ROLES.ADMIN]: 2,
  [USER_ROLES.MEMBER]: 1,
};

/**
 * Authentication Manager Class
 * Handles all authentication middleware logic
 */
class AuthenticationMiddleware {
  constructor() {
    this.authMetrics = {
      successfulAuthentications: 0,
      failedAuthentications: 0,
      tokenRefreshes: 0,
      permissionDenials: 0,
      suspiciousActivity: 0,
    };
  }

  /**
   * Main authentication middleware
   * Validates JWT token and loads user context
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async authenticate(req, res, next) {
    try {
      // Extract token from Authorization header
      const token = this.extractToken(req);

      if (!token) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'No authentication token provided',
        );
      }

      // Validate JWT token
      let decoded;
      try {
        decoded = validateToken(token, {
          requiredType: TOKEN_TYPES.ACCESS,
        });
      } catch (error) {
        if (error.message.includes('expired')) {
          return this.handleAuthError(
            res,
            AUTH_RESULTS.EXPIRED_TOKEN,
            'Token has expired',
          );
        }
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'Invalid authentication token',
        );
      }

      // Load user with workspace memberships
      const user = await this.loadUserWithContext(
        decoded.sub,
        decoded.workspace?.id,
      );

      if (!user) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.USER_NOT_FOUND,
          'User not found',
        );
      }

      if (!user.isActive) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.USER_INACTIVE,
          'User account is inactive',
        );
      }

      // Validate workspace access
      const membership = this.validateWorkspaceAccess(
        user,
        decoded.workspace?.id,
      );

      if (!membership) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.NO_WORKSPACE_ACCESS,
          'No access to workspace',
        );
      }

      // Attach user context to request
      req.user = user;
      req.workspace = membership.workspace;
      req.userRole = membership.role;
      req.tokenContext = {
        jti: decoded.jti,
        iat: decoded.iat,
        exp: decoded.exp,
        deviceId: decoded.deviceId,
      };

      // Update metrics
      this.authMetrics.successfulAuthentications++;

      // Log successful authentication
      this._logAuthEvent('AUTHENTICATION_SUCCESS', {
        userId: user.id,
        workspaceId: membership.workspace.id,
        role: membership.role,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
      });

      next();
    } catch (error) {
      console.error('Authentication middleware error:', error);
      this.authMetrics.failedAuthentications++;

      this._logAuthEvent('AUTHENTICATION_ERROR', {
        error: error.message,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
      });

      return this.handleAuthError(
        res,
        AUTH_RESULTS.INVALID_TOKEN,
        'Authentication failed',
      );
    }
  }

  /**
   * Optional authentication middleware
   * Loads user context if token is provided, but doesn't require it
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async optionalAuthenticate(req, res, next) {
    try {
      const token = this.extractToken(req);

      if (!token) {
        return next(); // No token, continue without authentication
      }

      // Try to authenticate, but don't fail if token is invalid
      try {
        const decoded = validateToken(token, {
          requiredType: TOKEN_TYPES.ACCESS,
        });

        const user = await this.loadUserWithContext(
          decoded.sub,
          decoded.workspace?.id,
        );

        if (user && user.isActive) {
          const membership = this.validateWorkspaceAccess(
            user,
            decoded.workspace?.id,
          );

          if (membership) {
            req.user = user;
            req.workspace = membership.workspace;
            req.userRole = membership.role;
            req.tokenContext = {
              jti: decoded.jti,
              iat: decoded.iat,
              exp: decoded.exp,
              deviceId: decoded.deviceId,
            };
          }
        }
      } catch (error) {
        // Ignore authentication errors in optional mode
      }

      next();
    } catch (error) {
      console.error('Optional authentication error:', error);
      next(); // Continue without authentication
    }
  }

  /**
   * Require specific role middleware
   * @param {string|Array} requiredRoles - Required role(s)
   * @returns {Function} Express middleware
   */
  requireRole(requiredRoles) {
    const roles = Array.isArray(requiredRoles)
      ? requiredRoles
      : [requiredRoles];

    return (req, res, next) => {
      if (!req.user) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'Authentication required',
        );
      }

      const userRole = req.userRole;
      const hasRequiredRole = roles.some((role) =>
        this.hasRole(userRole, role),
      );

      if (!hasRequiredRole) {
        this.authMetrics.permissionDenials++;

        this._logAuthEvent('PERMISSION_DENIED', {
          userId: req.user.id,
          userRole,
          requiredRoles: roles,
          workspaceId: req.workspace?.id,
          ip: req.ip,
          endpoint: req.originalUrl,
        });

        return this.handleAuthError(
          res,
          AUTH_RESULTS.INSUFFICIENT_PERMISSIONS,
          `Insufficient permissions. Required: ${roles.join(' or ')}`,
        );
      }

      next();
    };
  }

  /**
   * Require admin role middleware
   * @returns {Function} Express middleware
   */
  requireAdmin() {
    return this.requireRole(USER_ROLES.ADMIN);
  }

  /**
   * Require workspace access middleware
   * Validates that user has access to the workspace specified in the request
   * @returns {Function} Express middleware
   */
  requireWorkspaceAccess() {
    return (req, res, next) => {
      if (!req.user) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'Authentication required',
        );
      }

      if (!req.workspace) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.NO_WORKSPACE_ACCESS,
          'Workspace access required',
        );
      }

      // Additional workspace validation can be added here
      // For example, checking if workspace is active, not suspended, etc.

      next();
    };
  }

  /**
   * Require self or admin middleware
   * Allows access if user is accessing their own data or is an admin
   * @param {Function} getUserIdFromRequest - Function to extract user ID from request
   * @returns {Function} Express middleware
   */
  requireSelfOrAdmin(getUserIdFromRequest) {
    return (req, res, next) => {
      if (!req.user) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'Authentication required',
        );
      }

      const targetUserId = getUserIdFromRequest(req);
      const isAdmin = req.userRole === USER_ROLES.ADMIN;
      const isSelf = req.user.id === targetUserId;

      if (!isAdmin && !isSelf) {
        this.authMetrics.permissionDenials++;

        this._logAuthEvent('PERMISSION_DENIED', {
          userId: req.user.id,
          targetUserId,
          userRole: req.userRole,
          workspaceId: req.workspace?.id,
          ip: req.ip,
          endpoint: req.originalUrl,
          reason: 'Not self or admin',
        });

        return this.handleAuthError(
          res,
          AUTH_RESULTS.INSUFFICIENT_PERMISSIONS,
          'Access denied. Admin privileges or self-access required',
        );
      }

      next();
    };
  }

  /**
   * Token refresh middleware
   * Handles token refresh requests
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async refreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.INVALID_TOKEN,
          'Refresh token required',
        );
      }

      // Validate refresh token
      const decoded = validateToken(refreshToken, {
        requiredType: TOKEN_TYPES.REFRESH,
      });

      // Load user to ensure they still exist and are active
      const user = await this.loadUserWithContext(
        decoded.sub,
        decoded.workspace?.id,
      );

      if (!user || !user.isActive) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.USER_NOT_FOUND,
          'User not found or inactive',
        );
      }

      // Attach user context for token refresh
      req.user = user;
      req.refreshTokenPayload = decoded;

      this.authMetrics.tokenRefreshes++;

      this._logAuthEvent('TOKEN_REFRESH_ATTEMPT', {
        userId: user.id,
        workspaceId: decoded.workspace?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      next();
    } catch (error) {
      if (error.message.includes('expired')) {
        return this.handleAuthError(
          res,
          AUTH_RESULTS.EXPIRED_TOKEN,
          'Refresh token has expired',
        );
      }
      return this.handleAuthError(
        res,
        AUTH_RESULTS.INVALID_TOKEN,
        'Invalid refresh token',
      );
    }
  }

  /**
   * Logout middleware
   * Handles token revocation
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async logout(req, res, next) {
    try {
      const token = this.extractToken(req);

      if (token) {
        // Revoke the token
        revokeToken(token);

        // If refresh token is provided, revoke it too
        if (req.body.refreshToken) {
          revokeToken(req.body.refreshToken);
        }

        this._logAuthEvent('LOGOUT', {
          userId: req.user?.id,
          workspaceId: req.workspace?.id,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
        });
      }

      next();
    } catch (error) {
      console.error('Logout middleware error:', error);
      next(); // Continue with logout even if token revocation fails
    }
  }

  /**
   * Extract JWT token from request
   * @param {Object} req - Express request object
   * @returns {string|null} JWT token or null
   */
  extractToken(req) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  /**
   * Load user with workspace context
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<Object|null>} User object with memberships
   */
  async loadUserWithContext(userId, workspaceId) {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          memberships: {
            where: {
              isActive: true,
              ...(workspaceId && { workspaceId }),
            },
            include: {
              workspace: {
                select: {
                  id: true,
                  name: true,
                  domain: true,
                  isActive: true,
                },
              },
            },
          },
        },
      });

      return user;
    } catch (error) {
      console.error('Error loading user context:', error);
      return null;
    }
  }

  /**
   * Validate workspace access for user
   * @param {Object} user - User object
   * @param {string} workspaceId - Workspace ID
   * @returns {Object|null} Membership object or null
   */
  validateWorkspaceAccess(user, workspaceId) {
    if (!user.memberships || user.memberships.length === 0) {
      return null;
    }

    // If specific workspace ID is provided, find that membership
    if (workspaceId) {
      const membership = user.memberships.find(
        (m) => m.workspaceId === workspaceId,
      );
      return membership && membership.workspace.isActive ? membership : null;
    }

    // Otherwise, return the first active membership
    const activeMembership = user.memberships.find((m) => m.workspace.isActive);
    return activeMembership || null;
  }

  /**
   * Check if user has required role
   * @param {string} userRole - User's role
   * @param {string} requiredRole - Required role
   * @returns {boolean} Whether user has required role
   */
  hasRole(userRole, requiredRole) {
    const userLevel = ROLE_HIERARCHY[userRole] || 0;
    const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;

    return userLevel >= requiredLevel;
  }

  /**
   * Handle authentication errors
   * @param {Object} res - Express response object
   * @param {string} result - Authentication result
   * @param {string} message - Error message
   */
  handleAuthError(res, result, message) {
    const statusCode = this.getStatusCodeForResult(result);

    this.authMetrics.failedAuthentications++;

    res.status(statusCode).json({
      success: false,
      error: 'Authentication failed',
      message,
      code: result,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get HTTP status code for authentication result
   * @param {string} result - Authentication result
   * @returns {number} HTTP status code
   */
  getStatusCodeForResult(result) {
    const statusCodes = {
      [AUTH_RESULTS.INVALID_TOKEN]: 401,
      [AUTH_RESULTS.EXPIRED_TOKEN]: 401,
      [AUTH_RESULTS.USER_NOT_FOUND]: 401,
      [AUTH_RESULTS.USER_INACTIVE]: 401,
      [AUTH_RESULTS.NO_WORKSPACE_ACCESS]: 403,
      [AUTH_RESULTS.INSUFFICIENT_PERMISSIONS]: 403,
      [AUTH_RESULTS.TOKEN_REVOKED]: 401,
    };

    return statusCodes[result] || 401;
  }

  /**
   * Get authentication metrics
   * @returns {Object} Authentication metrics
   */
  getMetrics() {
    return {
      ...this.authMetrics,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log authentication events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logAuthEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'AUTH_MIDDLEWARE',
    };

    if (event.includes('DENIED') || event.includes('FAILED')) {
      console.warn('🔒 Auth Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('🔐 Auth Event:', logEntry);
    }

    // In production, send to security monitoring service
    if (config.isProduction()) {
      // TODO: Send to security monitoring service
    }
  }
}

// Create singleton instance
const authMiddleware = new AuthenticationMiddleware();

// Export authentication middleware functions
module.exports = {
  // Main authentication middleware
  authenticate: (req, res, next) => authMiddleware.authenticate(req, res, next),

  // Optional authentication
  optionalAuthenticate: (req, res, next) =>
    authMiddleware.optionalAuthenticate(req, res, next),

  // Role-based access control
  requireRole: (roles) => authMiddleware.requireRole(roles),
  requireAdmin: () => authMiddleware.requireAdmin(),
  requireWorkspaceAccess: () => authMiddleware.requireWorkspaceAccess(),
  requireSelfOrAdmin: (getUserIdFromRequest) =>
    authMiddleware.requireSelfOrAdmin(getUserIdFromRequest),

  // Token management
  refreshToken: (req, res, next) => authMiddleware.refreshToken(req, res, next),
  logout: (req, res, next) => authMiddleware.logout(req, res, next),

  // Utilities
  extractToken: (req) => authMiddleware.extractToken(req),
  hasRole: (userRole, requiredRole) =>
    authMiddleware.hasRole(userRole, requiredRole),

  // Monitoring
  getMetrics: () => authMiddleware.getMetrics(),

  // Constants
  AUTH_RESULTS,
  USER_ROLES,
  ROLE_HIERARCHY,

  // Middleware instance
  authMiddleware,
};
