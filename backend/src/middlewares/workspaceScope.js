/**
 * Workspace Scoping Middleware Module
 *
 * This module provides comprehensive workspace-based data isolation for
 * multi-tenant SaaS applications with enterprise security requirements:
 *
 * Features:
 * - Automatic workspace scoping for all database operations
 * - Request-level workspace context management
 * - Data isolation enforcement and validation
 * - Workspace access control and permissions
 * - Cross-workspace operation prevention
 * - Comprehensive audit logging for compliance
 * - Performance optimization for scoped queries
 *
 * @author AI-Persona Backend Team
 * @version 1.0.0
 */

const { client: prisma } = require('../config/database');
const config = require('../config');

/**
 * Workspace Scoping Results
 */
const SCOPING_RESULTS = {
  SUCCESS: 'success',
  NO_WORKSPACE_CONTEXT: 'no_workspace_context',
  INVALID_WORKSPACE: 'invalid_workspace',
  WORKSPACE_INACTIVE: 'workspace_inactive',
  ACCESS_DENIED: 'access_denied',
  CROSS_WORKSPACE_VIOLATION: 'cross_workspace_violation',
};

/**
 * Workspace Operation Types
 */
const WORKSPACE_OPERATIONS = {
  READ: 'read',
  WRITE: 'write',
  DELETE: 'delete',
  ADMIN: 'admin',
};

/**
 * Workspace Scoping Manager Class
 * Handles all workspace scoping logic and data isolation
 */
class WorkspaceScopingManager {
  constructor() {
    this.scopingMetrics = {
      totalRequests: 0,
      scopedRequests: 0,
      crossWorkspaceAttempts: 0,
      accessDenials: 0,
      isolationViolations: 0,
    };

    this.workspaceCache = new Map();
    this.maxCacheSize = 1000;
  }

  /**
   * Main workspace scoping middleware
   * Ensures all operations are scoped to the user's workspace
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async enforceWorkspaceScope(req, res, next) {
    try {
      this.scopingMetrics.totalRequests++;

      // Skip scoping for public endpoints
      if (this.isPublicEndpoint(req)) {
        return next();
      }

      // Require authentication for workspace-scoped operations
      if (!req.user || !req.workspace) {
        return this.handleScopingError(
          res,
          SCOPING_RESULTS.NO_WORKSPACE_CONTEXT,
          'Workspace context required for this operation',
        );
      }

      // Validate workspace access
      const workspaceValidation = await this.validateWorkspaceAccess(
        req.user,
        req.workspace,
      );

      if (!workspaceValidation.valid) {
        return this.handleScopingError(
          res,
          workspaceValidation.result,
          workspaceValidation.message,
        );
      }

      // Set up workspace scoping context
      this.setupWorkspaceContext(req);

      // Validate operation permissions
      const operationType = this.determineOperationType(req);
      const hasPermission = this.checkWorkspacePermission(
        req.userRole,
        operationType,
      );

      if (!hasPermission) {
        this.scopingMetrics.accessDenials++;
        return this.handleScopingError(
          res,
          SCOPING_RESULTS.ACCESS_DENIED,
          `Insufficient permissions for ${operationType} operation`,
        );
      }

      this.scopingMetrics.scopedRequests++;

      // Log workspace operation
      this._logWorkspaceEvent('WORKSPACE_OPERATION', {
        userId: req.user.id,
        workspaceId: req.workspace.id,
        operation: operationType,
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      next();
    } catch (error) {
      console.error('Workspace scoping error:', error);
      this.scopingMetrics.isolationViolations++;

      this._logWorkspaceEvent('SCOPING_ERROR', {
        error: error.message,
        userId: req.user?.id,
        workspaceId: req.workspace?.id,
        endpoint: req.originalUrl,
        ip: req.ip,
      });

      return this.handleScopingError(
        res,
        SCOPING_RESULTS.INVALID_WORKSPACE,
        'Workspace scoping failed',
      );
    }
  }

  /**
   * Validate workspace parameters in request
   * Ensures workspace IDs in URL/body match authenticated workspace
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async validateWorkspaceParameters(req, res, next) {
    try {
      const userWorkspaceId = req.workspace?.id;

      if (!userWorkspaceId) {
        return this.handleScopingError(
          res,
          SCOPING_RESULTS.NO_WORKSPACE_CONTEXT,
          'Workspace context required',
        );
      }

      // Check workspace ID in URL parameters
      const urlWorkspaceId = req.params.workspaceId;
      if (urlWorkspaceId && urlWorkspaceId !== userWorkspaceId) {
        this.scopingMetrics.crossWorkspaceAttempts++;

        this._logWorkspaceEvent('CROSS_WORKSPACE_ATTEMPT', {
          userId: req.user.id,
          userWorkspaceId,
          requestedWorkspaceId: urlWorkspaceId,
          endpoint: req.originalUrl,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
        });

        return this.handleScopingError(
          res,
          SCOPING_RESULTS.CROSS_WORKSPACE_VIOLATION,
          'Cross-workspace access denied',
        );
      }

      // Check workspace ID in request body
      const bodyWorkspaceId = req.body?.workspaceId;
      if (bodyWorkspaceId && bodyWorkspaceId !== userWorkspaceId) {
        this.scopingMetrics.crossWorkspaceAttempts++;

        this._logWorkspaceEvent('CROSS_WORKSPACE_ATTEMPT', {
          userId: req.user.id,
          userWorkspaceId,
          requestedWorkspaceId: bodyWorkspaceId,
          endpoint: req.originalUrl,
          ip: req.ip,
          method: req.method,
        });

        return this.handleScopingError(
          res,
          SCOPING_RESULTS.CROSS_WORKSPACE_VIOLATION,
          'Cross-workspace data modification denied',
        );
      }

      next();
    } catch (error) {
      console.error('Workspace parameter validation error:', error);
      return this.handleScopingError(
        res,
        SCOPING_RESULTS.INVALID_WORKSPACE,
        'Workspace parameter validation failed',
      );
    }
  }

  /**
   * Create scoped database client
   * Returns a database client that automatically scopes all queries
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async createScopedClient(req, res, next) {
    try {
      if (!req.workspace?.id) {
        return this.handleScopingError(
          res,
          SCOPING_RESULTS.NO_WORKSPACE_CONTEXT,
          'Workspace context required for database operations',
        );
      }

      // Create scoped database client
      req.scopedPrisma = this.createWorkspaceScopedPrisma(req.workspace.id);

      next();
    } catch (error) {
      console.error('Scoped client creation error:', error);
      return this.handleScopingError(
        res,
        SCOPING_RESULTS.INVALID_WORKSPACE,
        'Failed to create scoped database client',
      );
    }
  }

  /**
   * Workspace admin access middleware
   * Requires admin role within the workspace
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async requireWorkspaceAdmin(req, res, next) {
    try {
      if (!req.user || !req.workspace) {
        return this.handleScopingError(
          res,
          SCOPING_RESULTS.NO_WORKSPACE_CONTEXT,
          'Workspace context required',
        );
      }

      if (req.userRole !== 'ADMIN') {
        this.scopingMetrics.accessDenials++;

        this._logWorkspaceEvent('ADMIN_ACCESS_DENIED', {
          userId: req.user.id,
          workspaceId: req.workspace.id,
          userRole: req.userRole,
          endpoint: req.originalUrl,
          ip: req.ip,
        });

        return this.handleScopingError(
          res,
          SCOPING_RESULTS.ACCESS_DENIED,
          'Workspace admin privileges required',
        );
      }

      next();
    } catch (error) {
      console.error('Workspace admin check error:', error);
      return this.handleScopingError(
        res,
        SCOPING_RESULTS.ACCESS_DENIED,
        'Admin access validation failed',
      );
    }
  }

  /**
   * Validate workspace access for user
   * @param {Object} user - User object
   * @param {Object} workspace - Workspace object
   * @returns {Promise<Object>} Validation result
   */
  async validateWorkspaceAccess(user, workspace) {
    try {
      // Check if workspace is cached
      const cacheKey = `${user.id}:${workspace.id}`;
      const cached = this.workspaceCache.get(cacheKey);

      if (cached && Date.now() - cached.timestamp < 300000) {
        // 5 minutes cache
        return cached.result;
      }

      // Validate workspace exists and is active
      const workspaceRecord = await prisma.workspace.findUnique({
        where: { id: workspace.id },
        select: { id: true, isActive: true },
      });

      if (!workspaceRecord) {
        const result = {
          valid: false,
          result: SCOPING_RESULTS.INVALID_WORKSPACE,
          message: 'Workspace not found',
        };
        this.cacheValidationResult(cacheKey, result);
        return result;
      }

      if (!workspaceRecord.isActive) {
        const result = {
          valid: false,
          result: SCOPING_RESULTS.WORKSPACE_INACTIVE,
          message: 'Workspace is inactive',
        };
        this.cacheValidationResult(cacheKey, result);
        return result;
      }

      // Validate user membership
      const membership = await prisma.membership.findFirst({
        where: {
          userId: user.id,
          workspaceId: workspace.id,
          isActive: true,
        },
      });

      if (!membership) {
        const result = {
          valid: false,
          result: SCOPING_RESULTS.ACCESS_DENIED,
          message: 'No active membership in workspace',
        };
        this.cacheValidationResult(cacheKey, result);
        return result;
      }

      const result = {
        valid: true,
        result: SCOPING_RESULTS.SUCCESS,
        message: 'Workspace access validated',
        membership,
      };

      this.cacheValidationResult(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Workspace access validation error:', error);
      return {
        valid: false,
        result: SCOPING_RESULTS.INVALID_WORKSPACE,
        message: 'Workspace validation failed',
      };
    }
  }

  /**
   * Set up workspace context for request
   * @param {Object} req - Express request object
   */
  setupWorkspaceContext(req) {
    // Add workspace scoping helpers to request
    req.workspaceId = req.workspace.id;
    req.workspaceDomain = req.workspace.domain;

    // Add scoping utilities
    req.scopeToWorkspace = (query) => {
      return {
        ...query,
        where: {
          ...query.where,
          workspaceId: req.workspace.id,
        },
      };
    };

    // Add workspace filter helper
    req.addWorkspaceFilter = (filters = {}) => {
      return {
        ...filters,
        workspaceId: req.workspace.id,
      };
    };
  }

  /**
   * Create workspace-scoped Prisma client
   * @param {string} workspaceId - Workspace ID
   * @returns {Object} Scoped Prisma client
   */
  createWorkspaceScopedPrisma(workspaceId) {
    // Create a proxy that automatically adds workspace scoping
    return new Proxy(prisma, {
      get(target, prop) {
        const originalMethod = target[prop];

        if (typeof originalMethod === 'object' && originalMethod !== null) {
          // Handle model methods (e.g., prisma.user.findMany)
          return new Proxy(originalMethod, {
            get(modelTarget, modelProp) {
              const modelMethod = modelTarget[modelProp];

              if (typeof modelMethod === 'function') {
                return function (...args) {
                  // Automatically add workspace scoping to queries
                  if (args[0] && typeof args[0] === 'object') {
                    args[0] = {
                      ...args[0],
                      where: {
                        ...args[0].where,
                        workspaceId,
                      },
                    };
                  }

                  return modelMethod.apply(modelTarget, args);
                };
              }

              return modelMethod;
            },
          });
        }

        return originalMethod;
      },
    });
  }

  /**
   * Determine operation type from request
   * @param {Object} req - Express request object
   * @returns {string} Operation type
   */
  determineOperationType(req) {
    const method = req.method.toLowerCase();
    const path = req.originalUrl.toLowerCase();

    // Admin operations
    if (path.includes('/admin/') || path.includes('/settings/')) {
      return WORKSPACE_OPERATIONS.ADMIN;
    }

    // Write operations
    if (['post', 'put', 'patch'].includes(method)) {
      return WORKSPACE_OPERATIONS.WRITE;
    }

    // Delete operations
    if (method === 'delete') {
      return WORKSPACE_OPERATIONS.DELETE;
    }

    // Default to read
    return WORKSPACE_OPERATIONS.READ;
  }

  /**
   * Check workspace permission for operation
   * @param {string} userRole - User role
   * @param {string} operationType - Operation type
   * @returns {boolean} Whether user has permission
   */
  checkWorkspacePermission(userRole, operationType) {
    const permissions = {
      ADMIN: [
        WORKSPACE_OPERATIONS.READ,
        WORKSPACE_OPERATIONS.WRITE,
        WORKSPACE_OPERATIONS.DELETE,
        WORKSPACE_OPERATIONS.ADMIN,
      ],
      MEMBER: [WORKSPACE_OPERATIONS.READ, WORKSPACE_OPERATIONS.WRITE],
    };

    return permissions[userRole]?.includes(operationType) || false;
  }

  /**
   * Check if endpoint is public (no workspace scoping required)
   * @param {Object} req - Express request object
   * @returns {boolean} Whether endpoint is public
   */
  isPublicEndpoint(req) {
    const publicPaths = [
      '/api/v1/health',
      '/api/v1/auth/login',
      '/api/v1/auth/signup',
      '/api/v1/auth/refresh',
      '/api/v1/auth/google',
      '/api/v1/auth/microsoft',
      '/api/v1/security/csp-report',
      '/api/v1/metrics',
    ];

    return publicPaths.some((path) => req.originalUrl.startsWith(path));
  }

  /**
   * Cache workspace validation result
   * @param {string} cacheKey - Cache key
   * @param {Object} result - Validation result
   */
  cacheValidationResult(cacheKey, result) {
    // Implement cache size limit
    if (this.workspaceCache.size >= this.maxCacheSize) {
      const firstKey = this.workspaceCache.keys().next().value;
      this.workspaceCache.delete(firstKey);
    }

    this.workspaceCache.set(cacheKey, {
      result,
      timestamp: Date.now(),
    });
  }

  /**
   * Handle workspace scoping errors
   * @param {Object} res - Express response object
   * @param {string} result - Scoping result
   * @param {string} message - Error message
   */
  handleScopingError(res, result, message) {
    const statusCode = this.getStatusCodeForResult(result);

    res.status(statusCode).json({
      success: false,
      error: 'Workspace access denied',
      message,
      code: result,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Get HTTP status code for scoping result
   * @param {string} result - Scoping result
   * @returns {number} HTTP status code
   */
  getStatusCodeForResult(result) {
    const statusCodes = {
      [SCOPING_RESULTS.NO_WORKSPACE_CONTEXT]: 401,
      [SCOPING_RESULTS.INVALID_WORKSPACE]: 403,
      [SCOPING_RESULTS.WORKSPACE_INACTIVE]: 403,
      [SCOPING_RESULTS.ACCESS_DENIED]: 403,
      [SCOPING_RESULTS.CROSS_WORKSPACE_VIOLATION]: 403,
    };

    return statusCodes[result] || 403;
  }

  /**
   * Get workspace scoping metrics
   * @returns {Object} Scoping metrics
   */
  getMetrics() {
    return {
      ...this.scopingMetrics,
      cacheSize: this.workspaceCache.size,
      cacheHitRate:
        this.scopingMetrics.totalRequests > 0
          ? (this.scopingMetrics.scopedRequests /
              this.scopingMetrics.totalRequests) *
            100
          : 0,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Clear workspace cache
   */
  clearCache() {
    this.workspaceCache.clear();
    this._logWorkspaceEvent('CACHE_CLEARED', {
      reason: 'Manual cache clear',
    });
  }

  /**
   * Log workspace events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logWorkspaceEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'WORKSPACE_SCOPING',
    };

    if (
      event.includes('VIOLATION') ||
      event.includes('DENIED') ||
      event.includes('ERROR')
    ) {
      console.warn('🏢 Workspace Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('🏢 Workspace Event:', logEntry);
    }

    // In production, send to security monitoring service
    if (config.isProduction()) {
      // TODO: Send to security monitoring service
    }
  }
}

// Create singleton instance
const workspaceScopingManager = new WorkspaceScopingManager();

// Export workspace scoping middleware functions
module.exports = {
  // Main scoping middleware
  enforceWorkspaceScope: (req, res, next) =>
    workspaceScopingManager.enforceWorkspaceScope(req, res, next),

  // Parameter validation
  validateWorkspaceParameters: (req, res, next) =>
    workspaceScopingManager.validateWorkspaceParameters(req, res, next),

  // Scoped database client
  createScopedClient: (req, res, next) =>
    workspaceScopingManager.createScopedClient(req, res, next),

  // Admin access control
  requireWorkspaceAdmin: (req, res, next) =>
    workspaceScopingManager.requireWorkspaceAdmin(req, res, next),

  // Utilities
  validateWorkspaceAccess: (user, workspace) =>
    workspaceScopingManager.validateWorkspaceAccess(user, workspace),

  setupWorkspaceContext: (req) =>
    workspaceScopingManager.setupWorkspaceContext(req),

  createWorkspaceScopedPrisma: (workspaceId) =>
    workspaceScopingManager.createWorkspaceScopedPrisma(workspaceId),

  // Cache management
  clearCache: () => workspaceScopingManager.clearCache(),

  // Monitoring
  getMetrics: () => workspaceScopingManager.getMetrics(),

  // Constants
  SCOPING_RESULTS,
  WORKSPACE_OPERATIONS,

  // Manager instance
  workspaceScopingManager,
};
