/**
 * User Controller Module
 *
 * This controller provides REST API endpoints for user management operations
 * in multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - User profile management and updates
 * - Password change functionality
 * - User search and directory within workspaces
 * - Account activation/deactivation
 * - User preferences management
 * - Role-based access control
 * - Comprehensive error handling and validation
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  userService,
  getUserProfile,
  updateUserProfile,
  changeUserPassword,
  searchUsers,
  deactivateUser,
  reactivateUser,
  getUserPreferences,
  updateUserPreferences,
  validateWorkspaceAccess,
  canUpdateUserProfile,
  canManageUser,
  USER_RESULTS,
} = require('../services/userService');
const { emailService } = require('../services/emailService');
const config = require('../config');

/**
 * HTTP Status Code Mappings for User Results
 */
const HTTP_STATUS_CODES = {
  [USER_RESULTS.SUCCESS]: 200,
  [USER_RESULTS.USER_NOT_FOUND]: 404,
  [USER_RESULTS.INVALID_PERMISSIONS]: 403,
  [USER_RESULTS.EMAIL_ALREADY_EXISTS]: 409,
  [USER_RESULTS.INVALID_PASSWORD]: 400,
  [USER_RESULTS.ACCOUNT_INACTIVE]: 403,
  [USER_RESULTS.WORKSPACE_ACCESS_DENIED]: 403,
  [USER_RESULTS.VALIDATION_ERROR]: 400,
  [USER_RESULTS.OPERATION_FAILED]: 500,
};

/**
 * User Controller Class
 * Handles all user management HTTP endpoints
 */
class UserController {
  /**
   * Get user profile
   * GET /api/v1/users/:userId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getUserProfile(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;
      const { include_activity, include_preferences } = req.query;

      // Validate user can access this profile
      const canAccess = await canUpdateUserProfile(
        req.user.id,
        userId,
        workspaceId,
      );
      if (!canAccess && req.user.id !== userId) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to view this profile',
        });
      }

      // Get user profile
      const result = await getUserProfile(userId, workspaceId, {
        includeActivity: include_activity === 'true',
        includePreferences: include_preferences === 'true',
      });

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log profile access
      this._logControllerEvent('PROFILE_VIEW', {
        targetUserId: userId,
        requestingUserId: req.user.id,
        workspaceId,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Get user profile controller error:', error);

      this._logControllerEvent('PROFILE_VIEW_ERROR', {
        error: error.message,
        targetUserId: req.params.userId,
        requestingUserId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user profile',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Update user profile
   * PUT /api/v1/users/:userId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async updateUserProfile(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;
      const { name, email, preferences } = req.body;

      // Update user profile
      const result = await updateUserProfile(
        userId,
        workspaceId,
        {
          name,
          email,
          preferences,
        },
        {
          requestingUserId: req.user.id,
          ipAddress: req.ip,
        },
      );

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log profile update
      this._logControllerEvent('PROFILE_UPDATE', {
        targetUserId: userId,
        requestingUserId: req.user.id,
        workspaceId,
        success: result.success,
        changes: result.data?.changes || [],
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Update user profile controller error:', error);

      this._logControllerEvent('PROFILE_UPDATE_ERROR', {
        error: error.message,
        targetUserId: req.params.userId,
        requestingUserId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to update user profile',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Change user password
   * PUT /api/v1/users/:userId/password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async changePassword(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;
      const { currentPassword, newPassword } = req.body;

      // Validate required fields
      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          message: 'Current password and new password are required',
        });
      }

      // Users can only change their own password
      if (req.user.id !== userId) {
        return res.status(403).json({
          success: false,
          message: 'You can only change your own password',
        });
      }

      // Change password
      const result = await changeUserPassword(
        userId,
        workspaceId,
        {
          currentPassword,
          newPassword,
        },
        {
          ipAddress: req.ip,
        },
      );

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log password change
      this._logControllerEvent('PASSWORD_CHANGE', {
        userId,
        workspaceId,
        success: result.success,
        result: result.result,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Change password controller error:', error);

      this._logControllerEvent('PASSWORD_CHANGE_ERROR', {
        error: error.message,
        userId: req.params.userId,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to change password',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Search users in workspace
   * GET /api/v1/users/search
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async searchUsers(req, res) {
    try {
      const { workspaceId } = req;
      const {
        q: query = '',
        role,
        is_active,
        page = 1,
        limit = 20,
        sort_by = 'name',
        sort_order = 'asc',
      } = req.query;

      // Parse query parameters
      const searchParams = {
        query,
        role,
        isActive: is_active !== undefined ? is_active === 'true' : true,
        page: parseInt(page),
        limit: Math.min(parseInt(limit), 100), // Cap at 100
        sortBy: sort_by,
        sortOrder: sort_order,
      };

      // Search users
      const result = await searchUsers(workspaceId, searchParams, {
        requestingUserId: req.user.id,
      });

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log user search
      this._logControllerEvent('USER_SEARCH', {
        requestingUserId: req.user.id,
        workspaceId,
        searchParams,
        success: result.success,
        resultCount: result.data?.users?.length || 0,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Search users controller error:', error);

      this._logControllerEvent('USER_SEARCH_ERROR', {
        error: error.message,
        requestingUserId: req.user?.id,
        workspaceId: req.workspaceId,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to search users',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Deactivate user account
   * DELETE /api/v1/users/:userId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async deactivateUser(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;
      const { reason } = req.body;

      // Deactivate user
      const result = await deactivateUser(userId, workspaceId, {
        requestingUserId: req.user.id,
        reason: reason || 'No reason provided',
        ipAddress: req.ip,
      });

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log user deactivation
      this._logControllerEvent('USER_DEACTIVATION', {
        targetUserId: userId,
        requestingUserId: req.user.id,
        workspaceId,
        reason,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Deactivate user controller error:', error);

      this._logControllerEvent('USER_DEACTIVATION_ERROR', {
        error: error.message,
        targetUserId: req.params.userId,
        requestingUserId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to deactivate user',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Reactivate user account
   * POST /api/v1/users/:userId/reactivate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async reactivateUser(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;

      // Reactivate user
      const result = await reactivateUser(userId, workspaceId, {
        requestingUserId: req.user.id,
        ipAddress: req.ip,
      });

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log user reactivation
      this._logControllerEvent('USER_REACTIVATION', {
        targetUserId: userId,
        requestingUserId: req.user.id,
        workspaceId,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Reactivate user controller error:', error);

      this._logControllerEvent('USER_REACTIVATION_ERROR', {
        error: error.message,
        targetUserId: req.params.userId,
        requestingUserId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to reactivate user',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Get user preferences
   * GET /api/v1/users/:userId/preferences
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getUserPreferences(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;

      // Validate user can access preferences
      if (req.user.id !== userId) {
        const canAccess = await canUpdateUserProfile(
          req.user.id,
          userId,
          workspaceId,
        );
        if (!canAccess) {
          return res.status(403).json({
            success: false,
            message: 'Insufficient permissions to view user preferences',
          });
        }
      }

      // Get user preferences
      const preferences = await getUserPreferences(userId, workspaceId);

      // Log preferences access
      this._logControllerEvent('PREFERENCES_VIEW', {
        targetUserId: userId,
        requestingUserId: req.user.id,
        workspaceId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(200).json({
        success: true,
        message: 'User preferences retrieved successfully',
        data: { preferences },
      });
    } catch (error) {
      console.error('Get user preferences controller error:', error);

      this._logControllerEvent('PREFERENCES_VIEW_ERROR', {
        error: error.message,
        targetUserId: req.params.userId,
        requestingUserId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user preferences',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Update user preferences
   * PUT /api/v1/users/:userId/preferences
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async updateUserPreferences(req, res) {
    try {
      const { userId } = req.params;
      const { workspaceId } = req;
      const preferences = req.body;

      // Users can only update their own preferences
      if (req.user.id !== userId) {
        return res.status(403).json({
          success: false,
          message: 'You can only update your own preferences',
        });
      }

      // Update user preferences
      const result = await updateUserPreferences(
        userId,
        workspaceId,
        preferences,
      );

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log preferences update
      this._logControllerEvent('PREFERENCES_UPDATE', {
        userId,
        workspaceId,
        preferences: Object.keys(preferences),
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Update user preferences controller error:', error);

      this._logControllerEvent('PREFERENCES_UPDATE_ERROR', {
        error: error.message,
        userId: req.params.userId,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to update user preferences',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Get current user profile (convenience endpoint)
   * GET /api/v1/users/me
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getCurrentUserProfile(req, res) {
    try {
      const { workspaceId } = req;
      const { include_activity, include_preferences } = req.query;

      // Get current user profile
      const result = await getUserProfile(req.user.id, workspaceId, {
        includeActivity: include_activity === 'true',
        includePreferences: include_preferences === 'true',
      });

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log profile access
      this._logControllerEvent('CURRENT_USER_PROFILE_VIEW', {
        userId: req.user.id,
        workspaceId,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Get current user profile controller error:', error);

      this._logControllerEvent('CURRENT_USER_PROFILE_VIEW_ERROR', {
        error: error.message,
        userId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve current user profile',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Update current user profile (convenience endpoint)
   * PUT /api/v1/users/me
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async updateCurrentUserProfile(req, res) {
    try {
      const { workspaceId } = req;
      const { name, email, preferences } = req.body;

      // Update current user profile
      const result = await updateUserProfile(
        req.user.id,
        workspaceId,
        {
          name,
          email,
          preferences,
        },
        {
          requestingUserId: req.user.id,
          ipAddress: req.ip,
        },
      );

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 500;

      // Log profile update
      this._logControllerEvent('CURRENT_USER_PROFILE_UPDATE', {
        userId: req.user.id,
        workspaceId,
        success: result.success,
        changes: result.data?.changes || [],
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Update current user profile controller error:', error);

      this._logControllerEvent('CURRENT_USER_PROFILE_UPDATE_ERROR', {
        error: error.message,
        userId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to update current user profile',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Get user service metrics (admin only)
   * GET /api/v1/users/metrics
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getUserMetrics(req, res) {
    try {
      // Get metrics from user service
      const metrics = userService.getMetrics();

      // Log metrics access
      this._logControllerEvent('USER_METRICS_ACCESS', {
        userId: req.user?.id,
        workspaceId: req.workspaceId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(200).json({
        success: true,
        message: 'User metrics retrieved successfully',
        data: metrics,
      });
    } catch (error) {
      console.error('Get user metrics controller error:', error);

      this._logControllerEvent('USER_METRICS_ACCESS_ERROR', {
        error: error.message,
        userId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user metrics',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Log controller events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logControllerEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'USER_CONTROLLER',
    };

    if (event.includes('ERROR') || event.includes('FAILED')) {
      console.warn('👤 User Controller Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('👤 User Controller Event:', logEntry);
    }

    // In production, send to monitoring service
    if (config.isProduction()) {
      // TODO: Send to monitoring service
    }
  }
}

// Create controller instance
const userController = new UserController();

// Export controller methods
module.exports = {
  // User profile endpoints
  getUserProfile: (req, res) => userController.getUserProfile(req, res),
  updateUserProfile: (req, res) => userController.updateUserProfile(req, res),
  getCurrentUserProfile: (req, res) =>
    userController.getCurrentUserProfile(req, res),
  updateCurrentUserProfile: (req, res) =>
    userController.updateCurrentUserProfile(req, res),

  // Password management
  changePassword: (req, res) => userController.changePassword(req, res),

  // User search and management
  searchUsers: (req, res) => userController.searchUsers(req, res),
  deactivateUser: (req, res) => userController.deactivateUser(req, res),
  reactivateUser: (req, res) => userController.reactivateUser(req, res),

  // User preferences
  getUserPreferences: (req, res) => userController.getUserPreferences(req, res),
  updateUserPreferences: (req, res) =>
    userController.updateUserPreferences(req, res),

  // Admin endpoints
  getUserMetrics: (req, res) => userController.getUserMetrics(req, res),

  // Controller instance
  userController,
};
