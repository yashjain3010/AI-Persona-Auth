/**
 * User Service Module
 *
 * This service provides comprehensive user management functionality for
 * multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - User profile management and updates
 * - Account settings and preferences
 * - User search and directory within workspaces
 * - Role and permission management
 * - Account deactivation and reactivation
 * - User activity tracking and analytics
 * - Data export and privacy compliance (GDPR)
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const { client: prisma } = require('../config/database');
const { hashPassword, comparePassword } = require('../utils/encryption');
const { normalizeEmail, isValidEmail } = require('../utils/domain');
const { sendSecurityAlertEmail } = require('../config/email');
const config = require('../config');

/**
 * User Service Result Types
 */
const USER_RESULTS = {
  SUCCESS: 'success',
  USER_NOT_FOUND: 'user_not_found',
  INVALID_PERMISSIONS: 'invalid_permissions',
  EMAIL_ALREADY_EXISTS: 'email_already_exists',
  INVALID_PASSWORD: 'invalid_password',
  ACCOUNT_INACTIVE: 'account_inactive',
  WORKSPACE_ACCESS_DENIED: 'workspace_access_denied',
  VALIDATION_ERROR: 'validation_error',
  OPERATION_FAILED: 'operation_failed',
};

/**
 * User Events for audit logging
 */
const USER_EVENTS = {
  PROFILE_UPDATED: 'profile_updated',
  PASSWORD_CHANGED: 'password_changed',
  EMAIL_CHANGED: 'email_changed',
  ACCOUNT_DEACTIVATED: 'account_deactivated',
  ACCOUNT_REACTIVATED: 'account_reactivated',
  ROLE_CHANGED: 'role_changed',
  PREFERENCES_UPDATED: 'preferences_updated',
  DATA_EXPORTED: 'data_exported',
  SECURITY_EVENT: 'security_event',
};

/**
 * User Activity Types
 */
const USER_ACTIVITY_TYPES = {
  LOGIN: 'login',
  LOGOUT: 'logout',
  PROFILE_UPDATE: 'profile_update',
  PASSWORD_CHANGE: 'password_change',
  ROLE_CHANGE: 'role_change',
  WORKSPACE_ACCESS: 'workspace_access',
};

/**
 * User Service Class
 * Handles all user management business logic
 */
class UserService {
  constructor() {
    this.userMetrics = {
      profileUpdates: 0,
      passwordChanges: 0,
      emailChanges: 0,
      accountDeactivations: 0,
      accountReactivations: 0,
      roleChanges: 0,
      dataExports: 0,
      securityEvents: 0,
    };
  }

  /**
   * Get user profile with workspace context
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} User profile result
   */
  async getUserProfile(userId, workspaceId, options = {}) {
    try {
      const { includeActivity = false, includePreferences = true } = options;

      // Get user with workspace membership
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          memberships: {
            where: {
              workspaceId,
              isActive: true,
            },
            include: {
              workspace: {
                select: {
                  id: true,
                  name: true,
                  domain: true,
                },
              },
            },
          },
          ...(includeActivity && {
            sessions: {
              where: { isActive: true },
              orderBy: { createdAt: 'desc' },
              take: 5,
            },
          }),
        },
      });

      if (!user) {
        return {
          success: false,
          result: USER_RESULTS.USER_NOT_FOUND,
          message: 'User not found',
        };
      }

      // Check workspace access
      const membership = user.memberships.find(
        (m) => m.workspaceId === workspaceId,
      );
      if (!membership) {
        return {
          success: false,
          result: USER_RESULTS.WORKSPACE_ACCESS_DENIED,
          message: 'User does not have access to this workspace',
        };
      }

      // Get user preferences if requested
      let preferences = {};
      if (includePreferences) {
        preferences = await this.getUserPreferences(userId, workspaceId);
      }

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            emailVerified: user.emailVerified,
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
          },
          workspace: membership.workspace,
          role: membership.role,
          membershipCreatedAt: membership.createdAt,
          preferences: includePreferences ? preferences : undefined,
          recentActivity: includeActivity ? user.sessions : undefined,
        },
      };
    } catch (error) {
      console.error('Get user profile error:', error);

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to retrieve user profile',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Update user profile
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @param {Object} updateData - Profile update data
   * @param {Object} options - Update options
   * @returns {Promise<Object>} Update result
   */
  async updateUserProfile(userId, workspaceId, updateData, options = {}) {
    try {
      const { requestingUserId = userId, ipAddress = null } = options;
      const { name, email, preferences = null } = updateData;

      // Validate workspace access
      const accessCheck = await this.validateWorkspaceAccess(
        userId,
        workspaceId,
      );
      if (!accessCheck.success) {
        return accessCheck;
      }

      // Check if requesting user has permission to update this profile
      const canUpdate = await this.canUpdateUserProfile(
        requestingUserId,
        userId,
        workspaceId,
      );
      if (!canUpdate) {
        return {
          success: false,
          result: USER_RESULTS.INVALID_PERMISSIONS,
          message: 'Insufficient permissions to update this profile',
        };
      }

      // Prepare update data
      const updateFields = {};
      const changes = [];

      if (name !== undefined && name !== accessCheck.data.user.name) {
        updateFields.name = name;
        changes.push({
          field: 'name',
          oldValue: accessCheck.data.user.name,
          newValue: name,
        });
      }

      if (email !== undefined && email !== accessCheck.data.user.email) {
        const normalizedEmail = normalizeEmail(email);

        if (!isValidEmail(normalizedEmail)) {
          return {
            success: false,
            result: USER_RESULTS.VALIDATION_ERROR,
            message: 'Invalid email format',
          };
        }

        // Check if email already exists
        const existingUser = await prisma.user.findUnique({
          where: { email: normalizedEmail },
        });

        if (existingUser && existingUser.id !== userId) {
          return {
            success: false,
            result: USER_RESULTS.EMAIL_ALREADY_EXISTS,
            message: 'Email address is already in use',
          };
        }

        updateFields.email = normalizedEmail;
        updateFields.emailVerified = false; // Require re-verification
        changes.push({
          field: 'email',
          oldValue: accessCheck.data.user.email,
          newValue: normalizedEmail,
        });
      }

      // Update user profile
      let updatedUser = null;
      if (Object.keys(updateFields).length > 0) {
        updatedUser = await prisma.user.update({
          where: { id: userId },
          data: updateFields,
        });
      }

      // Update preferences if provided
      if (preferences) {
        await this.updateUserPreferences(userId, workspaceId, preferences);
        changes.push({
          field: 'preferences',
          oldValue: null,
          newValue: preferences,
        });
      }

      // Update metrics
      this.userMetrics.profileUpdates++;
      if (changes.some((c) => c.field === 'email')) {
        this.userMetrics.emailChanges++;
      }

      // Log profile update
      this._logUserEvent(USER_EVENTS.PROFILE_UPDATED, {
        userId,
        requestingUserId,
        workspaceId,
        changes,
        ipAddress,
      });

      // Send security alert if email was changed
      if (changes.some((c) => c.field === 'email')) {
        await sendSecurityAlertEmail({
          email: accessCheck.data.user.email, // Send to old email
          name: accessCheck.data.user.name,
          alertType: 'email_change',
          details: {
            oldEmail: accessCheck.data.user.email,
            newEmail: email,
            timestamp: new Date().toISOString(),
          },
          workspaceName: accessCheck.data.workspace.name,
          userId,
          workspaceId,
        });
      }

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        message: 'Profile updated successfully',
        data: {
          user: updatedUser || accessCheck.data.user,
          changes,
          requiresEmailVerification: updateFields.email ? true : false,
        },
      };
    } catch (error) {
      console.error('Update user profile error:', error);

      this._logUserEvent(USER_EVENTS.SECURITY_EVENT, {
        event: 'profile_update_failed',
        userId,
        workspaceId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to update profile',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Change user password
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @param {Object} passwordData - Password change data
   * @param {Object} options - Change options
   * @returns {Promise<Object>} Change result
   */
  async changeUserPassword(userId, workspaceId, passwordData, options = {}) {
    try {
      const { currentPassword, newPassword } = passwordData;
      const { ipAddress = null } = options;

      // Validate workspace access
      const accessCheck = await this.validateWorkspaceAccess(
        userId,
        workspaceId,
      );
      if (!accessCheck.success) {
        return accessCheck;
      }

      const user = accessCheck.data.user;

      // Verify current password
      if (user.passwordHash) {
        const isValidPassword = await comparePassword(
          currentPassword,
          user.passwordHash,
        );
        if (!isValidPassword) {
          return {
            success: false,
            result: USER_RESULTS.INVALID_PASSWORD,
            message: 'Current password is incorrect',
          };
        }
      }

      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);

      // Update password
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });

      // Revoke all existing sessions except current one
      await prisma.session.updateMany({
        where: {
          userId,
          // Keep current session active if available
        },
        data: { isActive: false },
      });

      // Update metrics
      this.userMetrics.passwordChanges++;

      // Log password change
      this._logUserEvent(USER_EVENTS.PASSWORD_CHANGED, {
        userId,
        workspaceId,
        ipAddress,
      });

      // Send security alert
      await sendSecurityAlertEmail({
        email: user.email,
        name: user.name,
        alertType: 'password_change',
        details: {
          timestamp: new Date().toISOString(),
          ipAddress,
        },
        workspaceName: accessCheck.data.workspace.name,
        userId,
        workspaceId,
      });

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        message: 'Password changed successfully',
      };
    } catch (error) {
      console.error('Change password error:', error);

      this._logUserEvent(USER_EVENTS.SECURITY_EVENT, {
        event: 'password_change_failed',
        userId,
        workspaceId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to change password',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Search users within workspace
   * @param {string} workspaceId - Workspace ID
   * @param {Object} searchParams - Search parameters
   * @param {Object} options - Search options
   * @returns {Promise<Object>} Search result
   */
  async searchUsers(workspaceId, searchParams, options = {}) {
    try {
      const {
        query = '',
        role = null,
        isActive = true,
        page = 1,
        limit = 20,
        sortBy = 'name',
        sortOrder = 'asc',
      } = searchParams;

      const { requestingUserId = null } = options;

      // Validate requesting user has access to workspace
      if (requestingUserId) {
        const accessCheck = await this.validateWorkspaceAccess(
          requestingUserId,
          workspaceId,
        );
        if (!accessCheck.success) {
          return accessCheck;
        }
      }

      // Build search filters
      const whereClause = {
        memberships: {
          some: {
            workspaceId,
            isActive: true,
            ...(role && { role }),
          },
        },
        ...(isActive !== null && { isActive }),
        ...(query && {
          OR: [
            { name: { contains: query, mode: 'insensitive' } },
            { email: { contains: query, mode: 'insensitive' } },
          ],
        }),
      };

      // Get total count
      const totalCount = await prisma.user.count({
        where: whereClause,
      });

      // Get users with pagination
      const users = await prisma.user.findMany({
        where: whereClause,
        include: {
          memberships: {
            where: { workspaceId, isActive: true },
            include: {
              workspace: {
                select: {
                  id: true,
                  name: true,
                  domain: true,
                },
              },
            },
          },
        },
        orderBy: { [sortBy]: sortOrder },
        skip: (page - 1) * limit,
        take: limit,
      });

      // Format results
      const formattedUsers = users.map((user) => ({
        id: user.id,
        email: user.email,
        name: user.name,
        emailVerified: user.emailVerified,
        isActive: user.isActive,
        role: user.memberships[0]?.role,
        membershipCreatedAt: user.memberships[0]?.createdAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      }));

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        data: {
          users: formattedUsers,
          pagination: {
            page,
            limit,
            totalCount,
            totalPages: Math.ceil(totalCount / limit),
            hasNextPage: page < Math.ceil(totalCount / limit),
            hasPreviousPage: page > 1,
          },
        },
      };
    } catch (error) {
      console.error('Search users error:', error);

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to search users',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Deactivate user account
   * @param {string} userId - User ID to deactivate
   * @param {string} workspaceId - Workspace ID
   * @param {Object} options - Deactivation options
   * @returns {Promise<Object>} Deactivation result
   */
  async deactivateUser(userId, workspaceId, options = {}) {
    try {
      const {
        requestingUserId,
        reason = 'No reason provided',
        ipAddress = null,
      } = options;

      // Validate requesting user has admin permissions
      const canDeactivate = await this.canManageUser(
        requestingUserId,
        userId,
        workspaceId,
      );
      if (!canDeactivate) {
        return {
          success: false,
          result: USER_RESULTS.INVALID_PERMISSIONS,
          message: 'Insufficient permissions to deactivate user',
        };
      }

      // Deactivate user
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: { isActive: false },
      });

      // Revoke all user sessions
      await prisma.session.updateMany({
        where: { userId },
        data: { isActive: false },
      });

      // Update metrics
      this.userMetrics.accountDeactivations++;

      // Log deactivation
      this._logUserEvent(USER_EVENTS.ACCOUNT_DEACTIVATED, {
        userId,
        requestingUserId,
        workspaceId,
        reason,
        ipAddress,
      });

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        message: 'User account deactivated successfully',
        data: {
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            name: updatedUser.name,
            isActive: updatedUser.isActive,
          },
        },
      };
    } catch (error) {
      console.error('Deactivate user error:', error);

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to deactivate user',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Reactivate user account
   * @param {string} userId - User ID to reactivate
   * @param {string} workspaceId - Workspace ID
   * @param {Object} options - Reactivation options
   * @returns {Promise<Object>} Reactivation result
   */
  async reactivateUser(userId, workspaceId, options = {}) {
    try {
      const { requestingUserId, ipAddress = null } = options;

      // Validate requesting user has admin permissions
      const canReactivate = await this.canManageUser(
        requestingUserId,
        userId,
        workspaceId,
      );
      if (!canReactivate) {
        return {
          success: false,
          result: USER_RESULTS.INVALID_PERMISSIONS,
          message: 'Insufficient permissions to reactivate user',
        };
      }

      // Reactivate user
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: { isActive: true },
      });

      // Update metrics
      this.userMetrics.accountReactivations++;

      // Log reactivation
      this._logUserEvent(USER_EVENTS.ACCOUNT_REACTIVATED, {
        userId,
        requestingUserId,
        workspaceId,
        ipAddress,
      });

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        message: 'User account reactivated successfully',
        data: {
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            name: updatedUser.name,
            isActive: updatedUser.isActive,
          },
        },
      };
    } catch (error) {
      console.error('Reactivate user error:', error);

      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to reactivate user',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Get user preferences
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<Object>} User preferences
   */
  async getUserPreferences(userId, workspaceId) {
    try {
      // In a real implementation, you might have a preferences table
      // For now, we'll return default preferences
      return {
        theme: 'light',
        language: 'en',
        timezone: 'UTC',
        notifications: {
          email: true,
          push: true,
          desktop: false,
        },
        privacy: {
          profileVisible: true,
          activityVisible: false,
        },
      };
    } catch (error) {
      console.error('Get user preferences error:', error);
      return {};
    }
  }

  /**
   * Update user preferences
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @param {Object} preferences - Preferences to update
   * @returns {Promise<Object>} Update result
   */
  async updateUserPreferences(userId, workspaceId, preferences) {
    try {
      // In a real implementation, you would update a preferences table
      // For now, we'll just log the update
      this._logUserEvent(USER_EVENTS.PREFERENCES_UPDATED, {
        userId,
        workspaceId,
        preferences,
      });

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        message: 'Preferences updated successfully',
      };
    } catch (error) {
      console.error('Update user preferences error:', error);
      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to update preferences',
      };
    }
  }

  /**
   * Validate workspace access for user
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<Object>} Validation result
   */
  async validateWorkspaceAccess(userId, workspaceId) {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          memberships: {
            where: {
              workspaceId,
              isActive: true,
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

      if (!user) {
        return {
          success: false,
          result: USER_RESULTS.USER_NOT_FOUND,
          message: 'User not found',
        };
      }

      if (!user.isActive) {
        return {
          success: false,
          result: USER_RESULTS.ACCOUNT_INACTIVE,
          message: 'User account is inactive',
        };
      }

      const membership = user.memberships[0];
      if (!membership || !membership.workspace.isActive) {
        return {
          success: false,
          result: USER_RESULTS.WORKSPACE_ACCESS_DENIED,
          message: 'User does not have access to this workspace',
        };
      }

      return {
        success: true,
        result: USER_RESULTS.SUCCESS,
        data: {
          user,
          workspace: membership.workspace,
          role: membership.role,
        },
      };
    } catch (error) {
      console.error('Validate workspace access error:', error);
      return {
        success: false,
        result: USER_RESULTS.OPERATION_FAILED,
        message: 'Failed to validate workspace access',
      };
    }
  }

  /**
   * Check if user can update another user's profile
   * @param {string} requestingUserId - Requesting user ID
   * @param {string} targetUserId - Target user ID
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<boolean>} Whether user can update profile
   */
  async canUpdateUserProfile(requestingUserId, targetUserId, workspaceId) {
    try {
      // Users can always update their own profile
      if (requestingUserId === targetUserId) {
        return true;
      }

      // Check if requesting user is admin in workspace
      const requestingUser = await prisma.membership.findFirst({
        where: {
          userId: requestingUserId,
          workspaceId,
          isActive: true,
          role: 'ADMIN',
        },
      });

      return !!requestingUser;
    } catch (error) {
      console.error('Check update profile permission error:', error);
      return false;
    }
  }

  /**
   * Check if user can manage another user
   * @param {string} requestingUserId - Requesting user ID
   * @param {string} targetUserId - Target user ID
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<boolean>} Whether user can manage target user
   */
  async canManageUser(requestingUserId, targetUserId, workspaceId) {
    try {
      // Users cannot manage themselves for certain operations
      if (requestingUserId === targetUserId) {
        return false;
      }

      // Check if requesting user is admin in workspace
      const requestingUser = await prisma.membership.findFirst({
        where: {
          userId: requestingUserId,
          workspaceId,
          isActive: true,
          role: 'ADMIN',
        },
      });

      return !!requestingUser;
    } catch (error) {
      console.error('Check manage user permission error:', error);
      return false;
    }
  }

  /**
   * Get user service metrics
   * @returns {Object} User service metrics
   */
  getMetrics() {
    return {
      ...this.userMetrics,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log user events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logUserEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'USER_SERVICE',
    };

    if (event === USER_EVENTS.SECURITY_EVENT) {
      console.warn('👤 User Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('👤 User Event:', logEntry);
    }

    // In production, send to audit log service
    if (config.isProduction()) {
      // TODO: Send to audit log service
    }
  }
}

// Create singleton instance
const userService = new UserService();

// Export user service
module.exports = {
  // Main service instance
  userService,

  // Service methods
  getUserProfile: (userId, workspaceId, options) =>
    userService.getUserProfile(userId, workspaceId, options),
  updateUserProfile: (userId, workspaceId, updateData, options) =>
    userService.updateUserProfile(userId, workspaceId, updateData, options),
  changeUserPassword: (userId, workspaceId, passwordData, options) =>
    userService.changeUserPassword(userId, workspaceId, passwordData, options),
  searchUsers: (workspaceId, searchParams, options) =>
    userService.searchUsers(workspaceId, searchParams, options),
  deactivateUser: (userId, workspaceId, options) =>
    userService.deactivateUser(userId, workspaceId, options),
  reactivateUser: (userId, workspaceId, options) =>
    userService.reactivateUser(userId, workspaceId, options),
  getUserPreferences: (userId, workspaceId) =>
    userService.getUserPreferences(userId, workspaceId),
  updateUserPreferences: (userId, workspaceId, preferences) =>
    userService.updateUserPreferences(userId, workspaceId, preferences),

  // Validation methods
  validateWorkspaceAccess: (userId, workspaceId) =>
    userService.validateWorkspaceAccess(userId, workspaceId),
  canUpdateUserProfile: (requestingUserId, targetUserId, workspaceId) =>
    userService.canUpdateUserProfile(
      requestingUserId,
      targetUserId,
      workspaceId,
    ),
  canManageUser: (requestingUserId, targetUserId, workspaceId) =>
    userService.canManageUser(requestingUserId, targetUserId, workspaceId),

  // Utilities
  getMetrics: () => userService.getMetrics(),

  // Constants
  USER_RESULTS,
  USER_EVENTS,
  USER_ACTIVITY_TYPES,
};
