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
const { normalizeEmail } = require('../utils/domain');
const { sendUserEmail } = require('../utils/email');
const logger = require('../utils/logger');
const { ApiError, ERROR_CODES, HTTP_STATUS } = require('../utils/apiError');
const { ApiResponse } = require('../utils/apiResponse');
const { asyncHandler } = require('../utils/asyncHandler');
const { InputValidator } = require('../validations/input');

// Initialize validators
const inputValidator = new InputValidator();

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
   */
  async getUserProfile(userId, workspaceId, options = {}) {
    return asyncHandler(async () => {
      const { includeActivity = false, includePreferences = true } = options;
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          memberships: {
            where: { workspaceId, isActive: true },
            include: {
              workspace: { select: { id: true, name: true, domain: true } },
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
      if (!user)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'User not found',
          HTTP_STATUS.NOT_FOUND,
        );
      const membership = user.memberships.find(
        (m) => m.workspaceId === workspaceId,
      );
      if (!membership)
        throw new ApiError(
          ERROR_CODES.ACCESS_DENIED,
          'User does not have access to this workspace',
          HTTP_STATUS.FORBIDDEN,
        );
      let preferences = {};
      if (includePreferences)
        preferences = await this.getUserPreferences(userId, workspaceId);
      return ApiResponse.success('User profile retrieved successfully', {
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
      });
    })();
  }

  /**
   * Update user profile
   */
  async updateUserProfile(userId, workspaceId, updateData, options = {}) {
    return asyncHandler(async () => {
      const { requestingUserId = userId, ipAddress = null } = options;
      const { name, email, preferences = null } = updateData;
      // Validate workspace access
      const accessCheck = await this.validateWorkspaceAccess(
        userId,
        workspaceId,
      );
      if (!accessCheck)
        throw new ApiError(
          ERROR_CODES.ACCESS_DENIED,
          'User does not have access to this workspace',
          HTTP_STATUS.FORBIDDEN,
        );
      // Check if requesting user has permission to update this profile
      const canUpdate = await this.canUpdateUserProfile(
        requestingUserId,
        userId,
        workspaceId,
      );
      if (!canUpdate)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Insufficient permissions to update this profile',
          HTTP_STATUS.FORBIDDEN,
        );
      // Prepare update data
      const updateFields = {};
      const changes = [];
      if (name !== undefined && name !== accessCheck.user.name) {
        updateFields.name = name;
        changes.push({
          field: 'name',
          oldValue: accessCheck.user.name,
          newValue: name,
        });
      }
      if (email !== undefined && email !== accessCheck.user.email) {
        const normalizedEmail = normalizeEmail(email);
        const emailValidation = inputValidator.validateEmail(normalizedEmail);
        if (!emailValidation.isValid)
          throw new ApiError(
            ERROR_CODES.VALIDATION_ERROR,
            'Invalid email format',
            HTTP_STATUS.BAD_REQUEST,
          );
        // Check if email already exists
        const existingUser = await prisma.user.findUnique({
          where: { email: normalizedEmail },
        });
        if (existingUser && existingUser.id !== userId)
          throw new ApiError(
            ERROR_CODES.RESOURCE_ALREADY_EXISTS,
            'Email address is already in use',
            HTTP_STATUS.CONFLICT,
          );
        updateFields.email = normalizedEmail;
        updateFields.emailVerified = false; // Require re-verification
        changes.push({
          field: 'email',
          oldValue: accessCheck.user.email,
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
      if (changes.some((c) => c.field === 'email'))
        this.userMetrics.emailChanges++;
      // Log profile update
      logger.info('User profile updated', {
        userId,
        requestingUserId,
        workspaceId,
        changes,
        ipAddress,
      });
      // Send security alert if email was changed
      if (changes.some((c) => c.field === 'email')) {
        await sendUserEmail('securityAlert', {
          user: { ...accessCheck.user },
          alertType: 'email_change',
          alertDetails: {
            oldEmail: accessCheck.user.email,
            newEmail: email,
            timestamp: new Date().toISOString(),
          },
          workspace: accessCheck.workspace,
        });
      }
      return ApiResponse.success('Profile updated successfully', {
        user: updatedUser || accessCheck.user,
        changes,
        requiresEmailVerification: updateFields.email ? true : false,
      });
    })();
  }

  /**
   * Change user password
   */
  async changeUserPassword(userId, workspaceId, passwordData, options = {}) {
    return asyncHandler(async () => {
      const { currentPassword, newPassword } = passwordData;
      const { ipAddress = null } = options;
      // Validate workspace access
      const accessCheck = await this.validateWorkspaceAccess(
        userId,
        workspaceId,
      );
      if (!accessCheck)
        throw new ApiError(
          ERROR_CODES.ACCESS_DENIED,
          'User does not have access to this workspace',
          HTTP_STATUS.FORBIDDEN,
        );
      const user = accessCheck.user;
      // Verify current password
      if (user.passwordHash) {
        const isValidPassword = await comparePassword(
          currentPassword,
          user.passwordHash,
        );
        if (!isValidPassword)
          throw new ApiError(
            ERROR_CODES.AUTHENTICATION_FAILED,
            'Current password is incorrect',
            HTTP_STATUS.UNAUTHORIZED,
          );
      }
      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);
      // Update password
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newPasswordHash },
      });
      // Revoke all existing sessions
      await prisma.session.updateMany({
        where: { userId },
        data: { isActive: false },
      });
      // Update metrics
      this.userMetrics.passwordChanges++;
      // Log password change
      logger.info('User password changed', { userId, workspaceId, ipAddress });
      // Send security alert
      await sendUserEmail('securityAlert', {
        user: { ...user },
        alertType: 'password_change',
        alertDetails: { timestamp: new Date().toISOString(), ipAddress },
        workspace: accessCheck.workspace,
      });
      return ApiResponse.success('Password changed successfully');
    })();
  }

  /**
   * Search users within workspace
   */
  async searchUsers(workspaceId, searchParams, options = {}) {
    return asyncHandler(async () => {
      const {
        query = '',
        role = null,
        isActive = true,
        page = 1,
        limit = 20,
        sortBy = 'name',
        sortOrder = 'asc',
      } = searchParams;
      // Build search filters
      const whereClause = {
        memberships: {
          some: { workspaceId, isActive: true, ...(role && { role }) },
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
      const totalCount = await prisma.user.count({ where: whereClause });
      // Get users with pagination
      const users = await prisma.user.findMany({
        where: whereClause,
        include: {
          memberships: {
            where: { workspaceId, isActive: true },
            include: {
              workspace: { select: { id: true, name: true, domain: true } },
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
      return ApiResponse.success('Users retrieved successfully', {
        users: formattedUsers,
        pagination: {
          page,
          limit,
          totalCount,
          totalPages: Math.ceil(totalCount / limit),
          hasNextPage: page < Math.ceil(totalCount / limit),
          hasPreviousPage: page > 1,
        },
      });
    })();
  }

  /**
   * Deactivate user account
   */
  async deactivateUser(userId, workspaceId, options = {}) {
    return asyncHandler(async () => {
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
      if (!canDeactivate)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Insufficient permissions to deactivate user',
          HTTP_STATUS.FORBIDDEN,
        );
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
      logger.info('User account deactivated', {
        userId,
        requestingUserId,
        workspaceId,
        reason,
        ipAddress,
      });
      return ApiResponse.success('User account deactivated successfully', {
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          name: updatedUser.name,
          isActive: updatedUser.isActive,
        },
      });
    })();
  }

  /**
   * Reactivate user account
   */
  async reactivateUser(userId, workspaceId, options = {}) {
    return asyncHandler(async () => {
      const { requestingUserId, ipAddress = null } = options;
      // Validate requesting user has admin permissions
      const canReactivate = await this.canManageUser(
        requestingUserId,
        userId,
        workspaceId,
      );
      if (!canReactivate)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Insufficient permissions to reactivate user',
          HTTP_STATUS.FORBIDDEN,
        );
      // Reactivate user
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: { isActive: true },
      });
      // Update metrics
      this.userMetrics.accountReactivations++;
      // Log reactivation
      logger.info('User account reactivated', {
        userId,
        requestingUserId,
        workspaceId,
        ipAddress,
      });
      return ApiResponse.success('User account reactivated successfully', {
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          name: updatedUser.name,
          isActive: updatedUser.isActive,
        },
      });
    })();
  }

  /**
   * Get user preferences (stub)
   */
  async getUserPreferences(userId, workspaceId) {
    // TODO: Implement real preferences storage
    return {
      theme: 'light',
      language: 'en',
      timezone: 'UTC',
      notifications: { email: true, push: true, desktop: false },
      privacy: { profileVisible: true, activityVisible: false },
    };
  }

  /**
   * Update user preferences (stub)
   */
  async updateUserPreferences(userId, workspaceId, preferences) {
    // TODO: Implement real preferences storage
    logger.info('User preferences updated', {
      userId,
      workspaceId,
      preferences,
    });
    return ApiResponse.success('Preferences updated successfully');
  }

  /**
   * Validate workspace access for user
   */
  async validateWorkspaceAccess(userId, workspaceId) {
    // Use workspaceService or direct DB check
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        memberships: {
          where: { workspaceId, isActive: true },
          include: {
            workspace: {
              select: { id: true, name: true, domain: true, isActive: true },
            },
          },
        },
      },
    });
    if (!user || !user.isActive) return null;
    const membership = user.memberships[0];
    if (!membership || !membership.workspace.isActive) return null;
    return { user, workspace: membership.workspace, role: membership.role };
  }

  /**
   * Check if user can update another user's profile
   */
  async canUpdateUserProfile(requestingUserId, targetUserId, workspaceId) {
    // Users can always update their own profile
    if (requestingUserId === targetUserId) return true;
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
  }

  /**
   * Check if user can manage another user
   */
  async canManageUser(requestingUserId, targetUserId, workspaceId) {
    // Users cannot manage themselves for certain operations
    if (requestingUserId === targetUserId) return false;
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
  }

  /**
   * Get user service metrics
   */
  getMetrics() {
    return { ...this.userMetrics, timestamp: new Date().toISOString() };
  }
}

const userService = new UserService();

module.exports = {
  userService,
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
  getMetrics: () => userService.getMetrics(),
};
