// backend/src/controllers/userController.js

/**
 * User Controller
 * Handles all user-related HTTP logic.
 * Delegates business logic to userService and uses DRY patterns.
 */

const { userService } = require('../services/userService');
const { asyncHandler } = require('../utils/asyncHandler');
const { ApiError, ERROR_CODES } = require('../utils/apiError');
const { SuccessResponse } = require('../utils/apiResponse');
const logger = require('../utils/logger');
const {
  validateSecurity,
  validateInput,
} = require('../validations/middleware');
const { authenticate } = require('../config/auth');

/**
 * Get current user's profile
 */
const getProfile = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const profile = await userService.getUserProfile(userId, workspaceId);
    return new SuccessResponse(profile, 'User profile retrieved').send(
      res,
      req,
    );
  }),
];

/**
 * Update current user's profile
 */
const updateProfile = [
  authenticate('jwt'),
  validateSecurity(),
  validateInput(/* Optionally pass a schema here */),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const updateData = req.body;
    const updated = await userService.updateUserProfile(
      userId,
      workspaceId,
      updateData,
    );
    return new SuccessResponse(updated, 'User profile updated').send(res, req);
  }),
];

/**
 * Change user password
 */
const changePassword = [
  authenticate('jwt'),
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      throw new ApiError(
        400,
        'Old and new password are required',
        ERROR_CODES.MISSING_FIELDS,
      );
    }
    const result = await userService.changeUserPassword(userId, workspaceId, {
      oldPassword,
      newPassword,
    });
    return new SuccessResponse(result, 'Password changed successfully').send(
      res,
      req,
    );
  }),
];

/**
 * Search users in workspace
 */
const searchUsers = [
  authenticate('jwt'),
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const searchParams = req.query;
    const users = await userService.searchUsers(workspaceId, searchParams);
    return new SuccessResponse(users, 'Users found').send(res, req);
  }),
];

/**
 * Deactivate user (self)
 */
const deactivate = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    await userService.deactivateUser(userId, workspaceId);
    return new SuccessResponse(null, 'User deactivated').send(res, req);
  }),
];

/**
 * Reactivate user (self)
 */
const reactivate = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    await userService.reactivateUser(userId, workspaceId);
    return new SuccessResponse(null, 'User reactivated').send(res, req);
  }),
];

/**
 * Get user preferences
 */
const getPreferences = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const prefs = await userService.getUserPreferences(userId, workspaceId);
    return new SuccessResponse(prefs, 'User preferences retrieved').send(
      res,
      req,
    );
  }),
];

/**
 * Update user preferences
 */
const updatePreferences = [
  authenticate('jwt'),
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const preferences = req.body;
    const updated = await userService.updateUserPreferences(
      userId,
      workspaceId,
      preferences,
    );
    return new SuccessResponse(updated, 'User preferences updated').send(
      res,
      req,
    );
  }),
];

module.exports = {
  getProfile,
  updateProfile,
  changePassword,
  searchUsers,
  deactivate,
  reactivate,
  getPreferences,
  updatePreferences,
};
