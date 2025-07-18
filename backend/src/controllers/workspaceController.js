// backend/src/controllers/workspaceController.js

/**
 * Workspace Controller
 * Handles all workspace-related HTTP logic.
 * Delegates business logic to workspaceService and uses DRY patterns.
 */

const { workspaceService } = require('../services/workspaceService');
const { asyncHandler } = require('../utils/asyncHandler');
const { ApiError, ERROR_CODES } = require('../utils/apiError');
const { SuccessResponse } = require('../utils/apiResponse');
const {
  validateSecurity,
  validateInput,
} = require('../validations/middleware');
const { authenticate } = require('../config/auth');

/**
 * Get workspace details
 */
const getWorkspaceDetails = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const details = await workspaceService.getWorkspaceDetails(workspaceId);
    return new SuccessResponse(details, 'Workspace details retrieved').send(
      res,
      req,
    );
  }),
];

/**
 * Update workspace details
 */
const updateWorkspace = [
  authenticate('jwt'),
  validateSecurity(),
  validateInput(/* Optionally pass a schema here */),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const updateData = req.body;
    const updated = await workspaceService.updateWorkspace(
      workspaceId,
      updateData,
    );
    return new SuccessResponse(updated, 'Workspace updated').send(res, req);
  }),
];

/**
 * Invite a user to workspace
 */
const inviteUser = [
  authenticate('jwt'),
  validateSecurity(),
  validateInput(/* Optionally pass a schema here */),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const inviteData = req.body;
    const result = await workspaceService.inviteUser(workspaceId, inviteData);
    return new SuccessResponse(result, 'User invited to workspace').send(
      res,
      req,
    );
  }),
];

/**
 * Accept workspace invitation
 */
const acceptInvitation = [
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const { inviteToken } = req.body;
    if (!inviteToken) {
      throw new ApiError(
        400,
        'Invite token is required',
        ERROR_CODES.MISSING_TOKEN,
      );
    }
    const result = await workspaceService.acceptInvitation(inviteToken);
    return new SuccessResponse(result, 'Invitation accepted').send(res, req);
  }),
];

/**
 * Remove a member from workspace
 */
const removeMember = [
  authenticate('jwt'),
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const { memberId } = req.body;
    if (!memberId) {
      throw new ApiError(
        400,
        'Member ID is required',
        ERROR_CODES.MISSING_FIELDS,
      );
    }
    await workspaceService.removeMember(workspaceId, memberId);
    return new SuccessResponse(null, 'Member removed from workspace').send(
      res,
      req,
    );
  }),
];

/**
 * Change a member's role in workspace
 */
const changeMemberRole = [
  authenticate('jwt'),
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const { memberId, newRole } = req.body;
    if (!memberId || !newRole) {
      throw new ApiError(
        400,
        'Member ID and new role are required',
        ERROR_CODES.MISSING_FIELDS,
      );
    }
    const result = await workspaceService.changeMemberRole(
      workspaceId,
      memberId,
      newRole,
    );
    return new SuccessResponse(result, 'Member role updated').send(res, req);
  }),
];

/**
 * Get workspace statistics
 */
const getWorkspaceStats = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const workspaceId = req.user.memberships?.[0]?.workspace?.id;
    const stats = await workspaceService.getWorkspaceStats(workspaceId);
    return new SuccessResponse(stats, 'Workspace stats retrieved').send(
      res,
      req,
    );
  }),
];

module.exports = {
  getWorkspaceDetails,
  updateWorkspace,
  inviteUser,
  acceptInvitation,
  removeMember,
  changeMemberRole,
  getWorkspaceStats,
};
