/**
 * Workspace Controller Module
 *
 * This controller provides REST API endpoints for workspace management operations
 * in multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - Workspace creation and configuration
 * - Member management and role assignments
 * - Invitation system with email domain validation
 * - Workspace settings and preferences
 * - Workspace analytics and reporting
 * - Bulk operations for enterprise clients
 *
 * Security:
 * - Workspace-scoped access control
 * - Role-based permissions (admin, member)
 * - Input validation and sanitization
 * - Rate limiting for sensitive operations
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const workspaceService = require('../services/workspaceService');
const { validateRequest } = require('../middlewares/validation');
const {
  requireAuth,
  requireWorkspaceAccess,
  requireWorkspaceAdmin,
} = require('../middlewares/auth');
const { asyncHandler } = require('../utils/asyncHandler');
const { ApiResponse } = require('../utils/apiResponse');
const { ApiError } = require('../utils/apiError');
const logger = require('../utils/logger');
const {
  workspaceValidationSchemas,
} = require('../validations/workspaceValidation');

class WorkspaceController {
  /**
   * Get current workspace details
   * GET /api/workspaces/current
   */
  getCurrentWorkspace = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;

    logger.info('Getting current workspace details', {
      workspaceId,
      userId: req.user.id,
      userAgent: req.get('User-Agent'),
    });

    const workspace = await workspaceService.getWorkspaceById(workspaceId);

    if (!workspace) {
      throw new ApiError(404, 'Workspace not found');
    }

    // Get workspace statistics
    const stats = await workspaceService.getWorkspaceStats(workspaceId);

    const response = {
      workspace: {
        ...workspace,
        stats,
      },
    };

    logger.info('Current workspace retrieved successfully', {
      workspaceId,
      userId: req.user.id,
    });

    res.json(
      new ApiResponse(200, response, 'Workspace retrieved successfully'),
    );
  });

  /**
   * Update workspace settings
   * PUT /api/workspaces/current
   */
  updateWorkspace = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const updateData = req.body;

    logger.info('Updating workspace settings', {
      workspaceId,
      userId: req.user.id,
      updateFields: Object.keys(updateData),
    });

    const updatedWorkspace = await workspaceService.updateWorkspace(
      workspaceId,
      updateData,
      req.user.id,
    );

    logger.info('Workspace updated successfully', {
      workspaceId,
      userId: req.user.id,
    });

    res.json(
      new ApiResponse(
        200,
        { workspace: updatedWorkspace },
        'Workspace updated successfully',
      ),
    );
  });

  /**
   * Get workspace members
   * GET /api/workspaces/members
   */
  getWorkspaceMembers = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { page = 1, limit = 20, search, role, status } = req.query;

    logger.info('Getting workspace members', {
      workspaceId,
      userId: req.user.id,
      filters: { search, role, status },
    });

    const result = await workspaceService.getWorkspaceMembers(workspaceId, {
      page: parseInt(page),
      limit: parseInt(limit),
      search,
      role,
      status,
    });

    logger.info('Workspace members retrieved successfully', {
      workspaceId,
      userId: req.user.id,
      totalMembers: result.total,
    });

    res.json(
      new ApiResponse(200, result, 'Workspace members retrieved successfully'),
    );
  });

  /**
   * Invite users to workspace
   * POST /api/workspaces/invite
   */
  inviteUsers = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { emails, role = 'member', message } = req.body;

    logger.info('Inviting users to workspace', {
      workspaceId,
      invitedBy: req.user.id,
      emailCount: emails.length,
      role,
    });

    const result = await workspaceService.inviteUsers(workspaceId, {
      emails,
      role,
      message,
      invitedBy: req.user.id,
    });

    logger.info('Users invited successfully', {
      workspaceId,
      invitedBy: req.user.id,
      successCount: result.successful.length,
      failureCount: result.failed.length,
    });

    res.json(new ApiResponse(200, result, 'Invitations sent successfully'));
  });

  /**
   * Get workspace invitations
   * GET /api/workspaces/invitations
   */
  getWorkspaceInvitations = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { page = 1, limit = 20, status } = req.query;

    logger.info('Getting workspace invitations', {
      workspaceId,
      userId: req.user.id,
      status,
    });

    const result = await workspaceService.getWorkspaceInvitations(workspaceId, {
      page: parseInt(page),
      limit: parseInt(limit),
      status,
    });

    logger.info('Workspace invitations retrieved successfully', {
      workspaceId,
      userId: req.user.id,
      totalInvitations: result.total,
    });

    res.json(
      new ApiResponse(200, result, 'Invitations retrieved successfully'),
    );
  });

  /**
   * Resend invitation
   * POST /api/workspaces/invitations/:invitationId/resend
   */
  resendInvitation = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { invitationId } = req.params;

    logger.info('Resending workspace invitation', {
      workspaceId,
      invitationId,
      userId: req.user.id,
    });

    await workspaceService.resendInvitation(
      workspaceId,
      invitationId,
      req.user.id,
    );

    logger.info('Invitation resent successfully', {
      workspaceId,
      invitationId,
      userId: req.user.id,
    });

    res.json(new ApiResponse(200, null, 'Invitation resent successfully'));
  });

  /**
   * Cancel invitation
   * DELETE /api/workspaces/invitations/:invitationId
   */
  cancelInvitation = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { invitationId } = req.params;

    logger.info('Cancelling workspace invitation', {
      workspaceId,
      invitationId,
      userId: req.user.id,
    });

    await workspaceService.cancelInvitation(
      workspaceId,
      invitationId,
      req.user.id,
    );

    logger.info('Invitation cancelled successfully', {
      workspaceId,
      invitationId,
      userId: req.user.id,
    });

    res.json(new ApiResponse(200, null, 'Invitation cancelled successfully'));
  });

  /**
   * Accept workspace invitation (public endpoint)
   * POST /api/workspaces/invitations/accept
   */
  acceptInvitation = asyncHandler(async (req, res) => {
    const { token } = req.body;

    logger.info('Accepting workspace invitation', {
      token: token.substring(0, 10) + '...',
      userAgent: req.get('User-Agent'),
    });

    const result = await workspaceService.acceptInvitation(token);

    logger.info('Invitation accepted successfully', {
      workspaceId: result.workspace.id,
      userId: result.user.id,
    });

    res.json(new ApiResponse(200, result, 'Invitation accepted successfully'));
  });

  /**
   * Update member role
   * PUT /api/workspaces/members/:userId/role
   */
  updateMemberRole = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { userId } = req.params;
    const { role } = req.body;

    logger.info('Updating member role', {
      workspaceId,
      targetUserId: userId,
      newRole: role,
      updatedBy: req.user.id,
    });

    const updatedMember = await workspaceService.updateMemberRole(
      workspaceId,
      userId,
      role,
      req.user.id,
    );

    logger.info('Member role updated successfully', {
      workspaceId,
      targetUserId: userId,
      newRole: role,
      updatedBy: req.user.id,
    });

    res.json(
      new ApiResponse(
        200,
        { member: updatedMember },
        'Member role updated successfully',
      ),
    );
  });

  /**
   * Remove member from workspace
   * DELETE /api/workspaces/members/:userId
   */
  removeMember = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { userId } = req.params;

    logger.info('Removing member from workspace', {
      workspaceId,
      targetUserId: userId,
      removedBy: req.user.id,
    });

    await workspaceService.removeMember(workspaceId, userId, req.user.id);

    logger.info('Member removed successfully', {
      workspaceId,
      targetUserId: userId,
      removedBy: req.user.id,
    });

    res.json(new ApiResponse(200, null, 'Member removed successfully'));
  });

  /**
   * Leave workspace
   * POST /api/workspaces/leave
   */
  leaveWorkspace = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const userId = req.user.id;

    logger.info('User leaving workspace', {
      workspaceId,
      userId,
    });

    await workspaceService.leaveWorkspace(workspaceId, userId);

    logger.info('User left workspace successfully', {
      workspaceId,
      userId,
    });

    res.json(new ApiResponse(200, null, 'Left workspace successfully'));
  });

  /**
   * Get workspace activity log
   * GET /api/workspaces/activity
   */
  getWorkspaceActivity = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { page = 1, limit = 20, type, userId: filterUserId } = req.query;

    logger.info('Getting workspace activity', {
      workspaceId,
      userId: req.user.id,
      filters: { type, filterUserId },
    });

    const result = await workspaceService.getWorkspaceActivity(workspaceId, {
      page: parseInt(page),
      limit: parseInt(limit),
      type,
      userId: filterUserId,
    });

    logger.info('Workspace activity retrieved successfully', {
      workspaceId,
      userId: req.user.id,
      totalActivities: result.total,
    });

    res.json(
      new ApiResponse(200, result, 'Workspace activity retrieved successfully'),
    );
  });

  /**
   * Get workspace analytics
   * GET /api/workspaces/analytics
   */
  getWorkspaceAnalytics = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { period = '30d', metrics } = req.query;

    logger.info('Getting workspace analytics', {
      workspaceId,
      userId: req.user.id,
      period,
      metrics,
    });

    const analytics = await workspaceService.getWorkspaceAnalytics(
      workspaceId,
      {
        period,
        metrics: metrics ? metrics.split(',') : undefined,
      },
    );

    logger.info('Workspace analytics retrieved successfully', {
      workspaceId,
      userId: req.user.id,
      period,
    });

    res.json(
      new ApiResponse(
        200,
        { analytics },
        'Workspace analytics retrieved successfully',
      ),
    );
  });

  /**
   * Export workspace data
   * POST /api/workspaces/export
   */
  exportWorkspaceData = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const {
      format = 'json',
      includeMembers = true,
      includeActivity = false,
    } = req.body;

    logger.info('Exporting workspace data', {
      workspaceId,
      userId: req.user.id,
      format,
      includeMembers,
      includeActivity,
    });

    const exportResult = await workspaceService.exportWorkspaceData(
      workspaceId,
      {
        format,
        includeMembers,
        includeActivity,
        requestedBy: req.user.id,
      },
    );

    logger.info('Workspace data export initiated', {
      workspaceId,
      userId: req.user.id,
      exportId: exportResult.exportId,
    });

    res.json(
      new ApiResponse(200, exportResult, 'Workspace data export initiated'),
    );
  });

  /**
   * Delete workspace (admin only)
   * DELETE /api/workspaces/current
   */
  deleteWorkspace = asyncHandler(async (req, res) => {
    const { workspaceId } = req.workspace;
    const { confirmation } = req.body;

    logger.warn('Workspace deletion requested', {
      workspaceId,
      userId: req.user.id,
      confirmation,
    });

    await workspaceService.deleteWorkspace(
      workspaceId,
      req.user.id,
      confirmation,
    );

    logger.warn('Workspace deleted successfully', {
      workspaceId,
      userId: req.user.id,
    });

    res.json(new ApiResponse(200, null, 'Workspace deleted successfully'));
  });
}

// Create controller instance
const workspaceController = new WorkspaceController();

// Export controller methods with middleware
module.exports = {
  // Workspace management
  getCurrentWorkspace: [
    requireAuth,
    requireWorkspaceAccess,
    workspaceController.getCurrentWorkspace,
  ],

  updateWorkspace: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.updateWorkspace),
    workspaceController.updateWorkspace,
  ],

  deleteWorkspace: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.deleteWorkspace),
    workspaceController.deleteWorkspace,
  ],

  // Member management
  getWorkspaceMembers: [
    requireAuth,
    requireWorkspaceAccess,
    validateRequest(workspaceValidationSchemas.getMembers),
    workspaceController.getWorkspaceMembers,
  ],

  updateMemberRole: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.updateMemberRole),
    workspaceController.updateMemberRole,
  ],

  removeMember: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.removeMember),
    workspaceController.removeMember,
  ],

  leaveWorkspace: [
    requireAuth,
    requireWorkspaceAccess,
    workspaceController.leaveWorkspace,
  ],

  // Invitation management
  inviteUsers: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.inviteUsers),
    workspaceController.inviteUsers,
  ],

  getWorkspaceInvitations: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.getInvitations),
    workspaceController.getWorkspaceInvitations,
  ],

  resendInvitation: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.resendInvitation),
    workspaceController.resendInvitation,
  ],

  cancelInvitation: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.cancelInvitation),
    workspaceController.cancelInvitation,
  ],

  acceptInvitation: [
    validateRequest(workspaceValidationSchemas.acceptInvitation),
    workspaceController.acceptInvitation,
  ],

  // Analytics and reporting
  getWorkspaceActivity: [
    requireAuth,
    requireWorkspaceAccess,
    validateRequest(workspaceValidationSchemas.getActivity),
    workspaceController.getWorkspaceActivity,
  ],

  getWorkspaceAnalytics: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.getAnalytics),
    workspaceController.getWorkspaceAnalytics,
  ],

  exportWorkspaceData: [
    requireAuth,
    requireWorkspaceAdmin,
    validateRequest(workspaceValidationSchemas.exportData),
    workspaceController.exportWorkspaceData,
  ],
};
