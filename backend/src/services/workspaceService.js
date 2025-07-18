/**
 * Workspace Service Module
 *
 * This service provides comprehensive workspace management functionality for
 * multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - Workspace creation and configuration
 * - Member management and role assignments
 * - Invitation system with email-based invites
 * - Workspace settings and customization
 * - Usage analytics and reporting
 * - Workspace deactivation and archival
 * - Custom domain management (future)
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const { client: prisma } = require('../config/database');
const {
  normalizeEmail
} = require('../utils/domain');
const { generateSecureToken } = require('../utils/encryption');
const { sendUserEmail } = require('../utils/email');
const logger = require('../utils/logger');
const { ApiError, ERROR_CODES, HTTP_STATUS } = require('../utils/apiError');
const { ApiResponse } = require('../utils/apiResponse');
const { asyncHandler } = require('../utils/asyncHandler');
const config = require('../config');

class WorkspaceService {
  constructor() {
    this.workspaceMetrics = {
      workspacesCreated: 0,
      workspacesUpdated: 0,
      workspacesDeactivated: 0,
      membersInvited: 0,
      membersJoined: 0,
      membersRemoved: 0,
      invitesCreated: 0,
      invitesAccepted: 0,
      invitesRevoked: 0,
      securityEvents: 0,
    };
  }

  /**
   * Get workspace details with members
   */
  async getWorkspaceDetails(workspaceId, options = {}) {
    return asyncHandler(async () => {
      const {
        includeMembers = true,
        includeInvites = false,
        includeStats = false,
        requestingUserId = null,
      } = options;
      // Validate workspaceId
      if (!workspaceId)
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Workspace ID is required',
          HTTP_STATUS.BAD_REQUEST,
        );
      // Optionally validate access
      if (requestingUserId) {
        const access = await this.validateWorkspaceAccess(
          requestingUserId,
          workspaceId,
        );
        if (!access)
          throw new ApiError(
            ERROR_CODES.ACCESS_DENIED,
            'No access to workspace',
            HTTP_STATUS.FORBIDDEN,
          );
      }
      const workspace = await prisma.workspace.findUnique({
        where: { id: workspaceId },
        include: {
          ...(includeMembers && {
            memberships: {
              where: { isActive: true },
              include: { user: true },
              orderBy: { createdAt: 'asc' },
            },
          }),
          ...(includeInvites && {
            invites: {
              where: { used: false, expiresAt: { gt: new Date() } },
              orderBy: { createdAt: 'desc' },
            },
          }),
        },
      });
      if (!workspace)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Workspace not found',
          HTTP_STATUS.NOT_FOUND,
        );
      let stats = null;
      if (includeStats) stats = await this.getWorkspaceStats(workspaceId);
      return ApiResponse.success('Workspace details retrieved', {
        workspace: {
          id: workspace.id,
          name: workspace.name,
          domain: workspace.domain,
          isActive: workspace.isActive,
          createdAt: workspace.createdAt,
          updatedAt: workspace.updatedAt,
        },
        members: includeMembers
          ? (workspace.memberships || []).map((m) => ({
              id: m.id,
              role: m.role,
              joinedAt: m.createdAt,
              user: m.user,
            }))
          : undefined,
        invites: includeInvites ? workspace.invites : undefined,
        stats: includeStats ? stats : undefined,
      });
    })();
  }

  /**
   * Update workspace settings
   */
  async updateWorkspace(workspaceId, updateData, options = {}) {
    return asyncHandler(async () => {
      const { requestingUserId, ipAddress = null } = options;
      const { name, domain } = updateData;
      // Validate workspaceId
      if (!workspaceId)
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Workspace ID is required',
          HTTP_STATUS.BAD_REQUEST,
        );
      // Validate permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Admin permissions required',
          HTTP_STATUS.FORBIDDEN,
        );
      // Get current workspace
      const currentWorkspace = await prisma.workspace.findUnique({
        where: { id: workspaceId },
      });
      if (!currentWorkspace)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Workspace not found',
          HTTP_STATUS.NOT_FOUND,
        );
      // Prepare update data
      const updateFields = {};
      const changes = [];
      if (name !== undefined && name !== currentWorkspace.name) {
        updateFields.name = name;
        changes.push({
          field: 'name',
          oldValue: currentWorkspace.name,
          newValue: name,
        });
      }
      if (domain !== undefined && domain !== currentWorkspace.domain) {
        // Check if domain already exists
        const existingWorkspace = await prisma.workspace.findUnique({
          where: { domain },
        });
        if (existingWorkspace && existingWorkspace.id !== workspaceId)
          throw new ApiError(
            ERROR_CODES.RESOURCE_ALREADY_EXISTS,
            'Domain is already in use',
            HTTP_STATUS.CONFLICT,
          );
        updateFields.domain = domain;
        changes.push({
          field: 'domain',
          oldValue: currentWorkspace.domain,
          newValue: domain,
        });
      }
      // Update workspace if there are changes
      let updatedWorkspace = currentWorkspace;
      if (Object.keys(updateFields).length > 0) {
        updatedWorkspace = await prisma.workspace.update({
          where: { id: workspaceId },
          data: updateFields,
        });
      }
      this.workspaceMetrics.workspacesUpdated++;
      logger.info('Workspace updated', {
        workspaceId,
        requestingUserId,
        changes,
        ipAddress,
      });
      return ApiResponse.success('Workspace updated successfully', {
        workspace: updatedWorkspace,
        changes,
      });
    })();
  }

  /**
   * Invite user to workspace
   */
  async inviteUser(workspaceId, inviteData, options = {}) {
    return asyncHandler(async () => {
      const { email } = inviteData;
      const { requestingUserId, ipAddress = null } = options;
      // Validate permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Admin permissions required',
          HTTP_STATUS.FORBIDDEN,
        );
      const normalizedEmail = normalizeEmail(email);
      // Check if user already exists in workspace
      const existingMember = await prisma.membership.findFirst({
        where: {
          workspaceId,
          user: { email: normalizedEmail },
          isActive: true,
        },
      });
      if (existingMember)
        throw new ApiError(
          ERROR_CODES.RESOURCE_ALREADY_EXISTS,
          'User is already a member',
          HTTP_STATUS.CONFLICT,
        );
      // Check for existing pending invite
      const existingInvite = await prisma.invite.findFirst({
        where: {
          workspaceId,
          email: normalizedEmail,
          used: false,
          expiresAt: { gt: new Date() },
        },
      });
      if (existingInvite)
        throw new ApiError(
          ERROR_CODES.RESOURCE_ALREADY_EXISTS,
          'User already has a pending invitation',
          HTTP_STATUS.CONFLICT,
        );
      // Check workspace member limit
      const memberCount = await prisma.membership.count({
        where: { workspaceId, isActive: true },
      });
      if (memberCount >= config.workspace.maxMembersPerWorkspace)
        throw new ApiError(
          ERROR_CODES.LIMIT_EXCEEDED,
          'Workspace member limit reached',
          HTTP_STATUS.FORBIDDEN,
        );
      // Generate invite token
      const inviteToken = generateSecureToken();
      const expiresAt = new Date(
        Date.now() + config.workspace.inviteExpiry * 60 * 60 * 1000,
      );
      // Create invite
      const invite = await prisma.invite.create({
        data: {
          workspaceId,
          email: normalizedEmail,
          token: inviteToken,
          expiresAt,
          createdById: requestingUserId,
        },
      });
      // Send invitation email
      await sendUserEmail('invitation', {
        invite: { email: normalizedEmail, token: inviteToken, expiresAt },
        inviter: { id: requestingUserId },
        workspace: { id: workspaceId },
      });
      this.workspaceMetrics.membersInvited++;
      this.workspaceMetrics.invitesCreated++;
      logger.info('Workspace member invited', {
        workspaceId,
        inviteId: invite.id,
        email: normalizedEmail,
        invitedBy: requestingUserId,
        expiresAt,
        ipAddress,
      });
      return ApiResponse.success('User invited successfully', { invite });
    })();
  }

  /**
   * Accept workspace invitation
   */
  async acceptInvitation(inviteToken, options = {}) {
    return asyncHandler(async () => {
      const { userId, ipAddress = null } = options;
      // Find invite
      const invite = await prisma.invite.findUnique({
        where: { token: inviteToken },
        include: { workspace: true },
      });
      if (!invite)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Invitation not found',
          HTTP_STATUS.NOT_FOUND,
        );
      if (invite.used)
        throw new ApiError(
          ERROR_CODES.RESOURCE_ALREADY_EXISTS,
          'Invitation already used',
          HTTP_STATUS.CONFLICT,
        );
      if (invite.expiresAt < new Date())
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invitation expired',
          HTTP_STATUS.BAD_REQUEST,
        );
      if (!invite.workspace.isActive)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Workspace is inactive',
          HTTP_STATUS.FORBIDDEN,
        );
      // Get user details
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user || user.email !== invite.email)
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'User email does not match invitation',
          HTTP_STATUS.BAD_REQUEST,
        );
      // Check if user is already a member
      const existingMembership = await prisma.membership.findFirst({
        where: { userId, workspaceId: invite.workspaceId, isActive: true },
      });
      if (existingMembership)
        throw new ApiError(
          ERROR_CODES.RESOURCE_ALREADY_EXISTS,
          'User is already a member',
          HTTP_STATUS.CONFLICT,
        );
      // Accept invitation in transaction
      const result = await prisma.$transaction(async (tx) => {
        await tx.invite.update({
          where: { id: invite.id },
          data: { used: true },
        });
        const membership = await tx.membership.create({
          data: { userId, workspaceId: invite.workspaceId, role: 'MEMBER' },
        });
        return { membership };
      });
      this.workspaceMetrics.membersJoined++;
      this.workspaceMetrics.invitesAccepted++;
      logger.info('Workspace invitation accepted', {
        inviteId: invite.id,
        workspaceId: invite.workspaceId,
        userId,
        email: invite.email,
        ipAddress,
      });
      return ApiResponse.success('Invitation accepted successfully', {
        workspace: invite.workspace,
        membership: result.membership,
      });
    })();
  }

  /**
   * Remove member from workspace
   */
  async removeMember(workspaceId, memberId, options = {}) {
    return asyncHandler(async () => {
      const {
        requestingUserId,
        reason = 'No reason provided',
        ipAddress = null,
      } = options;
      // Validate permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Admin permissions required',
          HTTP_STATUS.FORBIDDEN,
        );
      // Find membership
      const membership = await prisma.membership.findFirst({
        where: { id: memberId, workspaceId, isActive: true },
        include: { user: true },
      });
      if (!membership)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Member not found',
          HTTP_STATUS.NOT_FOUND,
        );
      if (membership.userId === requestingUserId)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Cannot remove yourself',
          HTTP_STATUS.FORBIDDEN,
        );
      // Check if this is the last admin
      if (membership.role === 'ADMIN') {
        const adminCount = await prisma.membership.count({
          where: { workspaceId, role: 'ADMIN', isActive: true },
        });
        if (adminCount <= 1)
          throw new ApiError(
            ERROR_CODES.FORBIDDEN,
            'Cannot remove the last admin',
            HTTP_STATUS.FORBIDDEN,
          );
      }
      // Remove membership
      await prisma.membership.update({
        where: { id: memberId },
        data: { isActive: false },
      });
      // Revoke user sessions for this workspace
      await prisma.session.updateMany({
        where: { userId: membership.userId },
        data: { isActive: false },
      });
      this.workspaceMetrics.membersRemoved++;
      logger.info('Workspace member removed', {
        workspaceId,
        memberId,
        userId: membership.userId,
        removedBy: requestingUserId,
        reason,
        ipAddress,
      });
      return ApiResponse.success('Member removed successfully', {
        removedMember: {
          id: membership.id,
          user: membership.user,
          role: membership.role,
        },
      });
    })();
  }

  /**
   * Change member role
   */
  async changeMemberRole(workspaceId, memberId, newRole, options = {}) {
    return asyncHandler(async () => {
      const { requestingUserId, ipAddress = null } = options;
      // Validate permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission)
        throw new ApiError(
          ERROR_CODES.FORBIDDEN,
          'Admin permissions required',
          HTTP_STATUS.FORBIDDEN,
        );
      // Validate new role
      if (!['ADMIN', 'MEMBER'].includes(newRole))
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid role specified',
          HTTP_STATUS.BAD_REQUEST,
        );
      // Find membership
      const membership = await prisma.membership.findFirst({
        where: { id: memberId, workspaceId, isActive: true },
        include: { user: true },
      });
      if (!membership)
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Member not found',
          HTTP_STATUS.NOT_FOUND,
        );
      // Check if demoting the last admin
      if (membership.role === 'ADMIN' && newRole !== 'ADMIN') {
        const adminCount = await prisma.membership.count({
          where: { workspaceId, role: 'ADMIN', isActive: true },
        });
        if (adminCount <= 1)
          throw new ApiError(
            ERROR_CODES.FORBIDDEN,
            'Cannot demote the last admin',
            HTTP_STATUS.FORBIDDEN,
          );
      }
      // Update role
      const updatedMembership = await prisma.membership.update({
        where: { id: memberId },
        data: { role: newRole },
        include: { user: true },
      });
      this.workspaceMetrics.roleChanges =
        (this.workspaceMetrics.roleChanges || 0) + 1;
      logger.info('Workspace member role changed', {
        workspaceId,
        memberId,
        userId: membership.userId,
        oldRole: membership.role,
        newRole,
        changedBy: requestingUserId,
        ipAddress,
      });
      return ApiResponse.success('Member role changed successfully', {
        membership: {
          id: updatedMembership.id,
          user: updatedMembership.user,
          role: updatedMembership.role,
          oldRole: membership.role,
        },
      });
    })();
  }

  /**
   * Get workspace statistics
   */
  async getWorkspaceStats(workspaceId) {
    // This is a stub for now, can be extended for analytics
    const [
      totalMembers,
      activeMembers,
      adminCount,
      pendingInvites,
      totalInvites,
    ] = await Promise.all([
      prisma.membership.count({ where: { workspaceId } }),
      prisma.membership.count({
        where: { workspaceId, isActive: true, user: { isActive: true } },
      }),
      prisma.membership.count({
        where: { workspaceId, role: 'ADMIN', isActive: true },
      }),
      prisma.invite.count({
        where: { workspaceId, used: false, expiresAt: { gt: new Date() } },
      }),
      prisma.invite.count({ where: { workspaceId } }),
    ]);
    return {
      members: {
        total: totalMembers,
        active: activeMembers,
        admins: adminCount,
        members: activeMembers - adminCount,
      },
      invites: {
        pending: pendingInvites,
        total: totalInvites,
        accepted: totalInvites - pendingInvites,
      },
    };
  }

  /**
   * Validate workspace access for user
   */
  async validateWorkspaceAccess(userId, workspaceId) {
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
   * Check if user has specific workspace permission
   */
  async hasWorkspacePermission(userId, workspaceId, requiredRole) {
    const membership = await prisma.membership.findFirst({
      where: { userId, workspaceId, isActive: true, user: { isActive: true } },
    });
    if (!membership) return false;
    if (membership.role === 'ADMIN') return true;
    return membership.role === requiredRole;
  }

  /**
   * Get workspace service metrics
   */
  getMetrics() {
    return { ...this.workspaceMetrics, timestamp: new Date().toISOString() };
  }
}

const workspaceService = new WorkspaceService();

module.exports = {
  workspaceService,
  getWorkspaceDetails: (workspaceId, options) =>
    workspaceService.getWorkspaceDetails(workspaceId, options),
  updateWorkspace: (workspaceId, updateData, options) =>
    workspaceService.updateWorkspace(workspaceId, updateData, options),
  inviteUser: (workspaceId, inviteData, options) =>
    workspaceService.inviteUser(workspaceId, inviteData, options),
  acceptInvitation: (inviteToken, options) =>
    workspaceService.acceptInvitation(inviteToken, options),
  removeMember: (workspaceId, memberId, options) =>
    workspaceService.removeMember(workspaceId, memberId, options),
  changeMemberRole: (workspaceId, memberId, newRole, options) =>
    workspaceService.changeMemberRole(workspaceId, memberId, newRole, options),
  getWorkspaceStats: (workspaceId) =>
    workspaceService.getWorkspaceStats(workspaceId),
  validateWorkspaceAccess: (userId, workspaceId) =>
    workspaceService.validateWorkspaceAccess(userId, workspaceId),
  hasWorkspacePermission: (userId, workspaceId, requiredRole) =>
    workspaceService.hasWorkspacePermission(userId, workspaceId, requiredRole),
  getMetrics: () => workspaceService.getMetrics(),
};
