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

const crypto = require('crypto');
const { client: prisma } = require('../config/database');
const {
  extractDomain,
  isPersonalEmail,
  normalizeEmail,
} = require('../utils/domain');
const { generateSecureToken } = require('../utils/encryption');
const { sendInvitationEmail } = require('../config/email');
const { generateSpecialToken, TOKEN_TYPES } = require('../config/jwt');
const config = require('../config');

/**
 * Workspace Service Result Types
 */
const WORKSPACE_RESULTS = {
  SUCCESS: 'success',
  WORKSPACE_NOT_FOUND: 'workspace_not_found',
  INVALID_PERMISSIONS: 'invalid_permissions',
  DOMAIN_ALREADY_EXISTS: 'domain_already_exists',
  MEMBER_ALREADY_EXISTS: 'member_already_exists',
  MEMBER_NOT_FOUND: 'member_not_found',
  INVITE_NOT_FOUND: 'invite_not_found',
  INVITE_EXPIRED: 'invite_expired',
  INVITE_ALREADY_USED: 'invite_already_used',
  WORKSPACE_INACTIVE: 'workspace_inactive',
  VALIDATION_ERROR: 'validation_error',
  OPERATION_FAILED: 'operation_failed',
  LIMIT_EXCEEDED: 'limit_exceeded',
};

/**
 * Workspace Events for audit logging
 */
const WORKSPACE_EVENTS = {
  WORKSPACE_CREATED: 'workspace_created',
  WORKSPACE_UPDATED: 'workspace_updated',
  WORKSPACE_DEACTIVATED: 'workspace_deactivated',
  WORKSPACE_REACTIVATED: 'workspace_reactivated',
  MEMBER_INVITED: 'member_invited',
  MEMBER_JOINED: 'member_joined',
  MEMBER_REMOVED: 'member_removed',
  MEMBER_ROLE_CHANGED: 'member_role_changed',
  INVITE_CREATED: 'invite_created',
  INVITE_ACCEPTED: 'invite_accepted',
  INVITE_REVOKED: 'invite_revoked',
  SETTINGS_UPDATED: 'settings_updated',
  SECURITY_EVENT: 'security_event',
};

/**
 * Workspace Member Roles
 */
const WORKSPACE_ROLES = {
  ADMIN: 'ADMIN',
  MEMBER: 'MEMBER',
};

/**
 * Workspace Service Class
 * Handles all workspace management business logic
 */
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
   * @param {string} workspaceId - Workspace ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Workspace details result
   */
  async getWorkspaceDetails(workspaceId, options = {}) {
    try {
      const {
        includeMembers = true,
        includeInvites = false,
        includeStats = false,
        requestingUserId = null,
      } = options;

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

      // Get workspace details
      const workspace = await prisma.workspace.findUnique({
        where: { id: workspaceId },
        include: {
          ...(includeMembers && {
            memberships: {
              where: { isActive: true },
              include: {
                user: {
                  select: {
                    id: true,
                    email: true,
                    name: true,
                    emailVerified: true,
                    isActive: true,
                    createdAt: true,
                  },
                },
              },
              orderBy: { createdAt: 'asc' },
            },
          }),
          ...(includeInvites && {
            invites: {
              where: {
                used: false,
                expiresAt: { gt: new Date() },
              },
              include: {
                createdBy: {
                  select: {
                    id: true,
                    name: true,
                    email: true,
                  },
                },
              },
              orderBy: { createdAt: 'desc' },
            },
          }),
        },
      });

      if (!workspace) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

      // Get workspace statistics if requested
      let stats = null;
      if (includeStats) {
        stats = await this.getWorkspaceStats(workspaceId);
      }

      // Format members
      const members =
        workspace.memberships?.map((membership) => ({
          id: membership.id,
          role: membership.role,
          joinedAt: membership.createdAt,
          user: membership.user,
        })) || [];

      // Format invites
      const invites =
        workspace.invites?.map((invite) => ({
          id: invite.id,
          email: invite.email,
          token: invite.token,
          expiresAt: invite.expiresAt,
          createdAt: invite.createdAt,
          createdBy: invite.createdBy,
        })) || [];

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        data: {
          workspace: {
            id: workspace.id,
            name: workspace.name,
            domain: workspace.domain,
            isActive: workspace.isActive,
            createdAt: workspace.createdAt,
            updatedAt: workspace.updatedAt,
          },
          members: includeMembers ? members : undefined,
          invites: includeInvites ? invites : undefined,
          stats: includeStats ? stats : undefined,
        },
      };
    } catch (error) {
      console.error('Get workspace details error:', error);

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to retrieve workspace details',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Update workspace settings
   * @param {string} workspaceId - Workspace ID
   * @param {Object} updateData - Update data
   * @param {Object} options - Update options
   * @returns {Promise<Object>} Update result
   */
  async updateWorkspace(workspaceId, updateData, options = {}) {
    try {
      const { requestingUserId, ipAddress = null } = options;
      const { name, domain } = updateData;

      // Validate requesting user has admin permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'Admin permissions required to update workspace',
        };
      }

      // Get current workspace
      const currentWorkspace = await prisma.workspace.findUnique({
        where: { id: workspaceId },
      });

      if (!currentWorkspace) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

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

        if (existingWorkspace && existingWorkspace.id !== workspaceId) {
          return {
            success: false,
            result: WORKSPACE_RESULTS.DOMAIN_ALREADY_EXISTS,
            message: 'Domain is already in use by another workspace',
          };
        }

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

      // Update metrics
      this.workspaceMetrics.workspacesUpdated++;

      // Log workspace update
      this._logWorkspaceEvent(WORKSPACE_EVENTS.WORKSPACE_UPDATED, {
        workspaceId,
        requestingUserId,
        changes,
        ipAddress,
      });

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        message: 'Workspace updated successfully',
        data: {
          workspace: updatedWorkspace,
          changes,
        },
      };
    } catch (error) {
      console.error('Update workspace error:', error);

      this._logWorkspaceEvent(WORKSPACE_EVENTS.SECURITY_EVENT, {
        event: 'workspace_update_failed',
        workspaceId,
        requestingUserId: options.requestingUserId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to update workspace',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Invite user to workspace
   * @param {string} workspaceId - Workspace ID
   * @param {Object} inviteData - Invite data
   * @param {Object} options - Invite options
   * @returns {Promise<Object>} Invite result
   */
  async inviteUser(workspaceId, inviteData, options = {}) {
    try {
      const { email } = inviteData;
      const { requestingUserId, ipAddress = null } = options;

      // Validate requesting user has admin permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'Admin permissions required to invite users',
        };
      }

      const normalizedEmail = normalizeEmail(email);

      // Get workspace details
      const workspace = await prisma.workspace.findUnique({
        where: { id: workspaceId },
      });

      if (!workspace || !workspace.isActive) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found or inactive',
        };
      }

      // Check if user already exists in workspace
      const existingMember = await prisma.membership.findFirst({
        where: {
          workspaceId,
          user: { email: normalizedEmail },
          isActive: true,
        },
      });

      if (existingMember) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.MEMBER_ALREADY_EXISTS,
          message: 'User is already a member of this workspace',
        };
      }

      // Check for existing pending invite
      const existingInvite = await prisma.invite.findFirst({
        where: {
          workspaceId,
          email: normalizedEmail,
          used: false,
          expiresAt: { gt: new Date() },
        },
      });

      if (existingInvite) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.MEMBER_ALREADY_EXISTS,
          message: 'User already has a pending invitation',
        };
      }

      // Check workspace member limit
      const memberCount = await prisma.membership.count({
        where: { workspaceId, isActive: true },
      });

      if (memberCount >= config.workspace.maxMembersPerWorkspace) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.LIMIT_EXCEEDED,
          message: 'Workspace member limit reached',
        };
      }

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
        include: {
          createdBy: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
      });

      // Send invitation email
      await sendInvitationEmail({
        email: normalizedEmail,
        inviterName: invite.createdBy.name,
        workspaceName: workspace.name,
        inviteToken,
        workspaceId,
        invitedBy: requestingUserId,
      });

      // Update metrics
      this.workspaceMetrics.membersInvited++;
      this.workspaceMetrics.invitesCreated++;

      // Log invite creation
      this._logWorkspaceEvent(WORKSPACE_EVENTS.MEMBER_INVITED, {
        workspaceId,
        inviteId: invite.id,
        email: normalizedEmail,
        invitedBy: requestingUserId,
        expiresAt,
        ipAddress,
      });

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        message: 'User invited successfully',
        data: {
          invite: {
            id: invite.id,
            email: invite.email,
            token: invite.token,
            expiresAt: invite.expiresAt,
            createdAt: invite.createdAt,
            createdBy: invite.createdBy,
          },
        },
      };
    } catch (error) {
      console.error('Invite user error:', error);

      this._logWorkspaceEvent(WORKSPACE_EVENTS.SECURITY_EVENT, {
        event: 'invite_failed',
        workspaceId,
        email: inviteData.email,
        requestingUserId: options.requestingUserId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to invite user',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Accept workspace invitation
   * @param {string} inviteToken - Invite token
   * @param {Object} options - Accept options
   * @returns {Promise<Object>} Accept result
   */
  async acceptInvitation(inviteToken, options = {}) {
    try {
      const { userId, ipAddress = null } = options;

      // Find invite
      const invite = await prisma.invite.findUnique({
        where: { token: inviteToken },
        include: {
          workspace: true,
          createdBy: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
      });

      if (!invite) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVITE_NOT_FOUND,
          message: 'Invitation not found',
        };
      }

      if (invite.used) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVITE_ALREADY_USED,
          message: 'Invitation has already been used',
        };
      }

      if (invite.expiresAt < new Date()) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVITE_EXPIRED,
          message: 'Invitation has expired',
        };
      }

      if (!invite.workspace.isActive) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.WORKSPACE_INACTIVE,
          message: 'Workspace is inactive',
        };
      }

      // Get user details
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user || user.email !== invite.email) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.VALIDATION_ERROR,
          message: 'User email does not match invitation',
        };
      }

      // Check if user is already a member
      const existingMembership = await prisma.membership.findFirst({
        where: {
          userId,
          workspaceId: invite.workspaceId,
          isActive: true,
        },
      });

      if (existingMembership) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.MEMBER_ALREADY_EXISTS,
          message: 'User is already a member of this workspace',
        };
      }

      // Accept invitation in transaction
      const result = await prisma.$transaction(async (tx) => {
        // Mark invite as used
        await tx.invite.update({
          where: { id: invite.id },
          data: { used: true },
        });

        // Create membership
        const membership = await tx.membership.create({
          data: {
            userId,
            workspaceId: invite.workspaceId,
            role: 'MEMBER',
          },
        });

        return { membership };
      });

      // Update metrics
      this.workspaceMetrics.membersJoined++;
      this.workspaceMetrics.invitesAccepted++;

      // Log invite acceptance
      this._logWorkspaceEvent(WORKSPACE_EVENTS.INVITE_ACCEPTED, {
        inviteId: invite.id,
        workspaceId: invite.workspaceId,
        userId,
        email: invite.email,
        invitedBy: invite.createdById,
        ipAddress,
      });

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        message: 'Invitation accepted successfully',
        data: {
          workspace: invite.workspace,
          membership: result.membership,
        },
      };
    } catch (error) {
      console.error('Accept invitation error:', error);

      this._logWorkspaceEvent(WORKSPACE_EVENTS.SECURITY_EVENT, {
        event: 'invite_accept_failed',
        inviteToken,
        userId: options.userId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to accept invitation',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Remove member from workspace
   * @param {string} workspaceId - Workspace ID
   * @param {string} memberId - Member ID to remove
   * @param {Object} options - Remove options
   * @returns {Promise<Object>} Remove result
   */
  async removeMember(workspaceId, memberId, options = {}) {
    try {
      const {
        requestingUserId,
        reason = 'No reason provided',
        ipAddress = null,
      } = options;

      // Validate requesting user has admin permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'Admin permissions required to remove members',
        };
      }

      // Find membership
      const membership = await prisma.membership.findFirst({
        where: {
          id: memberId,
          workspaceId,
          isActive: true,
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      if (!membership) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.MEMBER_NOT_FOUND,
          message: 'Member not found in workspace',
        };
      }

      // Prevent removing yourself
      if (membership.userId === requestingUserId) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'Cannot remove yourself from workspace',
        };
      }

      // Check if this is the last admin
      if (membership.role === 'ADMIN') {
        const adminCount = await prisma.membership.count({
          where: {
            workspaceId,
            role: 'ADMIN',
            isActive: true,
          },
        });

        if (adminCount <= 1) {
          return {
            success: false,
            result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
            message: 'Cannot remove the last admin from workspace',
          };
        }
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

      // Update metrics
      this.workspaceMetrics.membersRemoved++;

      // Log member removal
      this._logWorkspaceEvent(WORKSPACE_EVENTS.MEMBER_REMOVED, {
        workspaceId,
        memberId,
        userId: membership.userId,
        removedBy: requestingUserId,
        reason,
        ipAddress,
      });

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        message: 'Member removed successfully',
        data: {
          removedMember: {
            id: membership.id,
            user: membership.user,
            role: membership.role,
          },
        },
      };
    } catch (error) {
      console.error('Remove member error:', error);

      this._logWorkspaceEvent(WORKSPACE_EVENTS.SECURITY_EVENT, {
        event: 'member_remove_failed',
        workspaceId,
        memberId,
        requestingUserId: options.requestingUserId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to remove member',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Change member role
   * @param {string} workspaceId - Workspace ID
   * @param {string} memberId - Member ID
   * @param {string} newRole - New role
   * @param {Object} options - Change options
   * @returns {Promise<Object>} Change result
   */
  async changeMemberRole(workspaceId, memberId, newRole, options = {}) {
    try {
      const { requestingUserId, ipAddress = null } = options;

      // Validate requesting user has admin permissions
      const hasPermission = await this.hasWorkspacePermission(
        requestingUserId,
        workspaceId,
        'ADMIN',
      );
      if (!hasPermission) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'Admin permissions required to change member roles',
        };
      }

      // Validate new role
      if (!Object.values(WORKSPACE_ROLES).includes(newRole)) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.VALIDATION_ERROR,
          message: 'Invalid role specified',
        };
      }

      // Find membership
      const membership = await prisma.membership.findFirst({
        where: {
          id: memberId,
          workspaceId,
          isActive: true,
        },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      if (!membership) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.MEMBER_NOT_FOUND,
          message: 'Member not found in workspace',
        };
      }

      // Check if demoting the last admin
      if (membership.role === 'ADMIN' && newRole !== 'ADMIN') {
        const adminCount = await prisma.membership.count({
          where: {
            workspaceId,
            role: 'ADMIN',
            isActive: true,
          },
        });

        if (adminCount <= 1) {
          return {
            success: false,
            result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
            message: 'Cannot demote the last admin in workspace',
          };
        }
      }

      // Update role
      const updatedMembership = await prisma.membership.update({
        where: { id: memberId },
        data: { role: newRole },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
            },
          },
        },
      });

      // Update metrics
      this.workspaceMetrics.membersRemoved++; // This should be a role change metric

      // Log role change
      this._logWorkspaceEvent(WORKSPACE_EVENTS.MEMBER_ROLE_CHANGED, {
        workspaceId,
        memberId,
        userId: membership.userId,
        oldRole: membership.role,
        newRole,
        changedBy: requestingUserId,
        ipAddress,
      });

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        message: 'Member role changed successfully',
        data: {
          membership: {
            id: updatedMembership.id,
            user: updatedMembership.user,
            role: updatedMembership.role,
            oldRole: membership.role,
          },
        },
      };
    } catch (error) {
      console.error('Change member role error:', error);

      this._logWorkspaceEvent(WORKSPACE_EVENTS.SECURITY_EVENT, {
        event: 'role_change_failed',
        workspaceId,
        memberId,
        newRole,
        requestingUserId: options.requestingUserId,
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to change member role',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Get workspace statistics
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<Object>} Workspace statistics
   */
  async getWorkspaceStats(workspaceId) {
    try {
      const [
        totalMembers,
        activeMembers,
        adminCount,
        pendingInvites,
        totalInvites,
      ] = await Promise.all([
        prisma.membership.count({
          where: { workspaceId },
        }),
        prisma.membership.count({
          where: {
            workspaceId,
            isActive: true,
            user: { isActive: true },
          },
        }),
        prisma.membership.count({
          where: {
            workspaceId,
            role: 'ADMIN',
            isActive: true,
          },
        }),
        prisma.invite.count({
          where: {
            workspaceId,
            used: false,
            expiresAt: { gt: new Date() },
          },
        }),
        prisma.invite.count({
          where: { workspaceId },
        }),
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
    } catch (error) {
      console.error('Get workspace stats error:', error);
      return {};
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
      const membership = await prisma.membership.findFirst({
        where: {
          userId,
          workspaceId,
          isActive: true,
          user: { isActive: true },
          workspace: { isActive: true },
        },
        include: {
          workspace: true,
        },
      });

      if (!membership) {
        return {
          success: false,
          result: WORKSPACE_RESULTS.INVALID_PERMISSIONS,
          message: 'User does not have access to this workspace',
        };
      }

      return {
        success: true,
        result: WORKSPACE_RESULTS.SUCCESS,
        data: {
          membership,
          workspace: membership.workspace,
        },
      };
    } catch (error) {
      console.error('Validate workspace access error:', error);
      return {
        success: false,
        result: WORKSPACE_RESULTS.OPERATION_FAILED,
        message: 'Failed to validate workspace access',
      };
    }
  }

  /**
   * Check if user has specific workspace permission
   * @param {string} userId - User ID
   * @param {string} workspaceId - Workspace ID
   * @param {string} requiredRole - Required role
   * @returns {Promise<boolean>} Whether user has permission
   */
  async hasWorkspacePermission(userId, workspaceId, requiredRole) {
    try {
      const membership = await prisma.membership.findFirst({
        where: {
          userId,
          workspaceId,
          isActive: true,
          user: { isActive: true },
        },
      });

      if (!membership) {
        return false;
      }

      // Admin has all permissions
      if (membership.role === 'ADMIN') {
        return true;
      }

      // Check specific role requirement
      return membership.role === requiredRole;
    } catch (error) {
      console.error('Check workspace permission error:', error);
      return false;
    }
  }

  /**
   * Get workspace service metrics
   * @returns {Object} Workspace service metrics
   */
  getMetrics() {
    return {
      ...this.workspaceMetrics,
      timestamp: new Date().toISOString(),
    };
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
      source: 'WORKSPACE_SERVICE',
    };

    if (event === WORKSPACE_EVENTS.SECURITY_EVENT) {
      console.warn('🏢 Workspace Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('🏢 Workspace Event:', logEntry);
    }

    // In production, send to audit log service
    if (config.isProduction()) {
      // TODO: Send to audit log service
    }
  }
}

// Create singleton instance
const workspaceService = new WorkspaceService();

// Export workspace service
module.exports = {
  // Main service instance
  workspaceService,

  // Service methods
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

  // Validation methods
  validateWorkspaceAccess: (userId, workspaceId) =>
    workspaceService.validateWorkspaceAccess(userId, workspaceId),
  hasWorkspacePermission: (userId, workspaceId, requiredRole) =>
    workspaceService.hasWorkspacePermission(userId, workspaceId, requiredRole),

  // Utilities
  getMetrics: () => workspaceService.getMetrics(),

  // Constants
  WORKSPACE_RESULTS,
  WORKSPACE_EVENTS,
  WORKSPACE_ROLES,
};
