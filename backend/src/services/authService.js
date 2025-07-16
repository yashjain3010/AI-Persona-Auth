/**
 * Authentication Service Module
 *
 * This service provides comprehensive authentication business logic for
 * multi-tenant SaaS applications with enterprise security requirements:
 *
 * Features:
 * - User registration with automatic workspace assignment
 * - Multi-factor authentication support
 * - OAuth integration (Google, Microsoft, etc.)
 * - Domain-based workspace auto-assignment
 * - Session management and token refresh
 * - Security event logging and monitoring
 * - Email verification and password reset flows
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const {
  generateTokenPair,
  generateSpecialToken,
  TOKEN_TYPES,
} = require('../config/jwt');
const { client: prisma } = require('../config/database');
const {
  extractDomain,
  isPersonalEmail,
  normalizeEmail,
} = require('../utils/domain');
const {
  hashPassword,
  comparePassword,
  generateSecureToken,
} = require('../utils/encryption');
const {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
} = require('../config/email');
const config = require('../config');

/**
 * Authentication Result Types
 */
const AUTH_RESULTS = {
  SUCCESS: 'success',
  INVALID_CREDENTIALS: 'invalid_credentials',
  USER_NOT_FOUND: 'user_not_found',
  USER_EXISTS: 'user_exists',
  EMAIL_NOT_VERIFIED: 'email_not_verified',
  ACCOUNT_INACTIVE: 'account_inactive',
  PERSONAL_EMAIL_BLOCKED: 'personal_email_blocked',
  WORKSPACE_CREATION_FAILED: 'workspace_creation_failed',
  TOKEN_INVALID: 'token_invalid',
  TOKEN_EXPIRED: 'token_expired',
  PASSWORD_RESET_FAILED: 'password_reset_failed',
};

/**
 * Authentication Events for audit logging
 */
const AUTH_EVENTS = {
  USER_REGISTERED: 'user_registered',
  USER_LOGIN: 'user_login',
  USER_LOGOUT: 'user_logout',
  TOKEN_REFRESHED: 'token_refreshed',
  EMAIL_VERIFIED: 'email_verified',
  PASSWORD_RESET_REQUESTED: 'password_reset_requested',
  PASSWORD_RESET_COMPLETED: 'password_reset_completed',
  WORKSPACE_CREATED: 'workspace_created',
  OAUTH_LOGIN: 'oauth_login',
  SECURITY_EVENT: 'security_event',
};

/**
 * Authentication Service Class
 * Handles all authentication business logic
 */
class AuthenticationService {
  constructor() {
    this.authMetrics = {
      registrations: 0,
      logins: 0,
      logouts: 0,
      tokenRefreshes: 0,
      emailVerifications: 0,
      passwordResets: 0,
      workspacesCreated: 0,
      failedAttempts: 0,
      securityEvents: 0,
    };
  }

  /**
   * Register a new user with automatic workspace assignment
   * @param {Object} userData - User registration data
   * @param {Object} options - Registration options
   * @returns {Promise<Object>} Registration result
   */
  async registerUser(userData, options = {}) {
    try {
      const { email, password, name, inviteToken = null } = userData;
      const {
        skipEmailVerification = false,
        deviceId = null,
        ipAddress = null,
      } = options;

      // Normalize and validate email
      const normalizedEmail = normalizeEmail(email);
      const domain = extractDomain(normalizedEmail);

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (existingUser) {
        return {
          success: false,
          result: AUTH_RESULTS.USER_EXISTS,
          message: 'User already exists with this email',
        };
      }

      // Handle personal email domains
      if (isPersonalEmail(normalizedEmail) && !inviteToken) {
        return {
          success: false,
          result: AUTH_RESULTS.PERSONAL_EMAIL_BLOCKED,
          message:
            'Personal email domains are not allowed. Please use your company email or accept an invitation.',
        };
      }

      // Hash password
      const passwordHash = await hashPassword(password);

      // Create user and workspace in transaction
      const result = await prisma.$transaction(async (tx) => {
        let workspace;
        let isFirstUser = false;

        if (inviteToken) {
          // Handle invitation-based registration
          const invite = await tx.invite.findUnique({
            where: { token: inviteToken },
            include: { workspace: true },
          });

          if (!invite || invite.used || invite.expiresAt < new Date()) {
            throw new Error('Invalid or expired invitation');
          }

          if (invite.email !== normalizedEmail) {
            throw new Error('Email does not match invitation');
          }

          workspace = invite.workspace;

          // Mark invite as used
          await tx.invite.update({
            where: { id: invite.id },
            data: { used: true },
          });
        } else {
          // Handle domain-based workspace assignment
          workspace = await tx.workspace.findUnique({
            where: { domain },
          });

          if (!workspace) {
            // Create new workspace
            workspace = await tx.workspace.create({
              data: {
                name: this._generateWorkspaceName(domain),
                domain,
              },
            });
            isFirstUser = true;
            this.authMetrics.workspacesCreated++;
          }
        }

        // Create user
        const user = await tx.user.create({
          data: {
            email: normalizedEmail,
            name,
            passwordHash,
            emailVerified: skipEmailVerification,
          },
        });

        // Create membership
        const existingMemberships = await tx.membership.count({
          where: { workspaceId: workspace.id },
        });

        const role =
          isFirstUser || existingMemberships === 0 ? 'ADMIN' : 'MEMBER';

        const membership = await tx.membership.create({
          data: {
            userId: user.id,
            workspaceId: workspace.id,
            role,
          },
        });

        return { user, workspace, membership, role, isFirstUser };
      });

      // Generate tokens
      const tokens = generateTokenPair({
        userId: result.user.id,
        email: result.user.email,
        workspaceId: result.workspace.id,
        role: result.role,
        deviceId,
        ipAddress,
      });

      // Store refresh token session
      await prisma.session.create({
        data: {
          userId: result.user.id,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      // Send verification email if needed
      if (!skipEmailVerification) {
        const verificationToken = generateSpecialToken(
          { userId: result.user.id, email: normalizedEmail },
          TOKEN_TYPES.EMAIL_VERIFICATION,
          '24h',
        );

        await sendVerificationEmail({
          email: normalizedEmail,
          name,
          verificationToken,
          workspaceName: result.workspace.name,
          userId: result.user.id,
          workspaceId: result.workspace.id,
        });
      } else {
        // Send welcome email
        await sendWelcomeEmail({
          email: normalizedEmail,
          name,
          workspaceName: result.workspace.name,
          workspaceId: result.workspace.id,
          userId: result.user.id,
        });
      }

      // Update metrics
      this.authMetrics.registrations++;

      // Log registration event
      this._logAuthEvent(AUTH_EVENTS.USER_REGISTERED, {
        userId: result.user.id,
        email: normalizedEmail,
        workspaceId: result.workspace.id,
        role: result.role,
        isFirstUser: result.isFirstUser,
        domain,
        ipAddress,
        deviceId,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'User registered successfully',
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            name: result.user.name,
            emailVerified: result.user.emailVerified,
          },
          workspace: {
            id: result.workspace.id,
            name: result.workspace.name,
            domain: result.workspace.domain,
          },
          role: result.role,
          tokens: skipEmailVerification ? tokens : null,
          requiresEmailVerification: !skipEmailVerification,
        },
      };
    } catch (error) {
      console.error('User registration error:', error);
      this.authMetrics.failedAttempts++;

      this._logAuthEvent(AUTH_EVENTS.SECURITY_EVENT, {
        event: 'registration_failed',
        error: error.message,
        email: userData.email,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: AUTH_RESULTS.WORKSPACE_CREATION_FAILED,
        message: 'Registration failed. Please try again.',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Authenticate user login
   * @param {Object} credentials - Login credentials
   * @param {Object} options - Login options
   * @returns {Promise<Object>} Authentication result
   */
  async authenticateUser(credentials, options = {}) {
    try {
      const { email, password } = credentials;
      const { deviceId = null, ipAddress = null } = options;

      const normalizedEmail = normalizeEmail(email);

      // Find user with workspace memberships
      const user = await prisma.user.findUnique({
        where: { email: normalizedEmail },
        include: {
          memberships: {
            where: { isActive: true },
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
        this.authMetrics.failedAttempts++;
        return {
          success: false,
          result: AUTH_RESULTS.USER_NOT_FOUND,
          message: 'Invalid email or password',
        };
      }

      // Check if user has password (OAuth-only users don't have passwords)
      if (!user.passwordHash) {
        this.authMetrics.failedAttempts++;
        return {
          success: false,
          result: AUTH_RESULTS.INVALID_CREDENTIALS,
          message: 'Please sign in with your OAuth provider',
        };
      }

      // Verify password
      const isValidPassword = await comparePassword(
        password,
        user.passwordHash,
      );
      if (!isValidPassword) {
        this.authMetrics.failedAttempts++;
        return {
          success: false,
          result: AUTH_RESULTS.INVALID_CREDENTIALS,
          message: 'Invalid email or password',
        };
      }

      // Check if email is verified
      if (!user.emailVerified) {
        return {
          success: false,
          result: AUTH_RESULTS.EMAIL_NOT_VERIFIED,
          message: 'Please verify your email before signing in',
          data: { userId: user.id, email: user.email },
        };
      }

      // Check if user is active
      if (!user.isActive) {
        return {
          success: false,
          result: AUTH_RESULTS.ACCOUNT_INACTIVE,
          message: 'Your account has been deactivated',
        };
      }

      // Check workspace membership
      const activeMembership = user.memberships.find(
        (m) => m.workspace.isActive,
      );
      if (!activeMembership) {
        return {
          success: false,
          result: AUTH_RESULTS.ACCOUNT_INACTIVE,
          message: 'No active workspace access found',
        };
      }

      // Generate tokens
      const tokens = generateTokenPair({
        userId: user.id,
        email: user.email,
        workspaceId: activeMembership.workspace.id,
        role: activeMembership.role,
        deviceId,
        ipAddress,
      });

      // Store refresh token session
      await prisma.session.create({
        data: {
          userId: user.id,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      // Update metrics
      this.authMetrics.logins++;

      // Log login event
      this._logAuthEvent(AUTH_EVENTS.USER_LOGIN, {
        userId: user.id,
        email: user.email,
        workspaceId: activeMembership.workspace.id,
        role: activeMembership.role,
        ipAddress,
        deviceId,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            emailVerified: user.emailVerified,
          },
          workspace: activeMembership.workspace,
          role: activeMembership.role,
          tokens,
        },
      };
    } catch (error) {
      console.error('User authentication error:', error);
      this.authMetrics.failedAttempts++;

      this._logAuthEvent(AUTH_EVENTS.SECURITY_EVENT, {
        event: 'login_failed',
        error: error.message,
        email: credentials.email,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: AUTH_RESULTS.INVALID_CREDENTIALS,
        message: 'Authentication failed. Please try again.',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} options - Refresh options
   * @returns {Promise<Object>} Refresh result
   */
  async refreshAccessToken(refreshToken, options = {}) {
    try {
      const { ipAddress = null } = options;

      // Find session with refresh token
      const session = await prisma.session.findUnique({
        where: { refreshToken },
        include: {
          user: {
            include: {
              memberships: {
                where: { isActive: true },
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
          },
        },
      });

      if (!session || !session.isActive || session.expiresAt < new Date()) {
        return {
          success: false,
          result: AUTH_RESULTS.TOKEN_INVALID,
          message: 'Invalid or expired refresh token',
        };
      }

      const user = session.user;
      const activeMembership = user.memberships.find(
        (m) => m.workspace.isActive,
      );

      if (!user.isActive || !activeMembership) {
        return {
          success: false,
          result: AUTH_RESULTS.ACCOUNT_INACTIVE,
          message: 'User account or workspace is inactive',
        };
      }

      // Generate new tokens
      const tokens = generateTokenPair({
        userId: user.id,
        email: user.email,
        workspaceId: activeMembership.workspace.id,
        role: activeMembership.role,
        ipAddress,
      });

      // Update session with new refresh token
      await prisma.session.update({
        where: { id: session.id },
        data: {
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      // Update metrics
      this.authMetrics.tokenRefreshes++;

      // Log token refresh event
      this._logAuthEvent(AUTH_EVENTS.TOKEN_REFRESHED, {
        userId: user.id,
        workspaceId: activeMembership.workspace.id,
        ipAddress,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'Token refreshed successfully',
        data: { tokens },
      };
    } catch (error) {
      console.error('Token refresh error:', error);

      this._logAuthEvent(AUTH_EVENTS.SECURITY_EVENT, {
        event: 'token_refresh_failed',
        error: error.message,
        ipAddress: options.ipAddress,
      });

      return {
        success: false,
        result: AUTH_RESULTS.TOKEN_INVALID,
        message: 'Token refresh failed',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Logout user and revoke tokens
   * @param {string} refreshToken - Refresh token to revoke
   * @param {Object} options - Logout options
   * @returns {Promise<Object>} Logout result
   */
  async logoutUser(refreshToken, options = {}) {
    try {
      const { userId = null, ipAddress = null } = options;

      if (refreshToken) {
        // Deactivate session
        await prisma.session.updateMany({
          where: { refreshToken },
          data: { isActive: false },
        });
      }

      // Update metrics
      this.authMetrics.logouts++;

      // Log logout event
      this._logAuthEvent(AUTH_EVENTS.USER_LOGOUT, {
        userId,
        ipAddress,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'Logout successful',
      };
    } catch (error) {
      console.error('Logout error:', error);

      return {
        success: false,
        result: AUTH_RESULTS.TOKEN_INVALID,
        message: 'Logout failed',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Verify email address
   * @param {string} verificationToken - Email verification token
   * @returns {Promise<Object>} Verification result
   */
  async verifyEmail(verificationToken) {
    try {
      // Validate verification token
      const { validateToken } = require('../config/jwt');
      const decoded = validateToken(verificationToken, {
        requiredType: TOKEN_TYPES.EMAIL_VERIFICATION,
      });

      // Update user email verification status
      const user = await prisma.user.update({
        where: { id: decoded.userId },
        data: { emailVerified: true },
        include: {
          memberships: {
            where: { isActive: true },
            include: {
              workspace: true,
            },
          },
        },
      });

      // Send welcome email
      if (user.memberships.length > 0) {
        await sendWelcomeEmail({
          email: user.email,
          name: user.name,
          workspaceName: user.memberships[0].workspace.name,
          workspaceId: user.memberships[0].workspace.id,
          userId: user.id,
        });
      }

      // Update metrics
      this.authMetrics.emailVerifications++;

      // Log email verification event
      this._logAuthEvent(AUTH_EVENTS.EMAIL_VERIFIED, {
        userId: user.id,
        email: user.email,
        workspaceId: user.memberships[0]?.workspace.id,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'Email verified successfully',
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            emailVerified: user.emailVerified,
          },
        },
      };
    } catch (error) {
      console.error('Email verification error:', error);

      return {
        success: false,
        result: AUTH_RESULTS.TOKEN_INVALID,
        message: 'Email verification failed',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Request password reset
   * @param {string} email - User email
   * @param {Object} options - Reset options
   * @returns {Promise<Object>} Reset request result
   */
  async requestPasswordReset(email, options = {}) {
    try {
      const { ipAddress = null } = options;
      const normalizedEmail = normalizeEmail(email);

      // Find user
      const user = await prisma.user.findUnique({
        where: { email: normalizedEmail },
        include: {
          memberships: {
            where: { isActive: true },
            include: {
              workspace: true,
            },
          },
        },
      });

      if (!user) {
        // Don't reveal if user exists or not
        return {
          success: true,
          result: AUTH_RESULTS.SUCCESS,
          message:
            'If an account with this email exists, a password reset link has been sent.',
        };
      }

      // Generate password reset token
      const resetToken = generateSpecialToken(
        { userId: user.id, email: normalizedEmail },
        TOKEN_TYPES.PASSWORD_RESET,
        '1h',
      );

      // Send password reset email
      await sendPasswordResetEmail({
        email: normalizedEmail,
        name: user.name,
        resetToken,
        workspaceName: user.memberships[0]?.workspace.name,
        userId: user.id,
        workspaceId: user.memberships[0]?.workspace.id,
      });

      // Update metrics
      this.authMetrics.passwordResets++;

      // Log password reset request
      this._logAuthEvent(AUTH_EVENTS.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email: normalizedEmail,
        ipAddress,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message:
          'If an account with this email exists, a password reset link has been sent.',
      };
    } catch (error) {
      console.error('Password reset request error:', error);

      return {
        success: false,
        result: AUTH_RESULTS.PASSWORD_RESET_FAILED,
        message: 'Password reset request failed',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Reset password using reset token
   * @param {string} resetToken - Password reset token
   * @param {string} newPassword - New password
   * @param {Object} options - Reset options
   * @returns {Promise<Object>} Reset result
   */
  async resetPassword(resetToken, newPassword, options = {}) {
    try {
      const { ipAddress = null } = options;

      // Validate reset token
      const { validateToken } = require('../config/jwt');
      const decoded = validateToken(resetToken, {
        requiredType: TOKEN_TYPES.PASSWORD_RESET,
      });

      // Hash new password
      const passwordHash = await hashPassword(newPassword);

      // Update user password
      const user = await prisma.user.update({
        where: { id: decoded.userId },
        data: { passwordHash },
      });

      // Revoke all existing sessions
      await prisma.session.updateMany({
        where: { userId: user.id },
        data: { isActive: false },
      });

      // Log password reset completion
      this._logAuthEvent(AUTH_EVENTS.PASSWORD_RESET_COMPLETED, {
        userId: user.id,
        email: user.email,
        ipAddress,
      });

      return {
        success: true,
        result: AUTH_RESULTS.SUCCESS,
        message: 'Password reset successfully',
      };
    } catch (error) {
      console.error('Password reset error:', error);

      return {
        success: false,
        result: AUTH_RESULTS.PASSWORD_RESET_FAILED,
        message: 'Password reset failed',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Generate workspace name from domain
   * @param {string} domain - Email domain
   * @returns {string} Workspace name
   * @private
   */
  _generateWorkspaceName(domain) {
    // Remove common TLD and capitalize
    const name = domain
      .replace(/\.(com|org|net|edu|gov|mil|int)$/, '')
      .split('.')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');

    return name || 'Workspace';
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
      source: 'AUTH_SERVICE',
    };

    if (event === AUTH_EVENTS.SECURITY_EVENT) {
      console.warn('🔐 Auth Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('🔐 Auth Event:', logEntry);
    }

    // In production, send to audit log service
    if (config.isProduction()) {
      // TODO: Send to audit log service
    }
  }
}

// Create singleton instance
const authService = new AuthenticationService();

// Export authentication service
module.exports = {
  // Main service instance
  authService,

  // Service methods
  registerUser: (userData, options) =>
    authService.registerUser(userData, options),
  authenticateUser: (credentials, options) =>
    authService.authenticateUser(credentials, options),
  refreshAccessToken: (refreshToken, options) =>
    authService.refreshAccessToken(refreshToken, options),
  logoutUser: (refreshToken, options) =>
    authService.logoutUser(refreshToken, options),
  verifyEmail: (verificationToken) =>
    authService.verifyEmail(verificationToken),
  requestPasswordReset: (email, options) =>
    authService.requestPasswordReset(email, options),
  resetPassword: (resetToken, newPassword, options) =>
    authService.resetPassword(resetToken, newPassword, options),

  // Utilities
  getMetrics: () => authService.getMetrics(),

  // Constants
  AUTH_RESULTS,
  AUTH_EVENTS,
};
