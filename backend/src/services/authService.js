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

const {
  generateTokenPair,
  generateSpecialToken,
  TOKEN_TYPES,
  validateToken,
} = require('../config/jwt');
const { client: prisma } = require('../config/database');
const {
  extractDomain,
  isPersonalEmail,
  normalizeEmail,
} = require('../utils/domain');
const { hashPassword, comparePassword } = require('../utils/encryption');
const {
  getOrCreateWorkspace,
  assignMembershipRole,
} = require('../utils/workspace');
const { sendUserEmail } = require('../utils/email');
const logger = require('../utils/logger');
const { ApiError, ERROR_CODES, HTTP_STATUS } = require('../utils/apiError');
const { ApiResponse } = require('../utils/apiResponse');
const { asyncHandler } = require('../utils/asyncHandler');
const { InputValidator } = require('../validations/input');
const { BusinessValidator } = require('../validations/business');
const { SecurityValidator } = require('../validations/security');
const config = require('../config');

// Initialize validators
const inputValidator = new InputValidator();
const businessValidator = new BusinessValidator();
const securityValidator = new SecurityValidator();

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
   * Register a new user (local)
   * @param {Object} userData - { email, password, name }
   * @returns {Promise<Object>} Registration result (user, workspace, tokens)
   */
  async registerUser({ email, password, name }) {
    // Validate input (add your validation logic here)
    // Hash password
    const passwordHash = await hashPassword(password);
    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        name,
        passwordHash,
      },
    });
    // Create workspace (example logic, adjust as needed)
    const workspace = await prisma.workspace.create({
      data: {
        name: `${name}'s Workspace`,
        domain: email.split('@')[1],
      },
    });
    // Create membership
    await prisma.membership.create({
      data: {
        userId: user.id,
        workspaceId: workspace.id,
        role: 'ADMIN',
      },
    });
    // Generate tokens (implement as needed)
    const tokens = await this.generateAuthTokens({
      ...user,
      memberships: [{ workspace, role: 'ADMIN' }],
    });
    // Return result
    return { user, workspace, tokens };
  }

  /**
   * Authenticate user (local login)
   * @param {Object} credentials - { email, password }
   * @returns {Promise<Object>} Login result (user, workspace, tokens)
   */
  async authenticateUser({ email, password }) {
    // Find user
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
      throw new ApiError(
        401,
        'Invalid credentials',
        ERROR_CODES.INVALID_CREDENTIALS,
      );
    // Check password
    const valid = await comparePassword(password, user.passwordHash);
    if (!valid)
      throw new ApiError(
        401,
        'Invalid credentials',
        ERROR_CODES.INVALID_CREDENTIALS,
      );
    // Get membership and workspace
    const membership = await prisma.membership.findFirst({
      where: { userId: user.id },
      include: { workspace: true },
    });
    if (!membership)
      throw new ApiError(
        403,
        'No workspace access',
        ERROR_CODES.NO_WORKSPACE_ACCESS,
      );
    // Generate tokens
    const tokens = await this.generateAuthTokens({
      ...user,
      memberships: [{ workspace: membership.workspace, role: membership.role }],
    });
    // Return result
    return {
      user,
      workspace: membership.workspace,
      tokens,
    };
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} options - Refresh options
   * @returns {Promise<Object>} Refresh result
   */
  async refreshAccessToken(refreshToken, options = {}) {
    return asyncHandler(async () => {
      const { ipAddress = null } = options;

      if (!refreshToken) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Refresh token is required',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'refreshToken' },
        );
      }

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
        throw new ApiError(
          ERROR_CODES.TOKEN_INVALID,
          'Invalid or expired refresh token',
          HTTP_STATUS.UNAUTHORIZED,
        );
      }

      const user = session.user;
      const activeMembership = user.memberships.find(
        (m) => m.workspace.isActive,
      );

      if (!user.isActive || !activeMembership) {
        throw new ApiError(
          ERROR_CODES.ACCOUNT_INACTIVE,
          'User account or workspace is inactive',
          HTTP_STATUS.FORBIDDEN,
        );
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

      return ApiResponse.success('Token refreshed successfully', { tokens });
    })();
  }

  /**
   * Logout user and revoke tokens
   * @param {string} refreshToken - Refresh token to revoke
   * @param {Object} options - Logout options
   * @returns {Promise<Object>} Logout result
   */
  async logoutUser(refreshToken, options = {}) {
    return asyncHandler(async () => {
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

      return ApiResponse.success('Logout successful');
    })();
  }

  /**
   * Verify email address
   * @param {string} verificationToken - Email verification token
   * @returns {Promise<Object>} Verification result
   */
  async verifyEmail(verificationToken) {
    return asyncHandler(async () => {
      if (!verificationToken) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Verification token is required',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'verificationToken' },
        );
      }

      // Validate verification token
      const decoded = validateToken(verificationToken, {
        requiredType: TOKEN_TYPES.EMAIL_VERIFICATION,
      });

      if (!decoded) {
        throw new ApiError(
          ERROR_CODES.TOKEN_INVALID,
          'Invalid verification token',
          HTTP_STATUS.BAD_REQUEST,
        );
      }

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
        await sendUserEmail('welcome', {
          user: user,
          workspace: user.memberships[0].workspace,
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

      return ApiResponse.success('Email verified successfully', {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          emailVerified: user.emailVerified,
        },
      });
    })();
  }

  /**
   * Request password reset
   * @param {string} email - User email
   * @param {Object} options - Reset options
   * @returns {Promise<Object>} Reset request result
   */
  async requestPasswordReset(email, options = {}) {
    return asyncHandler(async () => {
      const { ipAddress = null } = options;

      // Validate email
      const emailValidation = inputValidator.validateEmail(email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email' },
        );
      }

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
        return ApiResponse.success(
          'If an account with this email exists, a password reset link has been sent.',
        );
      }

      // Generate password reset token
      const resetToken = generateSpecialToken(
        { userId: user.id, email: normalizedEmail },
        TOKEN_TYPES.PASSWORD_RESET,
        '1h',
      );

      // Send password reset email
      await sendUserEmail('passwordReset', {
        user: user,
        resetToken: resetToken,
      });

      // Update metrics
      this.authMetrics.passwordResets++;

      // Log password reset request
      this._logAuthEvent(AUTH_EVENTS.PASSWORD_RESET_REQUESTED, {
        userId: user.id,
        email: normalizedEmail,
        ipAddress,
      });

      return ApiResponse.success(
        'If an account with this email exists, a password reset link has been sent.',
      );
    })();
  }

  /**
   * Reset password using reset token
   * @param {string} resetToken - Password reset token
   * @param {string} newPassword - New password
   * @param {Object} options - Reset options
   * @returns {Promise<Object>} Reset result
   */
  async resetPassword(resetToken, newPassword, options = {}) {
    return asyncHandler(async () => {
      const { ipAddress = null } = options;

      if (!resetToken) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Reset token is required',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'resetToken' },
        );
      }

      // Validate new password
      const passwordValidation = inputValidator.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Password does not meet requirements',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'newPassword', details: passwordValidation.errors },
        );
      }

      // Validate reset token
      const decoded = validateToken(resetToken, {
        requiredType: TOKEN_TYPES.PASSWORD_RESET,
      });

      if (!decoded) {
        throw new ApiError(
          ERROR_CODES.TOKEN_INVALID,
          'Invalid or expired reset token',
          HTTP_STATUS.BAD_REQUEST,
        );
      }

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

      return ApiResponse.success('Password reset successfully');
    })();
  }

  /**
   * Generate authentication tokens for a user
   * @param {Object} user - User object with workspace membership
   * @param {Object} options - Token generation options
   * @returns {Promise<Object>} Access and refresh tokens
   */
  async generateAuthTokens(user, options = {}) {
    try {
      const { ipAddress, userAgent, deviceId } = options;

      // Validate user has workspace membership
      if (!user.memberships || user.memberships.length === 0) {
        throw new ApiError(
          403,
          'No workspace access',
          ERROR_CODES.NO_WORKSPACE_ACCESS,
        );
      }

      // Get primary workspace (first active membership)
      const primaryMembership = user.memberships[0];
      const workspace = primaryMembership.workspace;

      // Prepare token payload
      const tokenPayload = {
        sub: user.id,
        email: user.email,
        name: user.name,
        workspace: {
          id: workspace.id,
          name: workspace.name,
          domain: workspace.domain,
          role: primaryMembership.role,
        },
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          emailVerified: user.emailVerified,
          role: primaryMembership.role,
        },
      };

      // Generate token pair
      const tokens = await generateTokenPair(tokenPayload, {
        ipAddress,
        deviceId,
        userAgent,
      });

      logger.info('Auth tokens generated', {
        userId: user.id,
        workspaceId: workspace.id,
        tokenType: 'token_pair',
      });

      return tokens;
    } catch (error) {
      logger.error('Failed to generate auth tokens', {
        userId: user?.id,
        error: error.message,
      });
      throw error;
    }
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
      logger.warn('🔐 Auth Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      logger.debug('🔐 Auth Event:', logEntry);
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
  registerUser: (userData) => authService.registerUser(userData),
  authenticateUser: (credentials) => authService.authenticateUser(credentials),
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
  generateAuthTokens: (user, options) =>
    authService.generateAuthTokens(user, options),

  // Utilities
  getMetrics: () => authService.getMetrics(),

  // Constants
  AUTH_EVENTS,
};
