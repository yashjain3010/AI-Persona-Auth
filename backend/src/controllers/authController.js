/**
 * Authentication Controller Module
 *
 * This controller provides REST API endpoints for authentication operations
 * in multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - User registration and login endpoints
 * - Token refresh and logout functionality
 * - Email verification and password reset flows
 * - OAuth integration endpoints
 * - Comprehensive error handling and validation
 * - Rate limiting and security measures
 * - Audit logging and monitoring
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  authService,
  registerUser,
  authenticateUser,
  refreshAccessToken,
  logoutUser,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
  AUTH_RESULTS,
} = require('../services/authService');
const { emailService } = require('../services/emailService');
const { validateToken } = require('../config/jwt');
const { authenticate } = require('../config/auth');
const config = require('../config');

/**
 * HTTP Status Code Mappings for Authentication Results
 */
const HTTP_STATUS_CODES = {
  [AUTH_RESULTS.SUCCESS]: 200,
  [AUTH_RESULTS.INVALID_CREDENTIALS]: 401,
  [AUTH_RESULTS.USER_NOT_FOUND]: 401,
  [AUTH_RESULTS.USER_EXISTS]: 409,
  [AUTH_RESULTS.EMAIL_NOT_VERIFIED]: 403,
  [AUTH_RESULTS.ACCOUNT_INACTIVE]: 403,
  [AUTH_RESULTS.PERSONAL_EMAIL_BLOCKED]: 403,
  [AUTH_RESULTS.WORKSPACE_CREATION_FAILED]: 500,
  [AUTH_RESULTS.TOKEN_INVALID]: 401,
  [AUTH_RESULTS.TOKEN_EXPIRED]: 401,
  [AUTH_RESULTS.PASSWORD_RESET_FAILED]: 500,
};

/**
 * Authentication Controller Class
 * Handles all authentication HTTP endpoints
 */
class AuthController {
  /**
   * Register new user
   * POST /api/v1/auth/register
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async register(req, res) {
    try {
      const { email, password, name, inviteToken } = req.body;

      // Extract request context
      const options = {
        skipEmailVerification: false,
        deviceId: req.headers['x-device-id'] || null,
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await registerUser(
        {
          email,
          password,
          name,
          inviteToken,
        },
        options,
      );

      // Get appropriate HTTP status code
      const statusCode = result.success
        ? 201
        : HTTP_STATUS_CODES[result.result] || 400;

      // Log registration attempt
      this._logControllerEvent('REGISTER_ATTEMPT', {
        email,
        success: result.success,
        result: result.result,
        hasInviteToken: !!inviteToken,
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
      console.error('Register controller error:', error);

      this._logControllerEvent('REGISTER_ERROR', {
        error: error.message,
        email: req.body?.email,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Registration failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * User login
   * POST /api/v1/auth/login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async login(req, res) {
    try {
      const { email, password } = req.body;

      // Extract request context
      const options = {
        deviceId: req.headers['x-device-id'] || null,
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await authenticateUser(
        {
          email,
          password,
        },
        options,
      );

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 400;

      // Log login attempt
      this._logControllerEvent('LOGIN_ATTEMPT', {
        email,
        success: result.success,
        result: result.result,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Handle email not verified case
      if (result.result === AUTH_RESULTS.EMAIL_NOT_VERIFIED && result.data) {
        // Optionally resend verification email
        const resendVerification = req.body.resendVerification === true;

        if (resendVerification) {
          await emailService.sendEmailVerification(
            {
              userId: result.data.userId,
              email: result.data.email,
              name: 'User', // We don't have name in this context
              workspaceId: null, // Will be determined by service
            },
            { resend: true },
          );
        }
      }

      // Return response
      res.status(statusCode).json({
        success: result.success,
        message: result.message,
        ...(result.data && { data: result.data }),
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Login controller error:', error);

      this._logControllerEvent('LOGIN_ERROR', {
        error: error.message,
        email: req.body?.email,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Login failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Refresh access token
   * POST /api/v1/auth/refresh
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token is required',
        });
      }

      // Extract request context
      const options = {
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await refreshAccessToken(refreshToken, options);

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 400;

      // Log token refresh attempt
      this._logControllerEvent('TOKEN_REFRESH_ATTEMPT', {
        success: result.success,
        result: result.result,
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
      console.error('Refresh token controller error:', error);

      this._logControllerEvent('TOKEN_REFRESH_ERROR', {
        error: error.message,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Token refresh failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * User logout
   * POST /api/v1/auth/logout
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async logout(req, res) {
    try {
      const { refreshToken } = req.body;

      // Extract request context
      const options = {
        userId: req.user?.id || null,
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await logoutUser(refreshToken, options);

      // Log logout attempt
      this._logControllerEvent('LOGOUT_ATTEMPT', {
        userId: req.user?.id,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response (always 200 for logout)
      res.status(200).json({
        success: result.success,
        message: result.message,
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Logout controller error:', error);

      this._logControllerEvent('LOGOUT_ERROR', {
        error: error.message,
        userId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Logout failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Verify email address
   * POST /api/v1/auth/verify-email
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async verifyEmailAddress(req, res) {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          message: 'Verification token is required',
        });
      }

      // Call authentication service
      const result = await verifyEmail(token);

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 400;

      // Log email verification attempt
      this._logControllerEvent('EMAIL_VERIFICATION_ATTEMPT', {
        success: result.success,
        result: result.result,
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
      console.error('Verify email controller error:', error);

      this._logControllerEvent('EMAIL_VERIFICATION_ERROR', {
        error: error.message,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Email verification failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Request password reset
   * POST /api/v1/auth/forgot-password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: 'Email is required',
        });
      }

      // Extract request context
      const options = {
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await requestPasswordReset(email, options);

      // Always return 200 for password reset requests (security)
      const statusCode = 200;

      // Log password reset request
      this._logControllerEvent('PASSWORD_RESET_REQUEST', {
        email,
        success: result.success,
        result: result.result,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(statusCode).json({
        success: true, // Always return success for security
        message: result.message,
        ...(result.error && config.isDevelopment() && { error: result.error }),
      });
    } catch (error) {
      console.error('Forgot password controller error:', error);

      this._logControllerEvent('PASSWORD_RESET_REQUEST_ERROR', {
        error: error.message,
        email: req.body?.email,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Password reset request failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Reset password
   * POST /api/v1/auth/reset-password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({
          success: false,
          message: 'Token and new password are required',
        });
      }

      // Extract request context
      const options = {
        ipAddress: req.ip,
      };

      // Call authentication service
      const result = await resetPassword(token, newPassword, options);

      // Get appropriate HTTP status code
      const statusCode = HTTP_STATUS_CODES[result.result] || 400;

      // Log password reset attempt
      this._logControllerEvent('PASSWORD_RESET_ATTEMPT', {
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
      console.error('Reset password controller error:', error);

      this._logControllerEvent('PASSWORD_RESET_ERROR', {
        error: error.message,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Password reset failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Get current user profile
   * GET /api/v1/auth/me
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getCurrentUser(req, res) {
    try {
      // User information is already attached by authentication middleware
      const { user, workspace, userRole, tokenContext } = req;

      // Log profile access
      this._logControllerEvent('PROFILE_ACCESS', {
        userId: user.id,
        workspaceId: workspace?.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return user profile
      res.status(200).json({
        success: true,
        message: 'User profile retrieved successfully',
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
          workspace: workspace
            ? {
                id: workspace.id,
                name: workspace.name,
                domain: workspace.domain,
              }
            : null,
          role: userRole,
          tokenInfo: {
            issuedAt: new Date(tokenContext.iat * 1000).toISOString(),
            expiresAt: new Date(tokenContext.exp * 1000).toISOString(),
          },
        },
      });
    } catch (error) {
      console.error('Get current user controller error:', error);

      this._logControllerEvent('PROFILE_ACCESS_ERROR', {
        error: error.message,
        userId: req.user?.id,
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
   * Resend email verification
   * POST /api/v1/auth/resend-verification
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resendVerification(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: 'Email is required',
        });
      }

      // Find user by email
      const { client: prisma } = require('../config/database');
      const user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
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
        // Don't reveal if user exists
        return res.status(200).json({
          success: true,
          message:
            'If an account with this email exists, a verification email has been sent.',
        });
      }

      if (user.emailVerified) {
        return res.status(400).json({
          success: false,
          message: 'Email is already verified',
        });
      }

      // Send verification email
      const result = await emailService.sendEmailVerification(
        {
          userId: user.id,
          email: user.email,
          name: user.name,
          workspaceId: user.memberships[0]?.workspace.id,
        },
        { resend: true },
      );

      // Log verification resend
      this._logControllerEvent('VERIFICATION_RESEND', {
        userId: user.id,
        email: user.email,
        success: result.success,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return response
      res.status(200).json({
        success: true,
        message: 'Verification email sent successfully',
      });
    } catch (error) {
      console.error('Resend verification controller error:', error);

      this._logControllerEvent('VERIFICATION_RESEND_ERROR', {
        error: error.message,
        email: req.body?.email,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to resend verification email',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * OAuth callback handler (Google)
   * GET /api/v1/auth/google/callback
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async googleCallback(req, res) {
    try {
      // User information is attached by Passport OAuth middleware
      const { user } = req;

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'OAuth authentication failed',
        });
      }

      // Generate tokens for OAuth user
      const { generateTokenPair } = require('../config/jwt');
      const activeMembership = user.memberships.find(
        (m) => m.workspace.isActive,
      );

      const tokens = generateTokenPair({
        userId: user.id,
        email: user.email,
        workspaceId: activeMembership?.workspace.id,
        role: activeMembership?.role,
        ipAddress: req.ip,
      });

      // Store refresh token session
      const { client: prisma } = require('../config/database');
      await prisma.session.create({
        data: {
          userId: user.id,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      // Log OAuth login
      this._logControllerEvent('OAUTH_LOGIN', {
        userId: user.id,
        email: user.email,
        provider: 'google',
        workspaceId: activeMembership?.workspace.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Return tokens
      res.status(200).json({
        success: true,
        message: 'OAuth login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            emailVerified: user.emailVerified,
          },
          workspace: activeMembership?.workspace,
          role: activeMembership?.role,
          tokens,
        },
      });
    } catch (error) {
      console.error('Google OAuth callback error:', error);

      this._logControllerEvent('OAUTH_CALLBACK_ERROR', {
        error: error.message,
        provider: 'google',
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'OAuth callback failed',
        error: config.isDevelopment() ? error.message : 'Internal server error',
      });
    }
  }

  /**
   * Get authentication metrics (admin only)
   * GET /api/v1/auth/metrics
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getAuthMetrics(req, res) {
    try {
      // Get metrics from authentication service
      const metrics = authService.getMetrics();

      // Log metrics access
      this._logControllerEvent('METRICS_ACCESS', {
        userId: req.user?.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(200).json({
        success: true,
        message: 'Authentication metrics retrieved successfully',
        data: metrics,
      });
    } catch (error) {
      console.error('Get auth metrics controller error:', error);

      this._logControllerEvent('METRICS_ACCESS_ERROR', {
        error: error.message,
        userId: req.user?.id,
        ipAddress: req.ip,
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve authentication metrics',
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
      source: 'AUTH_CONTROLLER',
    };

    if (event.includes('ERROR') || event.includes('FAILED')) {
      console.warn('🎮 Auth Controller Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('🎮 Auth Controller Event:', logEntry);
    }

    // In production, send to monitoring service
    if (config.isProduction()) {
      // TODO: Send to monitoring service
    }
  }
}

// Create controller instance
const authController = new AuthController();

// Export controller methods
module.exports = {
  // Authentication endpoints
  register: (req, res) => authController.register(req, res),
  login: (req, res) => authController.login(req, res),
  refreshToken: (req, res) => authController.refreshToken(req, res),
  logout: (req, res) => authController.logout(req, res),

  // Email verification
  verifyEmailAddress: (req, res) => authController.verifyEmailAddress(req, res),
  resendVerification: (req, res) => authController.resendVerification(req, res),

  // Password reset
  forgotPassword: (req, res) => authController.forgotPassword(req, res),
  resetPassword: (req, res) => authController.resetPassword(req, res),

  // User profile
  getCurrentUser: (req, res) => authController.getCurrentUser(req, res),

  // OAuth callbacks
  googleCallback: (req, res) => authController.googleCallback(req, res),

  // Admin endpoints
  getAuthMetrics: (req, res) => authController.getAuthMetrics(req, res),

  // Controller instance
  authController,
};
