/**
 * Auth Controller
 * Handles all authentication-related HTTP logic.
 * Delegates business logic to authService and uses DRY patterns.
 */

const { authService } = require('../services/authService');
const { asyncHandler } = require('../utils/asyncHandler');
const { ApiError, ERROR_CODES } = require('../utils/apiError');
const { SuccessResponse } = require('../utils/apiResponse');
const logger = require('../utils/logger');
const {
  validateUserRegistration,
  validateUserLogin,
  validateSecurity,
} = require('../validations/middleware');
const { authenticate } = require('../config/auth');

/**
 * Register a new user (local)
 */
const register = [
  validateSecurity(),
  validateUserRegistration(),
  asyncHandler(async (req, res) => {
    const { email, password, name } = req.body;
    logger.info('Registering user', { email, ip: req.ip });
    const result = await authService.registerUser(
      { email, password, name },
      {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId,
      },
    );
    return new SuccessResponse(result, 'Registration successful').send(
      res,
      req,
    );
  }),
];

/**
 * Login (local)
 */
const login = [
  validateSecurity(),
  validateUserLogin(),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    logger.info('User login', { email, ip: req.ip });
    const result = await authService.authenticateUser(
      { email, password },
      {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        deviceId: req.get('X-Device-ID'),
        requestId: req.requestId,
      },
    );
    return new SuccessResponse(result, 'Login successful').send(res, req);
  }),
];

/**
 * Google OAuth callback
 */
const googleCallback = asyncHandler(async (req, res) => {
  const user = req.user;
  logger.info('Google OAuth callback', {
    userId: user.id,
    email: user.email,
    ip: req.ip,
  });
  const tokens = await authService.generateAuthTokens(user, {
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    deviceId: req.get('X-Device-ID'),
  });
  const redirectUrl = new URL(`${process.env.FRONTEND_URL}/auth/callback`);
  redirectUrl.searchParams.append('accessToken', tokens.accessToken);
  redirectUrl.searchParams.append('refreshToken', tokens.refreshToken);
  redirectUrl.searchParams.append('provider', 'google');
  res.redirect(redirectUrl.toString());
});

/**
 * Microsoft OAuth callback
 */
const microsoftCallback = asyncHandler(async (req, res) => {
  const user = req.user;
  logger.info('Microsoft OAuth callback', {
    userId: user.id,
    email: user.email,
    ip: req.ip,
  });
  const tokens = await authService.generateAuthTokens(user, {
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    deviceId: req.get('X-Device-ID'),
  });
  const redirectUrl = new URL(`${process.env.FRONTEND_URL}/auth/callback`);
  redirectUrl.searchParams.append('accessToken', tokens.accessToken);
  redirectUrl.searchParams.append('refreshToken', tokens.refreshToken);
  redirectUrl.searchParams.append('provider', 'microsoft');
  res.redirect(redirectUrl.toString());
});

/**
 * Refresh JWT token
 */
const refresh = [
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken)
      throw new ApiError(
        400,
        'Refresh token is required',
        ERROR_CODES.MISSING_REFRESH_TOKEN,
      );
    const result = await authService.refreshAccessToken(refreshToken, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      deviceId: req.get('X-Device-ID'),
      requestId: req.requestId,
    });
    return new SuccessResponse(result, 'Token refreshed successfully').send(
      res,
      req,
    );
  }),
];

/**
 * Logout
 */
const logout = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    const user = req.user;
    await authService.logoutUser(refreshToken, {
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });
    return new SuccessResponse(null, 'Logout successful').send(res, req);
  }),
];

/**
 * Verify email
 */
const verifyEmail = [
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const { token } = req.body;
    if (!token)
      throw new ApiError(
        400,
        'Verification token is required',
        ERROR_CODES.MISSING_TOKEN,
      );
    const result = await authService.verifyEmail(token);
    return new SuccessResponse(result, 'Email verification successful').send(
      res,
      req,
    );
  }),
];

/**
 * Forgot password (request reset)
 */
const forgotPassword = [
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email)
      throw new ApiError(400, 'Email is required', ERROR_CODES.MISSING_EMAIL);
    await authService.requestPasswordReset(email, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });
    // Always return success to prevent email enumeration
    return new SuccessResponse(
      { message: 'If the email exists, a password reset link has been sent' },
      'Password reset email sent',
    ).send(res, req);
  }),
];

/**
 * Reset password
 */
const resetPassword = [
  validateSecurity(),
  asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      throw new ApiError(
        400,
        'Token and new password are required',
        ERROR_CODES.MISSING_FIELDS,
      );
    const result = await authService.resetPassword(token, newPassword, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });
    return new SuccessResponse(result, 'Password reset successful').send(
      res,
      req,
    );
  }),
];

/**
 * Get current user profile
 */
const me = [
  authenticate('jwt'),
  asyncHandler(async (req, res) => {
    const user = req.user;
    return new SuccessResponse(
      {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          memberships: user.memberships,
        },
      },
      'Profile retrieved successfully',
    ).send(res, req);
  }),
];

/**
 * Auth service health check
 */
const health = asyncHandler(async (req, res) => {
  const metrics = authService.getMetrics();
  return new SuccessResponse(
    { status: 'healthy', metrics },
    'Auth service is healthy',
  ).send(res, req);
});

module.exports = {
  register,
  login,
  googleCallback,
  microsoftCallback,
  refresh,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  me,
  health,
};
