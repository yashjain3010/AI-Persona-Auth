/**
 * Email Service Module
 *
 * This service provides comprehensive email business logic for
 * multi-tenant SaaS applications with enterprise email requirements:
 *
 * Features:
 * - Email verification and welcome emails
 * - Password reset and security alerts
 * - Invitation and workspace notifications
 * - Email rate limiting and blocklist management
 * - Email metrics and delivery tracking
 * - Template management and personalization
 * - Multi-provider support (SMTP, SendGrid, etc.)
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const { sendUserEmail } = require('../utils/email');
const { normalizeEmail } = require('../utils/domain');
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
 * Email Service Class
 * Handles all email business logic
 */
class EmailService {
  constructor() {
    this.emailMetrics = {
      totalSent: 0,
      totalDelivered: 0,
      totalBounced: 0,
      totalComplaints: 0,
      totalOpened: 0,
      totalClicked: 0,
      verificationEmailsSent: 0,
      invitationEmailsSent: 0,
      passwordResetEmailsSent: 0,
      securityAlertsSent: 0,
      bulkEmailsSent: 0,
      rateLimitExceeded: 0,
      blockedEmails: 0,
      templateErrors: 0,
      providerErrors: 0,
    };

    this.emailBlocklist = new Set();
    this.rateLimitMap = new Map();
    this.lastCleanup = Date.now();
  }

  /**
   * Send email verification
   * @param {Object} userData - User data
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendEmailVerification(userData, options = {}) {
    return asyncHandler(async () => {
      const { user, workspace, verificationToken } = userData;
      const { priority = 'normal', ipAddress = null } = options;

      // Validate input
      const emailValidation = inputValidator.validateEmail(user.email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      // Business validation
      const businessValidation = businessValidator.validateEmailSending({
        email: user.email,
        type: 'verification',
        user,
        workspace,
      });
      if (!businessValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.BUSINESS_RULE_VIOLATION,
          'Email sending violates business rules',
          HTTP_STATUS.BAD_REQUEST,
          { details: businessValidation.errors },
        );
      }

      // Security validation
      const securityValidation = securityValidator.validateSecurity({
        email: user.email,
        type: 'verification',
        ipAddress,
        user,
      });
      if (!securityValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.SECURITY_VIOLATION,
          'Email blocked for security reasons',
          HTTP_STATUS.FORBIDDEN,
          { details: securityValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(user.email);

      // Check rate limiting
      this._checkRateLimit(normalizedEmail, 'verification');

      // Check blocklist
      if (this._isBlocked(normalizedEmail)) {
        throw new ApiError(
          ERROR_CODES.EMAIL_BLOCKED,
          'Email address is blocked',
          HTTP_STATUS.FORBIDDEN,
          { email: normalizedEmail },
        );
      }

      // Send email using helper
      await sendUserEmail('verification', {
        user: { ...user, email: normalizedEmail },
        workspace,
        verificationToken,
        priority,
      });

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.verificationEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: 'verification',
        recipient: normalizedEmail,
        userId: user.id,
        workspaceId: workspace?.id,
        priority,
        ipAddress,
      });

      return ApiResponse.success('Verification email sent successfully', {
        email: normalizedEmail,
        type: 'verification',
        sentAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Send invitation email
   * @param {Object} invitationData - Invitation data
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendInvitationEmail(invitationData, options = {}) {
    return asyncHandler(async () => {
      const { invite, inviter, workspace } = invitationData;
      const { priority = 'normal', ipAddress = null } = options;

      // Validate input
      const emailValidation = inputValidator.validateEmail(invite.email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      // Business validation
      const businessValidation = businessValidator.validateEmailSending({
        email: invite.email,
        type: 'invitation',
        invite,
        inviter,
        workspace,
      });
      if (!businessValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.BUSINESS_RULE_VIOLATION,
          'Invitation email violates business rules',
          HTTP_STATUS.BAD_REQUEST,
          { details: businessValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(invite.email);

      // Check rate limiting
      this._checkRateLimit(normalizedEmail, 'invitation');

      // Check blocklist
      if (this._isBlocked(normalizedEmail)) {
        throw new ApiError(
          ERROR_CODES.EMAIL_BLOCKED,
          'Email address is blocked',
          HTTP_STATUS.FORBIDDEN,
          { email: normalizedEmail },
        );
      }

      // Send email using helper
      await sendUserEmail('invitation', {
        invite: { ...invite, email: normalizedEmail },
        inviter,
        workspace,
        priority,
      });

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.invitationEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: 'invitation',
        recipient: normalizedEmail,
        inviterId: inviter.id,
        workspaceId: workspace.id,
        priority,
        ipAddress,
      });

      return ApiResponse.success('Invitation email sent successfully', {
        email: normalizedEmail,
        type: 'invitation',
        sentAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Send password reset email
   * @param {Object} resetData - Reset data
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendPasswordResetEmail(resetData, options = {}) {
    return asyncHandler(async () => {
      const { user, resetToken } = resetData;
      const { priority = 'high', ipAddress = null } = options;

      // Validate input
      const emailValidation = inputValidator.validateEmail(user.email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(user.email);

      // Check rate limiting
      this._checkRateLimit(normalizedEmail, 'passwordReset');

      // Check blocklist
      if (this._isBlocked(normalizedEmail)) {
        throw new ApiError(
          ERROR_CODES.EMAIL_BLOCKED,
          'Email address is blocked',
          HTTP_STATUS.FORBIDDEN,
          { email: normalizedEmail },
        );
      }

      // Send email using helper
      await sendUserEmail('passwordReset', {
        user: { ...user, email: normalizedEmail },
        resetToken,
        priority,
      });

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.passwordResetEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: 'passwordReset',
        recipient: normalizedEmail,
        userId: user.id,
        priority,
        ipAddress,
      });

      return ApiResponse.success('Password reset email sent successfully', {
        email: normalizedEmail,
        type: 'passwordReset',
        sentAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Send security alert email
   * @param {Object} alertData - Alert data
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendSecurityAlertEmail(alertData, options = {}) {
    return asyncHandler(async () => {
      const { user, alertType, alertDetails } = alertData;
      const { priority = 'urgent', ipAddress = null } = options;

      // Validate input
      const emailValidation = inputValidator.validateEmail(user.email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(user.email);

      // Security alerts bypass rate limiting but still check blocklist
      if (this._isBlocked(normalizedEmail)) {
        throw new ApiError(
          ERROR_CODES.EMAIL_BLOCKED,
          'Email address is blocked',
          HTTP_STATUS.FORBIDDEN,
          { email: normalizedEmail },
        );
      }

      // Send email using helper
      await sendUserEmail('securityAlert', {
        user: { ...user, email: normalizedEmail },
        alertType,
        alertDetails,
        priority,
      });

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.securityAlertsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: 'securityAlert',
        recipient: normalizedEmail,
        userId: user.id,
        alertType,
        priority,
        ipAddress,
      });

      return ApiResponse.success('Security alert email sent successfully', {
        email: normalizedEmail,
        type: 'securityAlert',
        sentAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Add email to blocklist
   * @param {string} email - Email to block
   * @param {string} reason - Reason for blocking
   * @returns {Promise<Object>} Block result
   */
  async blockEmail(email, reason = 'manual') {
    return asyncHandler(async () => {
      // Validate email
      const emailValidation = inputValidator.validateEmail(email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(email);
      this.emailBlocklist.add(normalizedEmail);

      // Update metrics
      this.emailMetrics.blockedEmails++;

      // Log block event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_BLOCKED, {
        email: normalizedEmail,
        reason,
        timestamp: new Date().toISOString(),
      });

      return ApiResponse.success('Email blocked successfully', {
        email: normalizedEmail,
        reason,
        blockedAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Remove email from blocklist
   * @param {string} email - Email to unblock
   * @returns {Promise<Object>} Unblock result
   */
  async unblockEmail(email) {
    return asyncHandler(async () => {
      // Validate email
      const emailValidation = inputValidator.validateEmail(email);
      if (!emailValidation.isValid) {
        throw new ApiError(
          ERROR_CODES.VALIDATION_ERROR,
          'Invalid email format',
          HTTP_STATUS.BAD_REQUEST,
          { field: 'email', details: emailValidation.errors },
        );
      }

      const normalizedEmail = normalizeEmail(email);
      const wasBlocked = this.emailBlocklist.delete(normalizedEmail);

      if (!wasBlocked) {
        throw new ApiError(
          ERROR_CODES.RESOURCE_NOT_FOUND,
          'Email was not blocked',
          HTTP_STATUS.NOT_FOUND,
          { email: normalizedEmail },
        );
      }

      return ApiResponse.success('Email unblocked successfully', {
        email: normalizedEmail,
        unblockedAt: new Date().toISOString(),
      });
    })();
  }

  /**
   * Get email metrics
   * @returns {Object} Email metrics
   */
  getMetrics() {
    return {
      ...this.emailMetrics,
      blockedEmailsCount: this.emailBlocklist.size,
      rateLimitedEmailsCount: this.rateLimitMap.size,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Check rate limiting for email
   * @param {string} email - Email to check
   * @param {string} type - Email type
   * @private
   */
  _checkRateLimit(email, type) {
    const now = Date.now();
    const key = `${email}:${type}`;
    const limit = this._getRateLimit(type);

    // Cleanup old entries
    if (now - this.lastCleanup > 60000) {
      this._cleanupRateLimit();
      this.lastCleanup = now;
    }

    if (!this.rateLimitMap.has(key)) {
      this.rateLimitMap.set(key, { count: 1, resetTime: now + limit.window });
      return;
    }

    const rateLimitData = this.rateLimitMap.get(key);
    if (now > rateLimitData.resetTime) {
      this.rateLimitMap.set(key, { count: 1, resetTime: now + limit.window });
      return;
    }

    if (rateLimitData.count >= limit.max) {
      this.emailMetrics.rateLimitExceeded++;
      throw new ApiError(
        ERROR_CODES.RATE_LIMIT_EXCEEDED,
        `Rate limit exceeded for ${type} emails`,
        HTTP_STATUS.TOO_MANY_REQUESTS,
        {
          email,
          type,
          resetTime: new Date(rateLimitData.resetTime).toISOString(),
        },
      );
    }

    rateLimitData.count++;
  }

  /**
   * Get rate limit for email type
   * @param {string} type - Email type
   * @returns {Object} Rate limit config
   * @private
   */
  _getRateLimit(type) {
    const limits = {
      verification: { max: 3, window: 300000 }, // 3 per 5 minutes
      invitation: { max: 10, window: 3600000 }, // 10 per hour
      passwordReset: { max: 3, window: 900000 }, // 3 per 15 minutes
      securityAlert: { max: 10, window: 3600000 }, // 10 per hour
      default: { max: 5, window: 600000 }, // 5 per 10 minutes
    };

    return limits[type] || limits.default;
  }

  /**
   * Check if email is blocked
   * @param {string} email - Email to check
   * @returns {boolean} Is blocked
   * @private
   */
  _isBlocked(email) {
    return this.emailBlocklist.has(email);
  }

  /**
   * Cleanup old rate limit entries
   * @private
   */
  _cleanupRateLimit() {
    const now = Date.now();
    for (const [key, data] of this.rateLimitMap.entries()) {
      if (now > data.resetTime) {
        this.rateLimitMap.delete(key);
      }
    }
  }

  /**
   * Log email events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  _logEmailEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'EMAIL_SERVICE',
    };

    if (
      event === EMAIL_EVENTS.EMAIL_BLOCKED ||
      event === EMAIL_EVENTS.RATE_LIMIT_EXCEEDED
    ) {
      logger.warn('📧 Email Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      logger.debug('📧 Email Event:', logEntry);
    }

    // In production, send to audit log service
    if (config.isProduction()) {
      // TODO: Send to audit log service
    }
  }
}

// Create singleton instance
const emailService = new EmailService();

// Export email service
module.exports = {
  // Main service instance
  emailService,

  // Service methods
  sendEmailVerification: (userData, options) =>
    emailService.sendEmailVerification(userData, options),
  sendInvitationEmail: (invitationData, options) =>
    emailService.sendInvitationEmail(invitationData, options),
  sendPasswordResetEmail: (resetData, options) =>
    emailService.sendPasswordResetEmail(resetData, options),
  sendSecurityAlertEmail: (alertData, options) =>
    emailService.sendSecurityAlertEmail(alertData, options),
  blockEmail: (email, reason) => emailService.blockEmail(email, reason),
  unblockEmail: (email) => emailService.unblockEmail(email),

  // Utilities
  getMetrics: () => emailService.getMetrics(),
};
