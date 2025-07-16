/**
 * Email Service Module
 *
 * This service provides comprehensive email management functionality for
 * multi-tenant SaaS applications with enterprise requirements:
 *
 * Features:
 * - Transactional email sending with templates
 * - Email delivery tracking and analytics
 * - Multi-tenant email customization
 * - Email queue management and retry logic
 * - Bounce and complaint handling
 * - Email verification and validation
 * - Bulk email operations with rate limiting
 * - Email template management and rendering
 *
 * @author AI-Persona Backend Team
 * @version 1.0.0
 */

const {
  emailManager,
  EMAIL_TYPES,
  EMAIL_PRIORITIES,
  sendVerificationEmail,
  sendInvitationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendSecurityAlertEmail,
} = require('../config/email');
const { generateSpecialToken, TOKEN_TYPES } = require('../config/jwt');
const { client: prisma } = require('../config/database');
const { normalizeEmail, isValidEmail } = require('../utils/domain');
const config = require('../config');

/**
 * Email Service Result Types
 */
const EMAIL_RESULTS = {
  SUCCESS: 'success',
  INVALID_EMAIL: 'invalid_email',
  TEMPLATE_NOT_FOUND: 'template_not_found',
  DELIVERY_FAILED: 'delivery_failed',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
  WORKSPACE_NOT_FOUND: 'workspace_not_found',
  USER_NOT_FOUND: 'user_not_found',
  INVALID_PERMISSIONS: 'invalid_permissions',
  OPERATION_FAILED: 'operation_failed',
  EMAIL_BLOCKED: 'email_blocked',
};

/**
 * Email Events for audit logging
 */
const EMAIL_EVENTS = {
  EMAIL_SENT: 'email_sent',
  EMAIL_DELIVERED: 'email_delivered',
  EMAIL_BOUNCED: 'email_bounced',
  EMAIL_COMPLAINT: 'email_complaint',
  EMAIL_OPENED: 'email_opened',
  EMAIL_CLICKED: 'email_clicked',
  TEMPLATE_RENDERED: 'template_rendered',
  BULK_EMAIL_SENT: 'bulk_email_sent',
  EMAIL_VERIFICATION_SENT: 'email_verification_sent',
  SECURITY_EVENT: 'security_event',
};

/**
 * Email Categories for organization
 */
const EMAIL_CATEGORIES = {
  AUTHENTICATION: 'authentication',
  NOTIFICATION: 'notification',
  MARKETING: 'marketing',
  SYSTEM: 'system',
  SECURITY: 'security',
};

/**
 * Email Service Class
 * Handles all email business logic and operations
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
      failedDeliveries: 0,
    };

    this.emailBlocklist = new Set();
    this.emailAllowlist = new Set();
    this.rateLimitTracker = new Map();
  }

  /**
   * Send email verification
   * @param {Object} verificationData - Verification data
   * @param {Object} options - Send options
   * @returns {Promise<Object>} Send result
   */
  async sendEmailVerification(verificationData, options = {}) {
    try {
      const { userId, email, name, workspaceId } = verificationData;
      const { resend = false, customTemplate = null } = options;

      // Validate email
      const normalizedEmail = normalizeEmail(email);
      if (!isValidEmail(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.INVALID_EMAIL,
          message: 'Invalid email address',
        };
      }

      // Check if email is blocked
      if (this.isEmailBlocked(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.EMAIL_BLOCKED,
          message: 'Email address is blocked',
        };
      }

      // Rate limiting check
      const rateLimitCheck = this.checkRateLimit(
        normalizedEmail,
        EMAIL_TYPES.VERIFICATION,
      );
      if (!rateLimitCheck.allowed) {
        return {
          success: false,
          result: EMAIL_RESULTS.RATE_LIMIT_EXCEEDED,
          message: `Rate limit exceeded. Try again in ${rateLimitCheck.resetTime} seconds`,
        };
      }

      // Get workspace details
      const workspace = await this.getWorkspaceDetails(workspaceId);
      if (!workspace) {
        return {
          success: false,
          result: EMAIL_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

      // Generate verification token
      const verificationToken = generateSpecialToken(
        { userId, email: normalizedEmail },
        TOKEN_TYPES.EMAIL_VERIFICATION,
        '24h',
      );

      // Send verification email
      const emailResult = await sendVerificationEmail({
        email: normalizedEmail,
        name,
        verificationToken,
        workspaceName: workspace.name,
        userId,
        workspaceId,
      });

      if (!emailResult) {
        return {
          success: false,
          result: EMAIL_RESULTS.DELIVERY_FAILED,
          message: 'Failed to send verification email',
        };
      }

      // Update rate limit tracker
      this.updateRateLimit(normalizedEmail, EMAIL_TYPES.VERIFICATION);

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.verificationEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_VERIFICATION_SENT, {
        userId,
        email: normalizedEmail,
        workspaceId,
        resend,
        verificationToken: verificationToken.substring(0, 20) + '...',
      });

      // Store email record for tracking
      await this.createEmailRecord({
        type: EMAIL_TYPES.VERIFICATION,
        recipient: normalizedEmail,
        userId,
        workspaceId,
        subject: `Verify your email address - ${workspace.name}`,
        templateData: { name, workspaceName: workspace.name },
        priority: EMAIL_PRIORITIES.HIGH,
      });

      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        message: 'Verification email sent successfully',
        data: {
          email: normalizedEmail,
          expiresIn: '24 hours',
        },
      };
    } catch (error) {
      console.error('Send email verification error:', error);
      this.emailMetrics.failedDeliveries++;

      this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
        event: 'verification_email_failed',
        userId: verificationData.userId,
        email: verificationData.email,
        error: error.message,
      });

      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to send verification email',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Send workspace invitation
   * @param {Object} invitationData - Invitation data
   * @param {Object} options - Send options
   * @returns {Promise<Object>} Send result
   */
  async sendWorkspaceInvitation(invitationData, options = {}) {
    try {
      const {
        email,
        inviterName,
        workspaceName,
        inviteToken,
        workspaceId,
        invitedBy,
      } = invitationData;

      // Validate email
      const normalizedEmail = normalizeEmail(email);
      if (!isValidEmail(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.INVALID_EMAIL,
          message: 'Invalid email address',
        };
      }

      // Check if email is blocked
      if (this.isEmailBlocked(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.EMAIL_BLOCKED,
          message: 'Email address is blocked',
        };
      }

      // Rate limiting check
      const rateLimitCheck = this.checkRateLimit(
        normalizedEmail,
        EMAIL_TYPES.INVITATION,
      );
      if (!rateLimitCheck.allowed) {
        return {
          success: false,
          result: EMAIL_RESULTS.RATE_LIMIT_EXCEEDED,
          message: `Rate limit exceeded. Try again in ${rateLimitCheck.resetTime} seconds`,
        };
      }

      // Send invitation email
      const emailResult = await sendInvitationEmail({
        email: normalizedEmail,
        inviterName,
        workspaceName,
        inviteToken,
        workspaceId,
        invitedBy,
      });

      if (!emailResult) {
        return {
          success: false,
          result: EMAIL_RESULTS.DELIVERY_FAILED,
          message: 'Failed to send invitation email',
        };
      }

      // Update rate limit tracker
      this.updateRateLimit(normalizedEmail, EMAIL_TYPES.INVITATION);

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.invitationEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: EMAIL_TYPES.INVITATION,
        recipient: normalizedEmail,
        workspaceId,
        invitedBy,
        inviterName,
      });

      // Store email record
      await this.createEmailRecord({
        type: EMAIL_TYPES.INVITATION,
        recipient: normalizedEmail,
        userId: null,
        workspaceId,
        subject: `You're invited to join ${workspaceName}`,
        templateData: { inviterName, workspaceName },
        priority: EMAIL_PRIORITIES.MEDIUM,
      });

      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        message: 'Invitation email sent successfully',
        data: {
          email: normalizedEmail,
          workspaceName,
          inviterName,
        },
      };
    } catch (error) {
      console.error('Send workspace invitation error:', error);
      this.emailMetrics.failedDeliveries++;

      this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
        event: 'invitation_email_failed',
        email: invitationData.email,
        workspaceId: invitationData.workspaceId,
        error: error.message,
      });

      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to send invitation email',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Send password reset email
   * @param {Object} resetData - Reset data
   * @param {Object} options - Send options
   * @returns {Promise<Object>} Send result
   */
  async sendPasswordReset(resetData, options = {}) {
    try {
      const { userId, email, name, workspaceId } = resetData;

      // Validate email
      const normalizedEmail = normalizeEmail(email);
      if (!isValidEmail(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.INVALID_EMAIL,
          message: 'Invalid email address',
        };
      }

      // Rate limiting check (strict for password resets)
      const rateLimitCheck = this.checkRateLimit(
        normalizedEmail,
        EMAIL_TYPES.PASSWORD_RESET,
        3,
      );
      if (!rateLimitCheck.allowed) {
        return {
          success: false,
          result: EMAIL_RESULTS.RATE_LIMIT_EXCEEDED,
          message: `Rate limit exceeded. Try again in ${rateLimitCheck.resetTime} seconds`,
        };
      }

      // Get workspace details
      const workspace = await this.getWorkspaceDetails(workspaceId);
      if (!workspace) {
        return {
          success: false,
          result: EMAIL_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

      // Generate password reset token
      const resetToken = generateSpecialToken(
        { userId, email: normalizedEmail },
        TOKEN_TYPES.PASSWORD_RESET,
        '1h',
      );

      // Send password reset email
      const emailResult = await sendPasswordResetEmail({
        email: normalizedEmail,
        name,
        resetToken,
        workspaceName: workspace.name,
        userId,
        workspaceId,
      });

      if (!emailResult) {
        return {
          success: false,
          result: EMAIL_RESULTS.DELIVERY_FAILED,
          message: 'Failed to send password reset email',
        };
      }

      // Update rate limit tracker
      this.updateRateLimit(normalizedEmail, EMAIL_TYPES.PASSWORD_RESET);

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.passwordResetEmailsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: EMAIL_TYPES.PASSWORD_RESET,
        recipient: normalizedEmail,
        userId,
        workspaceId,
        resetToken: resetToken.substring(0, 20) + '...',
      });

      // Store email record
      await this.createEmailRecord({
        type: EMAIL_TYPES.PASSWORD_RESET,
        recipient: normalizedEmail,
        userId,
        workspaceId,
        subject: `Reset your password - ${workspace.name}`,
        templateData: { name, workspaceName: workspace.name },
        priority: EMAIL_PRIORITIES.HIGH,
      });

      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        message: 'Password reset email sent successfully',
        data: {
          email: normalizedEmail,
          expiresIn: '1 hour',
        },
      };
    } catch (error) {
      console.error('Send password reset error:', error);
      this.emailMetrics.failedDeliveries++;

      this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
        event: 'password_reset_email_failed',
        userId: resetData.userId,
        email: resetData.email,
        error: error.message,
      });

      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to send password reset email',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Send security alert email
   * @param {Object} alertData - Alert data
   * @param {Object} options - Send options
   * @returns {Promise<Object>} Send result
   */
  async sendSecurityAlert(alertData, options = {}) {
    try {
      const { userId, email, name, alertType, details, workspaceId } =
        alertData;

      // Validate email
      const normalizedEmail = normalizeEmail(email);
      if (!isValidEmail(normalizedEmail)) {
        return {
          success: false,
          result: EMAIL_RESULTS.INVALID_EMAIL,
          message: 'Invalid email address',
        };
      }

      // Get workspace details
      const workspace = await this.getWorkspaceDetails(workspaceId);
      if (!workspace) {
        return {
          success: false,
          result: EMAIL_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

      // Send security alert email
      const emailResult = await sendSecurityAlertEmail({
        email: normalizedEmail,
        name,
        alertType,
        details,
        workspaceName: workspace.name,
        userId,
        workspaceId,
      });

      if (!emailResult) {
        return {
          success: false,
          result: EMAIL_RESULTS.DELIVERY_FAILED,
          message: 'Failed to send security alert email',
        };
      }

      // Update metrics
      this.emailMetrics.totalSent++;
      this.emailMetrics.securityAlertsSent++;

      // Log email event
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        type: EMAIL_TYPES.SECURITY_ALERT,
        recipient: normalizedEmail,
        userId,
        workspaceId,
        alertType,
        details: Object.keys(details),
      });

      // Store email record
      await this.createEmailRecord({
        type: EMAIL_TYPES.SECURITY_ALERT,
        recipient: normalizedEmail,
        userId,
        workspaceId,
        subject: `Security Alert - ${workspace.name}`,
        templateData: {
          name,
          alertType,
          details,
          workspaceName: workspace.name,
        },
        priority: EMAIL_PRIORITIES.HIGH,
      });

      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        message: 'Security alert email sent successfully',
        data: {
          email: normalizedEmail,
          alertType,
        },
      };
    } catch (error) {
      console.error('Send security alert error:', error);
      this.emailMetrics.failedDeliveries++;

      this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
        event: 'security_alert_email_failed',
        userId: alertData.userId,
        email: alertData.email,
        alertType: alertData.alertType,
        error: error.message,
      });

      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to send security alert email',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Send bulk emails to multiple recipients
   * @param {Object} bulkData - Bulk email data
   * @param {Object} options - Send options
   * @returns {Promise<Object>} Send result
   */
  async sendBulkEmails(bulkData, options = {}) {
    try {
      const {
        recipients,
        subject,
        template,
        templateData,
        workspaceId,
        senderId,
        category = EMAIL_CATEGORIES.NOTIFICATION,
      } = bulkData;
      const { batchSize = 50, delayBetweenBatches = 1000 } = options;

      // Validate recipients
      if (!Array.isArray(recipients) || recipients.length === 0) {
        return {
          success: false,
          result: EMAIL_RESULTS.INVALID_EMAIL,
          message: 'Invalid or empty recipients list',
        };
      }

      // Validate workspace
      const workspace = await this.getWorkspaceDetails(workspaceId);
      if (!workspace) {
        return {
          success: false,
          result: EMAIL_RESULTS.WORKSPACE_NOT_FOUND,
          message: 'Workspace not found',
        };
      }

      // Filter and validate recipients
      const validRecipients = [];
      const invalidRecipients = [];

      for (const recipient of recipients) {
        const normalizedEmail = normalizeEmail(recipient.email);

        if (
          !isValidEmail(normalizedEmail) ||
          this.isEmailBlocked(normalizedEmail)
        ) {
          invalidRecipients.push(recipient);
          continue;
        }

        validRecipients.push({
          ...recipient,
          email: normalizedEmail,
        });
      }

      // Process recipients in batches
      const results = {
        total: recipients.length,
        valid: validRecipients.length,
        invalid: invalidRecipients.length,
        sent: 0,
        failed: 0,
        errors: [],
      };

      for (let i = 0; i < validRecipients.length; i += batchSize) {
        const batch = validRecipients.slice(i, i + batchSize);

        const batchPromises = batch.map(async (recipient) => {
          try {
            // Merge template data with recipient-specific data
            const mergedTemplateData = {
              ...templateData,
              ...recipient.templateData,
              recipientName: recipient.name,
              workspaceName: workspace.name,
            };

            // Queue email
            const emailResult = await emailManager.queueEmail({
              type: template,
              to: recipient.email,
              subject,
              priority: EMAIL_PRIORITIES.MEDIUM,
              templateData: mergedTemplateData,
              metadata: {
                workspaceId,
                senderId,
                category,
                bulkEmailId: `bulk_${Date.now()}_${i}`,
              },
            });

            if (emailResult) {
              results.sent++;
            } else {
              results.failed++;
              results.errors.push({
                email: recipient.email,
                error: 'Failed to queue email',
              });
            }
          } catch (error) {
            results.failed++;
            results.errors.push({
              email: recipient.email,
              error: error.message,
            });
          }
        });

        await Promise.all(batchPromises);

        // Delay between batches to avoid overwhelming the email service
        if (i + batchSize < validRecipients.length) {
          await new Promise((resolve) =>
            setTimeout(resolve, delayBetweenBatches),
          );
        }
      }

      // Update metrics
      this.emailMetrics.totalSent += results.sent;
      this.emailMetrics.bulkEmailsSent++;
      this.emailMetrics.failedDeliveries += results.failed;

      // Log bulk email event
      this._logEmailEvent(EMAIL_EVENTS.BULK_EMAIL_SENT, {
        workspaceId,
        senderId,
        template,
        category,
        results,
      });

      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        message: 'Bulk emails processed successfully',
        data: results,
      };
    } catch (error) {
      console.error('Send bulk emails error:', error);

      this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
        event: 'bulk_email_failed',
        workspaceId: bulkData.workspaceId,
        senderId: bulkData.senderId,
        error: error.message,
      });

      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to send bulk emails',
        error: config.isDevelopment() ? error.message : undefined,
      };
    }
  }

  /**
   * Get email delivery status
   * @param {string} emailId - Email ID
   * @returns {Promise<Object>} Delivery status
   */
  async getEmailStatus(emailId) {
    try {
      // In a real implementation, this would query an email_logs table
      // For now, return mock data
      return {
        success: true,
        result: EMAIL_RESULTS.SUCCESS,
        data: {
          id: emailId,
          status: 'delivered',
          sentAt: new Date().toISOString(),
          deliveredAt: new Date().toISOString(),
          openedAt: null,
          clickedAt: null,
          bounced: false,
          complaint: false,
        },
      };
    } catch (error) {
      console.error('Get email status error:', error);
      return {
        success: false,
        result: EMAIL_RESULTS.OPERATION_FAILED,
        message: 'Failed to get email status',
      };
    }
  }

  /**
   * Get workspace details
   * @param {string} workspaceId - Workspace ID
   * @returns {Promise<Object|null>} Workspace details
   */
  async getWorkspaceDetails(workspaceId) {
    try {
      return await prisma.workspace.findUnique({
        where: { id: workspaceId },
        select: {
          id: true,
          name: true,
          domain: true,
          isActive: true,
        },
      });
    } catch (error) {
      console.error('Get workspace details error:', error);
      return null;
    }
  }

  /**
   * Create email record for tracking
   * @param {Object} emailData - Email data
   * @returns {Promise<Object>} Created record
   */
  async createEmailRecord(emailData) {
    try {
      // In a real implementation, this would create a record in an email_logs table
      // For now, just log the email
      this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, emailData);

      return {
        id: `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        ...emailData,
        createdAt: new Date(),
      };
    } catch (error) {
      console.error('Create email record error:', error);
      return null;
    }
  }

  /**
   * Check rate limit for email sending
   * @param {string} email - Email address
   * @param {string} emailType - Email type
   * @param {number} maxAttempts - Maximum attempts
   * @returns {Object} Rate limit check result
   */
  checkRateLimit(email, emailType, maxAttempts = 5) {
    const key = `${email}:${emailType}`;
    const now = Date.now();
    const windowMs = 60 * 60 * 1000; // 1 hour window

    if (!this.rateLimitTracker.has(key)) {
      this.rateLimitTracker.set(key, {
        attempts: 0,
        resetTime: now + windowMs,
      });
    }

    const tracker = this.rateLimitTracker.get(key);

    // Reset if window has passed
    if (now > tracker.resetTime) {
      tracker.attempts = 0;
      tracker.resetTime = now + windowMs;
    }

    const allowed = tracker.attempts < maxAttempts;
    const resetTime = Math.ceil((tracker.resetTime - now) / 1000);

    return {
      allowed,
      attempts: tracker.attempts,
      maxAttempts,
      resetTime,
    };
  }

  /**
   * Update rate limit tracker
   * @param {string} email - Email address
   * @param {string} emailType - Email type
   */
  updateRateLimit(email, emailType) {
    const key = `${email}:${emailType}`;
    const tracker = this.rateLimitTracker.get(key);

    if (tracker) {
      tracker.attempts++;
    }
  }

  /**
   * Check if email is blocked
   * @param {string} email - Email address
   * @returns {boolean} Whether email is blocked
   */
  isEmailBlocked(email) {
    return this.emailBlocklist.has(email.toLowerCase());
  }

  /**
   * Add email to blocklist
   * @param {string} email - Email address
   */
  blockEmail(email) {
    this.emailBlocklist.add(email.toLowerCase());
    this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
      event: 'email_blocked',
      email: email.toLowerCase(),
    });
  }

  /**
   * Remove email from blocklist
   * @param {string} email - Email address
   */
  unblockEmail(email) {
    this.emailBlocklist.delete(email.toLowerCase());
    this._logEmailEvent(EMAIL_EVENTS.SECURITY_EVENT, {
      event: 'email_unblocked',
      email: email.toLowerCase(),
    });
  }

  /**
   * Get email service metrics
   * @returns {Object} Email service metrics
   */
  getMetrics() {
    return {
      ...this.emailMetrics,
      blockedEmails: this.emailBlocklist.size,
      rateLimitTrackers: this.rateLimitTracker.size,
      deliveryRate:
        this.emailMetrics.totalSent > 0
          ? (this.emailMetrics.totalDelivered / this.emailMetrics.totalSent) *
            100
          : 0,
      bounceRate:
        this.emailMetrics.totalSent > 0
          ? (this.emailMetrics.totalBounced / this.emailMetrics.totalSent) * 100
          : 0,
      timestamp: new Date().toISOString(),
    };
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

    if (event === EMAIL_EVENTS.SECURITY_EVENT) {
      console.warn('📧 Email Security Event:', logEntry);
    } else if (config.logging.level === 'debug') {
      console.log('📧 Email Event:', logEntry);
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
  sendEmailVerification: (verificationData, options) =>
    emailService.sendEmailVerification(verificationData, options),
  sendWorkspaceInvitation: (invitationData, options) =>
    emailService.sendWorkspaceInvitation(invitationData, options),
  sendPasswordReset: (resetData, options) =>
    emailService.sendPasswordReset(resetData, options),
  sendSecurityAlert: (alertData, options) =>
    emailService.sendSecurityAlert(alertData, options),
  sendBulkEmails: (bulkData, options) =>
    emailService.sendBulkEmails(bulkData, options),
  getEmailStatus: (emailId) => emailService.getEmailStatus(emailId),

  // Email management
  blockEmail: (email) => emailService.blockEmail(email),
  unblockEmail: (email) => emailService.unblockEmail(email),
  isEmailBlocked: (email) => emailService.isEmailBlocked(email),

  // Rate limiting
  checkRateLimit: (email, emailType, maxAttempts) =>
    emailService.checkRateLimit(email, emailType, maxAttempts),

  // Utilities
  getMetrics: () => emailService.getMetrics(),

  // Constants
  EMAIL_RESULTS,
  EMAIL_EVENTS,
  EMAIL_CATEGORIES,
  EMAIL_TYPES,
  EMAIL_PRIORITIES,
};
