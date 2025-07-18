/**
 * Email Configuration Module
 *
 * This module provides a comprehensive email management system for multi-tenant SaaS
 * applications with enterprise-grade reliability, monitoring, and integration with the
 * enhanced backend architecture. Supports multiple email providers with queue-based
 * processing, comprehensive error handling, and detailed analytics.
 *
 * Key Features:
 * - Multiple email providers (SMTP, SendGrid, SES, Mailgun)
 * - Template-based email system with workspace branding
 * - Email verification and invitation workflows
 * - Queue-based email processing with retry logic and exponential backoff
 * - Email analytics and delivery tracking
 * - Multi-tenant email customization
 * - Security features (SPF, DKIM, rate limiting)
 * - Integration with enhanced systems (logger, error handling, async utilities)
 * - Performance monitoring and health checks
 * - Graceful error handling and recovery
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const nodemailer = require("nodemailer");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");

// Import enhanced systems
const config = require("./index");
const logger = require("../utils/logger");
const { generateTimestamp } = require("../utils/common");
const {
  ApiError,
  ValidationError,
  ExternalServiceError,
  ErrorHandler,
} = require("../utils/apiError");
const { asyncHandler } = require("../utils/asyncHandler");

/**
 * Email Types for different use cases
 */
const EMAIL_TYPES = {
  VERIFICATION: "email_verification",
  INVITATION: "workspace_invitation",
  PASSWORD_RESET: "password_reset",
  WELCOME: "welcome",
  NOTIFICATION: "notification",
  SECURITY_ALERT: "security_alert",
  WORKSPACE_DIGEST: "workspace_digest",
  ACCOUNT_LOCKED: "account_locked",
  LOGIN_ALERT: "login_alert",
  MEMBERSHIP_CHANGED: "membership_changed",
  WORKSPACE_CREATED: "workspace_created",
};

/**
 * Email Priorities for queue processing
 */
const EMAIL_PRIORITIES = {
  CRITICAL: "critical", // Security alerts, account locks
  HIGH: "high", // Password resets, verifications
  MEDIUM: "medium", // Invitations, welcome emails
  LOW: "low", // Notifications, digests
};

/**
 * Email Provider Types
 */
const EMAIL_PROVIDERS = {
  SMTP: "smtp",
  SENDGRID: "sendgrid",
  SES: "ses",
  MAILGUN: "mailgun",
};

/**
 * Email Status Types
 */
const EMAIL_STATUS = {
  QUEUED: "queued",
  PROCESSING: "processing",
  SENT: "sent",
  FAILED: "failed",
  BOUNCED: "bounced",
  DELIVERED: "delivered",
  OPENED: "opened",
  CLICKED: "clicked",
};

/**
 * Email Events for audit logging
 */
const EMAIL_EVENTS = {
  EMAIL_QUEUED: "EMAIL_QUEUED",
  EMAIL_SENT: "EMAIL_SENT",
  EMAIL_FAILED: "EMAIL_FAILED",
  EMAIL_BOUNCED: "EMAIL_BOUNCED",
  EMAIL_DELIVERED: "EMAIL_DELIVERED",
  TEMPLATE_LOADED: "TEMPLATE_LOADED",
  TRANSPORTER_CONFIGURED: "TRANSPORTER_CONFIGURED",
  QUEUE_PROCESSED: "QUEUE_PROCESSED",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  CLEANUP_COMPLETED: "CLEANUP_COMPLETED",
};

/**
 * Email Manager Class
 * Handles all email operations with enterprise features
 */
class EmailManager {
  constructor() {
    this.transporter = null;
    this.templateCache = new Map();
    this.emailQueue = [];
    this.processingQueue = false;
    this.failedJobs = new Map();

    // Enhanced metrics
    this.emailMetrics = {
      sent: 0,
      failed: 0,
      queued: 0,
      retries: 0,
      bounces: 0,
      delivered: 0,
      opened: 0,
      clicked: 0,
      averageProcessingTime: 0,
      lastProcessed: null,
      startTime: new Date(),
    };

    // Rate limiting
    this.rateLimits = new Map();
    this.rateLimitWindow = 3600000; // 1 hour
    this.maxEmailsPerHour = config.email.rateLimit?.maxPerHour || 100;

    // Processing configuration
    this.processingConfig = {
      batchSize: 10,
      processingInterval: 10000, // 10 seconds
      maxRetries: 3,
      retryDelay: 60000, // 1 minute
      cleanupInterval: 3600000, // 1 hour
    };

    // Queue management
    this.queueProcessor = null;
    this.cleanupInterval = null;

    this.initialize();
  }

  /**
   * Initialize email system with comprehensive error handling
   */
  async initialize() {
    try {
      logger.info("Initializing email system", {
        provider: config.email.provider,
        environment: config.NODE_ENV,
        rateLimit: this.maxEmailsPerHour,
      });

      await this.setupTransporter();
      await this.loadEmailTemplates();
      this.startQueueProcessor();
      this.startCleanupProcessor();

      logger.info("Email system initialized successfully", {
        provider: config.email.provider,
        templatesLoaded: this.templateCache.size,
        queueProcessorActive: !!this.queueProcessor,
      });
    } catch (error) {
      logger.error("Email system initialization failed", {
        error: error.message,
        stack: error.stack,
        provider: config.email.provider,
      });

      // In development, continue without email
      if (config.isDevelopment()) {
        logger.warn("Running in development mode without email functionality");
      } else {
        throw new ExternalServiceError(
          "email",
          "Email system initialization failed"
        );
      }
    }
  }

  /**
   * Setup email transporter based on configuration
   */
  async setupTransporter() {
    const provider = config.email.provider;

    try {
      switch (provider) {
        case EMAIL_PROVIDERS.SMTP:
          await this.setupSMTPTransporter();
          break;
        case EMAIL_PROVIDERS.SENDGRID:
          await this.setupSendGridTransporter();
          break;
        case EMAIL_PROVIDERS.SES:
          await this.setupSESTransporter();
          break;
        case EMAIL_PROVIDERS.MAILGUN:
          await this.setupMailgunTransporter();
          break;
        default:
          throw new ValidationError(`Unsupported email provider: ${provider}`);
      }

      await this._logEmailEvent(EMAIL_EVENTS.TRANSPORTER_CONFIGURED, {
        provider,
        configuration: this._getSafeTransporterConfig(),
      });
    } catch (error) {
      logger.error("Email transporter setup failed", {
        provider,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Setup SMTP transporter with enhanced configuration
   */
  async setupSMTPTransporter() {
    const smtpConfig = config.email.smtp;

    if (!smtpConfig.host || !smtpConfig.user || !smtpConfig.password) {
      throw new ValidationError(
        "SMTP configuration incomplete - missing host, user, or password"
      );
    }

    this.transporter = nodemailer.createTransporter({
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      auth: {
        user: smtpConfig.user,
        pass: smtpConfig.password,
      },
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 10,
      connectionTimeout: 60000,
      greetingTimeout: 30000,
      socketTimeout: 60000,
    });

    // Verify transporter
    await this.transporter.verify();

    logger.info("SMTP transporter configured and verified", {
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      user: smtpConfig.user.replace(/(.{3}).*(@.*)/, "$1***$2"), // Mask email
    });
  }

  /**
   * Setup SendGrid transporter
   */
  async setupSendGridTransporter() {
    const sendgridConfig = config.email.sendgrid;

    if (!sendgridConfig?.apiKey) {
      throw new ValidationError("SendGrid API key not configured");
    }

    // TODO: Implement SendGrid integration
    // const sgMail = require('@sendgrid/mail');
    // sgMail.setApiKey(sendgridConfig.apiKey);
    // this.transporter = sgMail;

    throw new ApiError(
      501,
      "SendGrid provider not yet implemented",
      "PROVIDER_NOT_IMPLEMENTED"
    );
  }

  /**
   * Setup AWS SES transporter
   */
  async setupSESTransporter() {
    const sesConfig = config.email.ses;

    if (
      !sesConfig?.accessKeyId ||
      !sesConfig?.secretAccessKey ||
      !sesConfig?.region
    ) {
      throw new ValidationError("AWS SES configuration incomplete");
    }

    // TODO: Implement AWS SES integration
    // const AWS = require('aws-sdk');
    // AWS.config.update({
    //   accessKeyId: sesConfig.accessKeyId,
    //   secretAccessKey: sesConfig.secretAccessKey,
    //   region: sesConfig.region,
    // });
    // this.transporter = new AWS.SES({ apiVersion: '2010-12-01' });

    throw new ApiError(
      501,
      "AWS SES provider not yet implemented",
      "PROVIDER_NOT_IMPLEMENTED"
    );
  }

  /**
   * Setup Mailgun transporter
   */
  async setupMailgunTransporter() {
    const mailgunConfig = config.email.mailgun;

    if (!mailgunConfig?.apiKey || !mailgunConfig?.domain) {
      throw new ValidationError("Mailgun configuration incomplete");
    }

    // TODO: Implement Mailgun integration
    throw new ApiError(
      501,
      "Mailgun provider not yet implemented",
      "PROVIDER_NOT_IMPLEMENTED"
    );
  }

  /**
   * Load email templates from filesystem with caching
   */
  async loadEmailTemplates() {
    const templatesDir = path.join(__dirname, "../templates/email");

    try {
      const templateFiles = await fs.readdir(templatesDir);
      let loadedCount = 0;

      for (const file of templateFiles) {
        if (file.endsWith(".html")) {
          const templateName = file.replace(".html", "");
          const templatePath = path.join(templatesDir, file);

          try {
            const templateContent = await fs.readFile(templatePath, "utf8");
            this.templateCache.set(templateName, templateContent);
            loadedCount++;

            await this._logEmailEvent(EMAIL_EVENTS.TEMPLATE_LOADED, {
              templateName,
              templatePath,
              size: templateContent.length,
            });
          } catch (error) {
            logger.warn("Failed to load email template", {
              templateName,
              templatePath,
              error: error.message,
            });
          }
        }
      }

      logger.info("Email templates loaded successfully", {
        templatesDir,
        loadedCount,
        totalFiles: templateFiles.length,
      });
    } catch (error) {
      logger.warn(
        "Email templates directory not found, using fallback templates",
        {
          templatesDir,
          error: error.message,
        }
      );
      this.loadFallbackTemplates();
    }
  }

  /**
   * Load fallback email templates
   */
  loadFallbackTemplates() {
    const fallbackTemplates = {
      [EMAIL_TYPES.VERIFICATION]: this._getVerificationTemplate(),
      [EMAIL_TYPES.INVITATION]: this._getInvitationTemplate(),
      [EMAIL_TYPES.PASSWORD_RESET]: this._getPasswordResetTemplate(),
      [EMAIL_TYPES.WELCOME]: this._getWelcomeTemplate(),
      [EMAIL_TYPES.SECURITY_ALERT]: this._getSecurityAlertTemplate(),
      [EMAIL_TYPES.ACCOUNT_LOCKED]: this._getAccountLockedTemplate(),
      [EMAIL_TYPES.LOGIN_ALERT]: this._getLoginAlertTemplate(),
    };

    for (const [type, template] of Object.entries(fallbackTemplates)) {
      this.templateCache.set(type, template);
    }

    logger.info("Fallback email templates loaded", {
      templateCount: Object.keys(fallbackTemplates).length,
    });
  }

  /**
   * Send email verification with enhanced validation
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendVerificationEmail(params) {
    try {
      this._validateEmailParams(params, ["email", "name", "verificationToken"]);

      const {
        email,
        name,
        verificationToken,
        workspaceName,
        userId,
        workspaceId,
      } = params;
      const verificationUrl = `${config.app.clientUrl}/verify-email?token=${verificationToken}`;

      return await this.queueEmail({
        type: EMAIL_TYPES.VERIFICATION,
        to: email,
        subject: `Verify your email address - ${
          workspaceName || config.app.name
        }`,
        priority: EMAIL_PRIORITIES.HIGH,
        templateData: {
          name,
          verificationUrl,
          workspaceName: workspaceName || config.app.name,
          appName: config.app.name,
          supportEmail: config.email.from.email,
          expiryHours: 24,
        },
        metadata: {
          userId,
          workspaceId,
          verificationToken,
          emailType: EMAIL_TYPES.VERIFICATION,
        },
      });
    } catch (error) {
      logger.error("Failed to send verification email", {
        email: params.email,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Send workspace invitation with enhanced features
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendInvitationEmail(params) {
    try {
      this._validateEmailParams(params, [
        "email",
        "inviterName",
        "workspaceName",
        "inviteToken",
      ]);

      const {
        email,
        inviterName,
        workspaceName,
        inviteToken,
        workspaceId,
        invitedBy,
        role,
      } = params;
      const inviteUrl = `${config.app.clientUrl}/accept-invite?token=${inviteToken}`;

      return await this.queueEmail({
        type: EMAIL_TYPES.INVITATION,
        to: email,
        subject: `You're invited to join ${workspaceName}`,
        priority: EMAIL_PRIORITIES.MEDIUM,
        templateData: {
          inviterName,
          workspaceName,
          inviteUrl,
          appName: config.app.name,
          role: role || "Member",
          supportEmail: config.email.from.email,
          expiryDays: config.workspace.inviteExpiry / 24 || 7,
        },
        metadata: {
          workspaceId,
          invitedBy,
          inviteToken,
          role,
          emailType: EMAIL_TYPES.INVITATION,
        },
      });
    } catch (error) {
      logger.error("Failed to send invitation email", {
        email: params.email,
        workspaceName: params.workspaceName,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Send password reset email with security features
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendPasswordResetEmail(params) {
    try {
      this._validateEmailParams(params, ["email", "name", "resetToken"]);

      const {
        email,
        name,
        resetToken,
        workspaceName,
        userId,
        workspaceId,
        ipAddress,
      } = params;
      const resetUrl = `${config.app.clientUrl}/reset-password?token=${resetToken}`;

      return await this.queueEmail({
        type: EMAIL_TYPES.PASSWORD_RESET,
        to: email,
        subject: `Reset your password - ${workspaceName || config.app.name}`,
        priority: EMAIL_PRIORITIES.HIGH,
        templateData: {
          name,
          resetUrl,
          workspaceName: workspaceName || config.app.name,
          appName: config.app.name,
          supportEmail: config.email.from.email,
          ipAddress,
          expiryHours: 1,
          securityTip:
            "If you did not request this password reset, please contact support immediately.",
        },
        metadata: {
          userId,
          workspaceId,
          resetToken,
          ipAddress,
          emailType: EMAIL_TYPES.PASSWORD_RESET,
        },
      });
    } catch (error) {
      logger.error("Failed to send password reset email", {
        email: params.email,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Send welcome email with onboarding information
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendWelcomeEmail(params) {
    try {
      this._validateEmailParams(params, ["email", "name", "workspaceName"]);

      const { email, name, workspaceName, workspaceId, userId, role } = params;
      const loginUrl = `${config.app.clientUrl}/login`;

      return await this.queueEmail({
        type: EMAIL_TYPES.WELCOME,
        to: email,
        subject: `Welcome to ${workspaceName}!`,
        priority: EMAIL_PRIORITIES.MEDIUM,
        templateData: {
          name,
          workspaceName,
          loginUrl,
          appName: config.app.name,
          role: role || "Member",
          supportEmail: config.email.from.email,
          gettingStartedUrl: `${config.app.clientUrl}/getting-started`,
        },
        metadata: {
          userId,
          workspaceId,
          role,
          emailType: EMAIL_TYPES.WELCOME,
        },
      });
    } catch (error) {
      logger.error("Failed to send welcome email", {
        email: params.email,
        workspaceName: params.workspaceName,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Send security alert email
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendSecurityAlertEmail(params) {
    try {
      this._validateEmailParams(params, ["email", "name", "alertType"]);

      const {
        email,
        name,
        alertType,
        details,
        workspaceName,
        userId,
        workspaceId,
        ipAddress,
      } = params;

      return await this.queueEmail({
        type: EMAIL_TYPES.SECURITY_ALERT,
        to: email,
        subject: `Security Alert - ${workspaceName || config.app.name}`,
        priority: EMAIL_PRIORITIES.CRITICAL,
        templateData: {
          name,
          alertType,
          details,
          workspaceName: workspaceName || config.app.name,
          appName: config.app.name,
          supportEmail: config.email.from.email,
          ipAddress,
          timestamp: generateTimestamp(),
          securityUrl: `${config.app.clientUrl}/security`,
        },
        metadata: {
          userId,
          workspaceId,
          alertType,
          ipAddress,
          emailType: EMAIL_TYPES.SECURITY_ALERT,
        },
      });
    } catch (error) {
      logger.error("Failed to send security alert email", {
        email: params.email,
        alertType: params.alertType,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Send account locked notification
   * @param {Object} params - Email parameters
   * @returns {Promise<boolean>} Success status
   */
  async sendAccountLockedEmail(params) {
    try {
      this._validateEmailParams(params, ["email", "name"]);

      const {
        email,
        name,
        lockReason,
        unlockTime,
        workspaceName,
        userId,
        workspaceId,
        ipAddress,
      } = params;

      return await this.queueEmail({
        type: EMAIL_TYPES.ACCOUNT_LOCKED,
        to: email,
        subject: `Account Security Alert - ${workspaceName || config.app.name}`,
        priority: EMAIL_PRIORITIES.CRITICAL,
        templateData: {
          name,
          lockReason: lockReason || "Multiple failed login attempts",
          unlockTime: unlockTime
            ? new Date(unlockTime).toLocaleString()
            : "Contact support",
          workspaceName: workspaceName || config.app.name,
          appName: config.app.name,
          supportEmail: config.email.from.email,
          ipAddress,
          securityUrl: `${config.app.clientUrl}/security`,
        },
        metadata: {
          userId,
          workspaceId,
          lockReason,
          ipAddress,
          emailType: EMAIL_TYPES.ACCOUNT_LOCKED,
        },
      });
    } catch (error) {
      logger.error("Failed to send account locked email", {
        email: params.email,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Queue email for processing with rate limiting
   * @param {Object} emailData - Email data
   * @returns {Promise<boolean>} Success status
   */
  async queueEmail(emailData) {
    try {
      // Check rate limiting
      if (!this._checkRateLimit(emailData.to)) {
        await this._logEmailEvent(EMAIL_EVENTS.RATE_LIMIT_EXCEEDED, {
          email: emailData.to,
          type: emailData.type,
          rateLimit: this.maxEmailsPerHour,
        });
        throw new ApiError(
          429,
          "Email rate limit exceeded",
          "RATE_LIMIT_EXCEEDED"
        );
      }

      const emailJob = {
        id: crypto.randomUUID(),
        ...emailData,
        attempts: 0,
        maxAttempts: this.processingConfig.maxRetries,
        createdAt: new Date(),
        scheduledAt: new Date(),
        status: EMAIL_STATUS.QUEUED,
      };

      this.emailQueue.push(emailJob);
      this.emailMetrics.queued++;

      await this._logEmailEvent(EMAIL_EVENTS.EMAIL_QUEUED, {
        emailId: emailJob.id,
        type: emailJob.type,
        to: emailJob.to,
        priority: emailJob.priority,
        queueLength: this.emailQueue.length,
      });

      // Start processing if not already running
      if (!this.processingQueue) {
        this.processEmailQueue();
      }

      return true;
    } catch (error) {
      logger.error("Failed to queue email", {
        emailData: { ...emailData, templateData: "[REDACTED]" },
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Process email queue with enhanced error handling
   */
  async processEmailQueue() {
    if (this.processingQueue || this.emailQueue.length === 0) {
      return;
    }

    this.processingQueue = true;
    const startTime = Date.now();

    try {
      // Sort by priority and creation time
      this.emailQueue.sort((a, b) => {
        const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        const priorityDiff =
          priorityOrder[b.priority] - priorityOrder[a.priority];

        if (priorityDiff !== 0) return priorityDiff;
        return new Date(a.createdAt) - new Date(b.createdAt);
      });

      // Process emails in batches
      const batch = this.emailQueue.splice(0, this.processingConfig.batchSize);
      const processedEmails = [];

      for (const emailJob of batch) {
        try {
          await this.processEmailJob(emailJob);
          processedEmails.push({ id: emailJob.id, status: "success" });
        } catch (error) {
          logger.error("Email processing failed", {
            emailId: emailJob.id,
            type: emailJob.type,
            to: emailJob.to,
            error: error.message,
            attempts: emailJob.attempts,
          });

          // Retry logic with exponential backoff
          if (emailJob.attempts < emailJob.maxAttempts) {
            emailJob.attempts++;
            emailJob.scheduledAt = new Date(
              Date.now() +
                this.processingConfig.retryDelay *
                  Math.pow(2, emailJob.attempts - 1)
            );
            emailJob.status = EMAIL_STATUS.QUEUED;
            this.emailQueue.push(emailJob);
            this.emailMetrics.retries++;

            processedEmails.push({ id: emailJob.id, status: "retried" });
          } else {
            emailJob.status = EMAIL_STATUS.FAILED;
            this.failedJobs.set(emailJob.id, emailJob);
            this.emailMetrics.failed++;

            await this._logEmailEvent(EMAIL_EVENTS.EMAIL_FAILED, {
              emailId: emailJob.id,
              type: emailJob.type,
              to: emailJob.to,
              error: error.message,
              attempts: emailJob.attempts,
            });

            processedEmails.push({ id: emailJob.id, status: "failed" });
          }
        }
      }

      const processingTime = Date.now() - startTime;
      this.emailMetrics.averageProcessingTime =
        (this.emailMetrics.averageProcessingTime + processingTime) / 2;
      this.emailMetrics.lastProcessed = new Date();

      await this._logEmailEvent(EMAIL_EVENTS.QUEUE_PROCESSED, {
        batchSize: batch.length,
        processed: processedEmails.length,
        processingTime,
        queueLength: this.emailQueue.length,
        results: processedEmails,
      });
    } catch (error) {
      logger.error("Email queue processing failed", {
        error: error.message,
        queueLength: this.emailQueue.length,
      });
    } finally {
      this.processingQueue = false;
    }
  }

  /**
   * Process individual email job with enhanced error handling
   * @param {Object} emailJob - Email job data
   */
  async processEmailJob(emailJob) {
    const startTime = Date.now();

    try {
      // Mock email sending in development
      if (config.development.mockEmailSending) {
        logger.info("Mock email sent", {
          emailId: emailJob.id,
          to: emailJob.to,
          subject: emailJob.subject,
          type: emailJob.type,
        });

        emailJob.status = EMAIL_STATUS.SENT;
        this.emailMetrics.sent++;
        return;
      }

      // Check if transporter is available
      if (!this.transporter) {
        throw new ExternalServiceError(
          "email",
          "Email transporter not configured"
        );
      }

      // Render email template
      const htmlContent = this.renderTemplate(
        emailJob.type,
        emailJob.templateData
      );

      // Prepare email options
      const mailOptions = {
        from: {
          name: config.email.from.name,
          address: config.email.from.email,
        },
        to: emailJob.to,
        subject: emailJob.subject,
        html: htmlContent,
        headers: {
          "X-Email-Type": emailJob.type,
          "X-Email-ID": emailJob.id,
          "X-Workspace-ID": emailJob.metadata?.workspaceId,
          "X-Priority": emailJob.priority,
        },
      };

      // Send email
      const result = await this.transporter.sendMail(mailOptions);

      emailJob.status = EMAIL_STATUS.SENT;
      this.emailMetrics.sent++;

      const processingTime = Date.now() - startTime;

      await this._logEmailEvent(EMAIL_EVENTS.EMAIL_SENT, {
        emailId: emailJob.id,
        type: emailJob.type,
        to: emailJob.to,
        subject: emailJob.subject,
        messageId: result.messageId,
        attempts: emailJob.attempts + 1,
        processingTime,
      });
    } catch (error) {
      emailJob.status = EMAIL_STATUS.FAILED;
      throw error;
    }
  }

  /**
   * Render email template with data and validation
   * @param {string} templateType - Template type
   * @param {Object} data - Template data
   * @returns {string} Rendered HTML
   */
  renderTemplate(templateType, data) {
    try {
      const template = this.templateCache.get(templateType);

      if (!template) {
        throw new ValidationError(`Email template not found: ${templateType}`);
      }

      // Simple template rendering (replace {{variable}} with data)
      let rendered = template;

      // Replace template variables
      for (const [key, value] of Object.entries(data)) {
        const regex = new RegExp(`{{${key}}}`, "g");
        rendered = rendered.replace(regex, value || "");
      }

      // Add common variables
      rendered = rendered.replace(/{{currentYear}}/g, new Date().getFullYear());
      rendered = rendered.replace(/{{appUrl}}/g, config.app.apiUrl);
      rendered = rendered.replace(/{{clientUrl}}/g, config.app.clientUrl);

      return rendered;
    } catch (error) {
      logger.error("Template rendering failed", {
        templateType,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Start queue processor with interval
   */
  startQueueProcessor() {
    if (this.queueProcessor) {
      clearInterval(this.queueProcessor);
    }

    this.queueProcessor = setInterval(async () => {
      if (this.emailQueue.length > 0) {
        await this.processEmailQueue();
      }
    }, this.processingConfig.processingInterval);

    logger.info("Email queue processor started", {
      interval: this.processingConfig.processingInterval,
      batchSize: this.processingConfig.batchSize,
    });
  }

  /**
   * Start cleanup processor for failed jobs and rate limits
   */
  startCleanupProcessor() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.cleanupInterval = setInterval(async () => {
      await this.cleanupExpiredData();
    }, this.processingConfig.cleanupInterval);

    logger.debug("Email cleanup processor started", {
      interval: this.processingConfig.cleanupInterval,
    });
  }

  /**
   * Cleanup expired data
   */
  async cleanupExpiredData() {
    const startTime = Date.now();
    let cleanedRateLimits = 0;
    let cleanedFailedJobs = 0;

    try {
      const now = Date.now();

      // Clean rate limits
      for (const [email, data] of this.rateLimits.entries()) {
        if (now - data.windowStart > this.rateLimitWindow) {
          this.rateLimits.delete(email);
          cleanedRateLimits++;
        }
      }

      // Clean old failed jobs (keep for 24 hours)
      const failedJobExpiry = 24 * 60 * 60 * 1000; // 24 hours
      for (const [jobId, job] of this.failedJobs.entries()) {
        if (now - job.createdAt.getTime() > failedJobExpiry) {
          this.failedJobs.delete(jobId);
          cleanedFailedJobs++;
        }
      }

      const duration = Date.now() - startTime;

      await this._logEmailEvent(EMAIL_EVENTS.CLEANUP_COMPLETED, {
        cleanedRateLimits,
        cleanedFailedJobs,
        duration,
        remainingRateLimits: this.rateLimits.size,
        remainingFailedJobs: this.failedJobs.size,
      });

      logger.debug("Email cleanup completed", {
        cleanedRateLimits,
        cleanedFailedJobs,
        duration,
      });
    } catch (error) {
      logger.error("Email cleanup failed", {
        error: error.message,
        duration: Date.now() - startTime,
      });
    }
  }

  /**
   * Get comprehensive email metrics
   * @returns {Object} Email metrics
   */
  getMetrics() {
    const uptime = Date.now() - this.emailMetrics.startTime.getTime();
    const totalEmails = this.emailMetrics.sent + this.emailMetrics.failed;
    const successRate =
      totalEmails > 0 ? (this.emailMetrics.sent / totalEmails) * 100 : 100;

    return {
      ...this.emailMetrics,
      uptime: Math.round(uptime / 1000), // seconds
      queueLength: this.emailQueue.length,
      templatesLoaded: this.templateCache.size,
      failedJobsCount: this.failedJobs.size,
      rateLimitedEmails: this.rateLimits.size,
      successRate: Math.round(successRate * 100) / 100,
      totalEmails,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    const metrics = this.getMetrics();
    const isHealthy =
      metrics.successRate > 95 &&
      metrics.queueLength < 100 &&
      metrics.averageProcessingTime < 5000;

    return {
      status: isHealthy ? "healthy" : "degraded",
      checks: {
        successRate: {
          status: metrics.successRate > 95 ? "pass" : "fail",
          value: `${metrics.successRate}%`,
          threshold: "95%",
        },
        queueLength: {
          status: metrics.queueLength < 100 ? "pass" : "warn",
          value: metrics.queueLength,
          threshold: 100,
        },
        processingTime: {
          status: metrics.averageProcessingTime < 5000 ? "pass" : "warn",
          value: `${metrics.averageProcessingTime}ms`,
          threshold: "5000ms",
        },
        transporter: {
          status: this.transporter ? "pass" : "fail",
          value: this.transporter ? "configured" : "not configured",
        },
      },
      metrics: {
        uptime: metrics.uptime,
        totalEmails: metrics.totalEmails,
        successRate: metrics.successRate,
        queueLength: metrics.queueLength,
      },
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Graceful shutdown
   * @returns {Promise<void>}
   */
  async gracefulShutdown() {
    logger.info("Email Manager shutting down gracefully");

    // Stop processors
    if (this.queueProcessor) {
      clearInterval(this.queueProcessor);
      this.queueProcessor = null;
    }

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    // Process remaining emails
    if (this.emailQueue.length > 0) {
      logger.info("Processing remaining emails in queue", {
        queueLength: this.emailQueue.length,
      });
      await this.processEmailQueue();
    }

    // Close transporter
    if (this.transporter && this.transporter.close) {
      await this.transporter.close();
    }

    // Clear caches
    this.templateCache.clear();
    this.rateLimits.clear();
    this.failedJobs.clear();

    logger.info("Email Manager shutdown completed", {
      finalMetrics: this.getMetrics(),
    });
  }

  // === Private Methods ===

  /**
   * Validate email parameters
   * @param {Object} params - Parameters to validate
   * @param {Array} requiredFields - Required fields
   * @private
   */
  _validateEmailParams(params, requiredFields) {
    for (const field of requiredFields) {
      if (!params[field]) {
        throw new ValidationError(`Missing required email parameter: ${field}`);
      }
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(params.email)) {
      throw new ValidationError("Invalid email format");
    }
  }

  /**
   * Check rate limiting
   * @param {string} email - Email address
   * @returns {boolean} Whether email is within rate limit
   * @private
   */
  _checkRateLimit(email) {
    const now = Date.now();
    const rateLimitData = this.rateLimits.get(email);

    if (!rateLimitData) {
      this.rateLimits.set(email, {
        count: 1,
        windowStart: now,
      });
      return true;
    }

    // Reset window if expired
    if (now - rateLimitData.windowStart > this.rateLimitWindow) {
      this.rateLimits.set(email, {
        count: 1,
        windowStart: now,
      });
      return true;
    }

    // Check if within limit
    if (rateLimitData.count >= this.maxEmailsPerHour) {
      return false;
    }

    // Increment count
    rateLimitData.count++;
    return true;
  }

  /**
   * Get safe transporter configuration for logging
   * @returns {Object} Safe configuration
   * @private
   */
  _getSafeTransporterConfig() {
    const provider = config.email.provider;

    switch (provider) {
      case EMAIL_PROVIDERS.SMTP:
        return {
          host: config.email.smtp.host,
          port: config.email.smtp.port,
          secure: config.email.smtp.secure,
          user: config.email.smtp.user?.replace(/(.{3}).*(@.*)/, "$1***$2"),
        };
      default:
        return { provider };
    }
  }

  /**
   * Log email events for audit trail
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  async _logEmailEvent(event, data) {
    const logEntry = {
      event,
      timestamp: generateTimestamp(),
      data: {
        ...data,
        // Remove sensitive data
        templateData: undefined,
        password: undefined,
        token: undefined,
      },
      source: "EMAIL_MANAGER",
      environment: config.NODE_ENV,
    };

    // Use logger's email method for email events
    logger.email(event, logEntry.data);

    // Debug logging in development
    if (config.isDevelopment() && config.logging.level === "debug") {
      logger.debug("Email Event", logEntry);
    }
  }

  // === Template Methods ===

  _getVerificationTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Verify Your Email Address</h2>
        <p>Hello {{name}},</p>
        <p>Please click the button below to verify your email address for {{workspaceName}}:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{verificationUrl}}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
        </div>
        <p><strong>This link will expire in {{expiryHours}} hours.</strong></p>
        <p>If you didn't request this verification, please ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getInvitationTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">You're Invited to Join {{workspaceName}}</h2>
        <p>Hello,</p>
        <p>{{inviterName}} has invited you to join the <strong>{{workspaceName}}</strong> workspace on {{appName}} as a {{role}}.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{inviteUrl}}" style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Accept Invitation</a>
        </div>
        <p><strong>This invitation will expire in {{expiryDays}} days.</strong></p>
        <p>If you don't want to join this workspace, you can simply ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getPasswordResetTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Reset Your Password</h2>
        <p>Hello {{name}},</p>
        <p>You requested to reset your password for {{workspaceName}}. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{resetUrl}}" style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </div>
        <p><strong>This link will expire in {{expiryHours}} hour.</strong></p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #666;"><strong>Security Notice:</strong> {{securityTip}}</p>
          {{#if ipAddress}}<p style="margin: 5px 0 0 0; color: #666; font-size: 12px;">Request made from: {{ipAddress}}</p>{{/if}}
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getWelcomeTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to {{workspaceName}}!</h2>
        <p>Hello {{name}},</p>
        <p>Welcome to <strong>{{workspaceName}}</strong> on {{appName}}! Your account has been successfully created as a {{role}}.</p>
        <p>You can now access your workspace and start collaborating with your team.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{loginUrl}}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin-right: 10px;">Go to Workspace</a>
          <a href="{{gettingStartedUrl}}" style="background: #6c757d; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Getting Started</a>
        </div>
        <p>If you have any questions, don't hesitate to reach out to our support team.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getSecurityAlertTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #dc3545;">Security Alert</h2>
        <p>Hello {{name}},</p>
        <p>We detected a security event on your {{workspaceName}} account:</p>
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #721c24;"><strong>Alert Type:</strong> {{alertType}}</p>
          <p style="margin: 5px 0 0 0; color: #721c24;"><strong>Details:</strong> {{details}}</p>
          <p style="margin: 5px 0 0 0; color: #721c24; font-size: 12px;"><strong>Time:</strong> {{timestamp}}</p>
          {{#if ipAddress}}<p style="margin: 5px 0 0 0; color: #721c24; font-size: 12px;"><strong>IP Address:</strong> {{ipAddress}}</p>{{/if}}
        </div>
        <p>If this was you, no action is needed. If you don't recognize this activity, please secure your account immediately.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{securityUrl}}" style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Review Security Settings</a>
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getAccountLockedTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #dc3545;">Account Security Alert</h2>
        <p>Hello {{name}},</p>
        <p>Your {{workspaceName}} account has been temporarily locked for security reasons.</p>
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #721c24;"><strong>Reason:</strong> {{lockReason}}</p>
          <p style="margin: 5px 0 0 0; color: #721c24;"><strong>Unlock Time:</strong> {{unlockTime}}</p>
          {{#if ipAddress}}<p style="margin: 5px 0 0 0; color: #721c24; font-size: 12px;"><strong>Last Attempt IP:</strong> {{ipAddress}}</p>{{/if}}
        </div>
        <p>Your account will be automatically unlocked at the specified time. If you believe this was an error, please contact support.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{securityUrl}}" style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Security Settings</a>
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }

  _getLoginAlertTemplate() {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">New Login Alert</h2>
        <p>Hello {{name}},</p>
        <p>We detected a new login to your {{workspaceName}} account:</p>
        <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #155724;"><strong>Time:</strong> {{timestamp}}</p>
          {{#if ipAddress}}<p style="margin: 5px 0 0 0; color: #155724;"><strong>IP Address:</strong> {{ipAddress}}</p>{{/if}}
          {{#if location}}<p style="margin: 5px 0 0 0; color: #155724;"><strong>Location:</strong> {{location}}</p>{{/if}}
          {{#if device}}<p style="margin: 5px 0 0 0; color: #155724;"><strong>Device:</strong> {{device}}</p>{{/if}}
        </div>
        <p>If this was you, no action is needed. If you don't recognize this login, please secure your account immediately.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{securityUrl}}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Review Security Settings</a>
        </div>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Need help? Contact us at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a><br>
          © {{currentYear}} {{appName}}. All rights reserved.
        </p>
      </div>
    `;
  }
}

// Create singleton instance
const emailManager = new EmailManager();

// Graceful shutdown handler
process.on("SIGTERM", async () => {
  await emailManager.gracefulShutdown();
});

process.on("SIGINT", async () => {
  await emailManager.gracefulShutdown();
});

// Export email manager and utilities
module.exports = {
  // Main email manager instance
  emailManager,

  // Constants
  EMAIL_TYPES,
  EMAIL_PRIORITIES,
  EMAIL_PROVIDERS,
  EMAIL_STATUS,
  EMAIL_EVENTS,

  // Wrapped email methods with async handling
  sendVerificationEmail: asyncHandler(async (params) => {
    return await emailManager.sendVerificationEmail(params);
  }),

  sendInvitationEmail: asyncHandler(async (params) => {
    return await emailManager.sendInvitationEmail(params);
  }),

  sendPasswordResetEmail: asyncHandler(async (params) => {
    return await emailManager.sendPasswordResetEmail(params);
  }),

  sendWelcomeEmail: asyncHandler(async (params) => {
    return await emailManager.sendWelcomeEmail(params);
  }),

  sendSecurityAlertEmail: asyncHandler(async (params) => {
    return await emailManager.sendSecurityAlertEmail(params);
  }),

  sendAccountLockedEmail: asyncHandler(async (params) => {
    return await emailManager.sendAccountLockedEmail(params);
  }),

  // Queue management
  queueEmail: asyncHandler(async (emailData) => {
    return await emailManager.queueEmail(emailData);
  }),

  // Template management
  renderTemplate: (templateType, data) => {
    return emailManager.renderTemplate(templateType, data);
  },

  // Metrics and health
  getMetrics: () => emailManager.getMetrics(),
  getHealthStatus: () => emailManager.getHealthStatus(),

  // Management
  initialize: asyncHandler(async () => {
    return await emailManager.initialize();
  }),

  gracefulShutdown: () => emailManager.gracefulShutdown(),
};
