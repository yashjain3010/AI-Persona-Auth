const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const config = require('./index');
const { client: prisma } = require('./database');
const { validateToken, TOKEN_TYPES } = require('./jwt');
const logger = require('../utils/logger');
const { generateTimestamp } = require('../utils/common');
const {
  ApiError,
  ValidationError,
  SecurityError,
} = require('../utils/apiError');
const { asyncHandler } = require('../utils/asyncHandler');

/**
 * Authentication Strategy Names
 */
const STRATEGIES = {
  LOCAL: 'local',
  GOOGLE: 'google',
  MICROSOFT: 'microsoft',
  JWT: 'jwt',
  API_KEY: 'api-key',
};

/**
 * Authentication Events for audit logging
 */
const AUTH_EVENTS = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  SIGNUP_SUCCESS: 'SIGNUP_SUCCESS',
  SIGNUP_FAILURE: 'SIGNUP_FAILURE',
  OAUTH_SUCCESS: 'OAUTH_SUCCESS',
  OAUTH_FAILURE: 'OAUTH_FAILURE',
  LOGOUT: 'LOGOUT',
  TOKEN_REFRESH: 'TOKEN_REFRESH',
  PASSWORD_RESET: 'PASSWORD_RESET',
  EMAIL_VERIFICATION: 'EMAIL_VERIFICATION',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
  WORKSPACE_CREATED: 'WORKSPACE_CREATED',
  MEMBERSHIP_CREATED: 'MEMBERSHIP_CREATED',
};

/**
 * Authentication Result Codes
 */
const AUTH_RESULT_CODES = {
  SUCCESS: 'SUCCESS',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  OAUTH_ONLY_USER: 'OAUTH_ONLY_USER',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  ACCOUNT_DEACTIVATED: 'ACCOUNT_DEACTIVATED',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  NO_WORKSPACE_ACCESS: 'NO_WORKSPACE_ACCESS',
  PERSONAL_EMAIL_BLOCKED: 'PERSONAL_EMAIL_BLOCKED',
  INVALID_TOKEN_TYPE: 'INVALID_TOKEN_TYPE',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  SECURITY_VIOLATION: 'SECURITY_VIOLATION',
};

/**
 * User Roles
 */
const USER_ROLES = {
  ADMIN: 'ADMIN',
  MEMBER: 'MEMBER',
  GUEST: 'GUEST',
};

/**
 * Authentication Configuration Class
 * Manages all authentication strategies and flows with enterprise features
 */
class AuthenticationManager {
  constructor() {
    // TODO: Add SSO (SAML/OIDC) strategy support for enterprise SSO integration in the future.
    // Performance and security metrics
    this.authMetrics = {
      localLogins: 0,
      oauthLogins: 0,
      jwtValidations: 0,
      failedAttempts: 0,
      newRegistrations: 0,
      workspacesCreated: 0,
      accountsLocked: 0,
      securityViolations: 0,
      averageAuthTime: 0,
      lastReset: new Date(),
    };

    // Security configuration
    this.securityConfig = {
      maxFailedAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      passwordMinLength: config.auth.password.minLength,
      bcryptRounds: config.auth.password.bcryptRounds,
      suspiciousActivityThreshold: 3,
    };

    // Rate limiting tracking
    this.rateLimitTracking = new Map();
    this.lockedAccounts = new Map();

    // Authentication timing tracking
    this.authTimes = [];
    this.maxAuthTimeHistory = 100;

    this.initialize();
  }

  /**
   * Initialize all authentication strategies
   */
  initialize() {
    logger.info('Initializing authentication strategies', {
      environment: config.NODE_ENV,
      strategies: Object.values(STRATEGIES),
    });

    try {
      this.configureLocalStrategy();
      this.configureGoogleStrategy();
      this.configureMicrosoftStrategy();
      this.configureJWTStrategy();
      this.configurePassportSerialization();
      this._setupCleanupIntervals();

      logger.info('Authentication strategies initialized successfully', {
        configuredStrategies: this._getConfiguredStrategies(),
        securityConfig: this.securityConfig,
      });
    } catch (error) {
      logger.error('Authentication initialization failed', {
        error: error.message,
        stack: error.stack,
      });
      throw new ApiError(
        500,
        'Authentication system initialization failed',
        'AUTH_INIT_FAILED',
      );
    }
  }

  /**
   * Configure Local Authentication Strategy
   * Handles email/password authentication with comprehensive security
   */
  configureLocalStrategy() {
    passport.use(
      STRATEGIES.LOCAL,
      new LocalStrategy(
        {
          usernameField: 'email',
          passwordField: 'password',
          passReqToCallback: true,
        },
        asyncHandler(async (req, email, password, done) => {
          const startTime = Date.now();

          try {
            // Normalize and validate email
            const normalizedEmail = this._normalizeEmail(email);
            const domain = this._extractDomain(normalizedEmail);

            // Security checks
            await this._performSecurityChecks(normalizedEmail, req.ip, req);

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
                        settings: true,
                      },
                    },
                  },
                },
              },
            });

            // User not found
            if (!user) {
              await this._handleFailedAttempt(
                normalizedEmail,
                req.ip,
                'USER_NOT_FOUND',
              );
              return done(null, false, {
                message: 'Invalid email or password',
                code: AUTH_RESULT_CODES.INVALID_CREDENTIALS,
              });
            }

            // Check if user has password (might be OAuth-only user)
            if (!user.passwordHash) {
              await this._handleFailedAttempt(
                normalizedEmail,
                req.ip,
                'OAUTH_ONLY_USER',
              );
              return done(null, false, {
                message: 'Please sign in with your OAuth provider',
                code: AUTH_RESULT_CODES.OAUTH_ONLY_USER,
              });
            }

            // Verify password
            const isValidPassword = await bcrypt.compare(
              password,
              user.passwordHash,
            );
            if (!isValidPassword) {
              await this._handleFailedAttempt(
                normalizedEmail,
                req.ip,
                'INVALID_PASSWORD',
              );
              return done(null, false, {
                message: 'Invalid email or password',
                code: AUTH_RESULT_CODES.INVALID_CREDENTIALS,
              });
            }

            // Additional user validations
            const validationResult = await this._validateUserAccess(user);
            if (!validationResult.valid) {
              return done(null, false, validationResult);
            }

            // Success - update metrics and log
            const authTime = Date.now() - startTime;
            this._updateAuthMetrics('local', authTime);

            await this._logAuthEvent(AUTH_EVENTS.LOGIN_SUCCESS, {
              userId: user.id,
              email: normalizedEmail,
              domain,
              workspaceId: user.memberships[0]?.workspace.id,
              method: 'local',
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            // Clear failed attempts on success
            this._clearFailedAttempts(normalizedEmail);

            return done(null, user);
          } catch (error) {
            const authTime = Date.now() - startTime;

            await this._handleAuthError(error, {
              email: this._normalizeEmail(email),
              method: 'local',
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            if (error instanceof ApiError) {
              return done(null, false, {
                message: error.message,
                code: error.code,
              });
            }

            return done(error);
          }
        }),
      ),
    );

    logger.debug('Local authentication strategy configured');
  }

  /**
   * Configure Google OAuth Strategy
   * Handles Google OAuth with automatic workspace assignment
   */
  configureGoogleStrategy() {
    if (!config.oauth.google.clientId || !config.oauth.google.clientSecret) {
      logger.warn('Google OAuth not configured - missing client credentials');
      return;
    }

    passport.use(
      STRATEGIES.GOOGLE,
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: config.oauth.google.callbackUrl,
          scope: config.oauth.google.scope,
          passReqToCallback: true,
        },
        asyncHandler(async (req, accessToken, refreshToken, profile, done) => {
          const startTime = Date.now();

          try {
            const email = profile.emails?.[0]?.value;
            if (!email) {
              throw new ValidationError('No email found in Google profile');
            }

            const normalizedEmail = this._normalizeEmail(email);
            const domain = this._extractDomain(normalizedEmail);
            const name =
              profile.displayName ||
              profile.name?.givenName ||
              profile.name?.familyName ||
              'Unknown User';

            // Check for personal email domains
            if (this._isPersonalEmail(normalizedEmail)) {
              await this._logAuthEvent(AUTH_EVENTS.OAUTH_FAILURE, {
                email: normalizedEmail,
                domain,
                reason: 'personal_email_blocked',
                provider: 'google',
                ip: req.ip,
              });

              return done(null, false, {
                message:
                  'Personal email domains are not allowed. Please use your company email.',
                code: AUTH_RESULT_CODES.PERSONAL_EMAIL_BLOCKED,
              });
            }

            // Find or create user
            let user = await prisma.user.findUnique({
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
                        settings: true,
                      },
                    },
                  },
                },
              },
            });

            if (user) {
              // Existing user - update profile information
              user = await prisma.user.update({
                where: { id: user.id },
                data: {
                  name: name,
                  emailVerified: true,
                  lastLoginAt: new Date(),
                  loginCount: { increment: 1 },
                },
                include: {
                  memberships: {
                    where: { isActive: true },
                    include: {
                      workspace: {
                        select: {
                          id: true,
                          name: true,
                          domain: true,
                          settings: true,
                        },
                      },
                    },
                  },
                },
              });
            } else {
              // New user - create user and workspace assignment
              const result = await this._createUserWithWorkspace(
                normalizedEmail,
                name,
                domain,
                'google',
              );

              user = result.user;
              this.authMetrics.newRegistrations++;

              if (result.workspaceCreated) {
                this.authMetrics.workspacesCreated++;
              }
            }

            // Validate user access
            const validationResult = await this._validateUserAccess(user);
            if (!validationResult.valid) {
              return done(null, false, validationResult);
            }

            // Success - update metrics and log
            const authTime = Date.now() - startTime;
            this._updateAuthMetrics('oauth', authTime);

            await this._logAuthEvent(AUTH_EVENTS.OAUTH_SUCCESS, {
              userId: user.id,
              email: normalizedEmail,
              domain,
              workspaceId: user.memberships[0]?.workspace.id,
              provider: 'google',
              profileId: profile.id,
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            return done(null, user);
          } catch (error) {
            const authTime = Date.now() - startTime;

            await this._handleAuthError(error, {
              email: profile.emails?.[0]?.value,
              provider: 'google',
              profileId: profile.id,
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            if (error instanceof ApiError) {
              return done(null, false, {
                message: error.message,
                code: error.code,
              });
            }

            return done(error);
          }
        }),
      ),
    );

    logger.debug('Google OAuth strategy configured');
  }

  /**
   * Configure Microsoft OAuth Strategy
   * Handles Microsoft OAuth with automatic workspace assignment
   */
  configureMicrosoftStrategy() {
    if (
      !config.oauth.microsoft.clientId ||
      !config.oauth.microsoft.clientSecret
    ) {
      logger.warn(
        'Microsoft OAuth not configured - missing client credentials',
      );
      return;
    }

    passport.use(
      STRATEGIES.MICROSOFT,
      new MicrosoftStrategy(
        {
          clientID: config.oauth.microsoft.clientId,
          clientSecret: config.oauth.microsoft.clientSecret,
          callbackURL: config.oauth.microsoft.callbackUrl,
          tenant: config.oauth.microsoft.tenant,
          passReqToCallback: true,
        },
        asyncHandler(async (req, accessToken, refreshToken, profile, done) => {
          const startTime = Date.now();

          try {
            const email = profile.emails?.[0]?.value || profile._json?.mail;
            if (!email) {
              throw new ValidationError('No email found in Microsoft profile');
            }

            const normalizedEmail = this._normalizeEmail(email);
            const domain = this._extractDomain(normalizedEmail);
            const name =
              profile.displayName || profile.name?.givenName || 'Unknown User';

            // Check for personal email domains
            if (this._isPersonalEmail(normalizedEmail)) {
              await this._logAuthEvent(AUTH_EVENTS.OAUTH_FAILURE, {
                email: normalizedEmail,
                domain,
                reason: 'personal_email_blocked',
                provider: 'microsoft',
                ip: req.ip,
              });

              return done(null, false, {
                message:
                  'Personal email domains are not allowed. Please use your company email.',
                code: AUTH_RESULT_CODES.PERSONAL_EMAIL_BLOCKED,
              });
            }

            // Find or create user (similar to Google strategy)
            let user = await prisma.user.findUnique({
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
                        settings: true,
                      },
                    },
                  },
                },
              },
            });

            if (user) {
              // Update existing user
              user = await prisma.user.update({
                where: { id: user.id },
                data: {
                  name: name,
                  emailVerified: true,
                  lastLoginAt: new Date(),
                  loginCount: { increment: 1 },
                },
                include: {
                  memberships: {
                    where: { isActive: true },
                    include: {
                      workspace: {
                        select: {
                          id: true,
                          name: true,
                          domain: true,
                          settings: true,
                        },
                      },
                    },
                  },
                },
              });
            } else {
              // Create new user
              const result = await this._createUserWithWorkspace(
                normalizedEmail,
                name,
                domain,
                'microsoft',
              );

              user = result.user;
              this.authMetrics.newRegistrations++;

              if (result.workspaceCreated) {
                this.authMetrics.workspacesCreated++;
              }
            }

            // Validate user access
            const validationResult = await this._validateUserAccess(user);
            if (!validationResult.valid) {
              return done(null, false, validationResult);
            }

            // Success
            const authTime = Date.now() - startTime;
            this._updateAuthMetrics('oauth', authTime);

            await this._logAuthEvent(AUTH_EVENTS.OAUTH_SUCCESS, {
              userId: user.id,
              email: normalizedEmail,
              domain,
              workspaceId: user.memberships[0]?.workspace.id,
              provider: 'microsoft',
              profileId: profile.id,
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            return done(null, user);
          } catch (error) {
            const authTime = Date.now() - startTime;

            await this._handleAuthError(error, {
              email: profile.emails?.[0]?.value,
              provider: 'microsoft',
              profileId: profile.id,
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            if (error instanceof ApiError) {
              return done(null, false, {
                message: error.message,
                code: error.code,
              });
            }

            return done(error);
          }
        }),
      ),
    );

    logger.debug('Microsoft OAuth strategy configured');
  }

  /**
   * Configure JWT Strategy for API authentication
   * Validates JWT tokens and loads user context with enhanced security
   */
  configureJWTStrategy() {
    passport.use(
      STRATEGIES.JWT,
      new JwtStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: config.auth.jwt.secret,
          issuer: config.auth.jwt.issuer,
          audience: config.auth.jwt.audience,
          passReqToCallback: true,
        },
        asyncHandler(async (req, jwtPayload, done) => {
          const startTime = Date.now();

          try {
            // Validate token type
            if (jwtPayload.type !== TOKEN_TYPES.ACCESS) {
              return done(null, false, {
                message: 'Invalid token type',
                code: AUTH_RESULT_CODES.INVALID_TOKEN_TYPE,
              });
            }

            // Additional JWT validation using our JWT module
            const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
            const validatedToken = await validateToken(token, {
              requiredType: TOKEN_TYPES.ACCESS,
              ipAddress: req.ip,
              deviceId: req.get('X-Device-ID'),
            });

            // Load user with workspace context
            const user = await prisma.user.findUnique({
              where: { id: jwtPayload.sub },
              include: {
                memberships: {
                  where: {
                    isActive: true,
                    workspaceId: jwtPayload.workspace.id,
                  },
                  include: {
                    workspace: {
                      select: {
                        id: true,
                        name: true,
                        domain: true,
                        settings: true,
                      },
                    },
                  },
                },
              },
            });

            if (!user || !user.isActive) {
              return done(null, false, {
                message: 'User not found or inactive',
                code: AUTH_RESULT_CODES.USER_NOT_FOUND,
              });
            }

            // Verify workspace access
            if (!user.memberships || user.memberships.length === 0) {
              return done(null, false, {
                message: 'No workspace access',
                code: AUTH_RESULT_CODES.NO_WORKSPACE_ACCESS,
              });
            }

            // Add token context to user object
            user.tokenContext = {
              jti: jwtPayload.jti,
              iat: jwtPayload.iat,
              exp: jwtPayload.exp,
              workspace: jwtPayload.workspace,
              deviceId: jwtPayload.deviceId,
              permissions: jwtPayload.user?.permissions || [],
            };

            // Update metrics
            const authTime = Date.now() - startTime;
            this.authMetrics.jwtValidations++;
            this._updateAuthTime(authTime);

            return done(null, user);
          } catch (error) {
            const authTime = Date.now() - startTime;

            logger.warn('JWT authentication failed', {
              error: error.message,
              userId: jwtPayload?.sub,
              workspaceId: jwtPayload?.workspace?.id,
              authTime,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
            });

            if (error instanceof ApiError) {
              return done(null, false, {
                message: error.message,
                code: error.code,
              });
            }

            return done(error);
          }
        }),
      ),
    );

    logger.debug('JWT authentication strategy configured');
  }

  /**
   * Configure Passport serialization (required but not used in JWT setup)
   */
  configurePassportSerialization() {
    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(
      asyncHandler(async (id, done) => {
        try {
          const user = await prisma.user.findUnique({
            where: { id },
            include: {
              memberships: {
                where: { isActive: true },
                include: {
                  workspace: {
                    select: {
                      id: true,
                      name: true,
                      domain: true,
                      settings: true,
                    },
                  },
                },
              },
            },
          });
          done(null, user);
        } catch (error) {
          logger.error('User deserialization failed', {
            userId: id,
            error: error.message,
          });
          done(error);
        }
      }),
    );
  }

  /**
   * Get authentication metrics
   * @returns {Object} Authentication metrics
   */
  getMetrics() {
    const uptime = Date.now() - this.authMetrics.lastReset.getTime();
    const totalAuth =
      this.authMetrics.localLogins + this.authMetrics.oauthLogins;
    const successRate =
      totalAuth > 0
        ? (totalAuth / (totalAuth + this.authMetrics.failedAttempts)) * 100
        : 100;

    return {
      ...this.authMetrics,
      uptime: Math.round(uptime / 1000), // seconds
      totalAuthentications: totalAuth,
      successRate: Math.round(successRate * 100) / 100,
      lockedAccountsCount: this.lockedAccounts.size,
      rateLimitedIPs: this.rateLimitTracking.size,
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
      metrics.averageAuthTime < 1000 &&
      metrics.securityViolations < 10;

    return {
      status: isHealthy ? 'healthy' : 'degraded',
      checks: {
        successRate: {
          status: metrics.successRate > 95 ? 'pass' : 'fail',
          value: `${metrics.successRate}%`,
          threshold: '95%',
        },
        averageAuthTime: {
          status: metrics.averageAuthTime < 1000 ? 'pass' : 'fail',
          value: `${metrics.averageAuthTime}ms`,
          threshold: '1000ms',
        },
        securityViolations: {
          status: metrics.securityViolations < 10 ? 'pass' : 'warn',
          value: metrics.securityViolations,
          threshold: 10,
        },
      },
      metrics: {
        uptime: metrics.uptime,
        totalAuthentications: metrics.totalAuthentications,
        successRate: metrics.successRate,
        lockedAccounts: metrics.lockedAccountsCount,
      },
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Reset authentication metrics
   */
  resetMetrics() {
    this.authMetrics = {
      localLogins: 0,
      oauthLogins: 0,
      jwtValidations: 0,
      failedAttempts: 0,
      newRegistrations: 0,
      workspacesCreated: 0,
      accountsLocked: 0,
      securityViolations: 0,
      averageAuthTime: 0,
      lastReset: new Date(),
    };

    this.authTimes = [];

    logger.info('Authentication metrics reset');
  }

  // === Private Methods ===

  /**
   * Create user with automatic workspace assignment
   * @param {string} email - User email
   * @param {string} name - User name
   * @param {string} domain - Email domain
   * @param {string} provider - OAuth provider
   * @returns {Object} Created user and workspace info
   * @private
   */
  async _createUserWithWorkspace(email, name, domain, provider = 'local') {
    return await prisma.$transaction(async (tx) => {
      // Find or create workspace
      let workspace = await tx.workspace.findUnique({
        where: { domain },
      });

      let workspaceCreated = false;
      if (!workspace) {
        workspace = await tx.workspace.create({
          data: {
            name: this._generateWorkspaceName(domain),
            domain,
            settings: {
              allowedAuthProviders: [provider],
            },
          },
        });
        workspaceCreated = true;

        await this._logAuthEvent(AUTH_EVENTS.WORKSPACE_CREATED, {
          workspaceId: workspace.id,
          workspaceName: workspace.name,
          domain,
          createdBy: email,
          provider,
        });
      }

      // Create user
      const user = await tx.user.create({
        data: {
          email,
          name,
          emailVerified: provider !== 'local', // OAuth users are pre-verified
          lastLoginAt: new Date(),
          loginCount: 1,
        },
      });

      // Determine role (first user in workspace becomes admin)
      const existingMemberships = await tx.membership.count({
        where: { workspaceId: workspace.id, isActive: true },
      });

      const role =
        existingMemberships === 0 ? USER_ROLES.ADMIN : USER_ROLES.MEMBER;

      // Create membership
      await tx.membership.create({
        data: {
          userId: user.id,
          workspaceId: workspace.id,
          role,
          isActive: true,
        },
      });

      await this._logAuthEvent(AUTH_EVENTS.MEMBERSHIP_CREATED, {
        userId: user.id,
        workspaceId: workspace.id,
        role,
        email,
        provider,
      });

      // Fetch user with memberships
      const userWithMemberships = await tx.user.findUnique({
        where: { id: user.id },
        include: {
          memberships: {
            where: { isActive: true },
            include: {
              workspace: {
                select: {
                  id: true,
                  name: true,
                  domain: true,
                  settings: true,
                },
              },
            },
          },
        },
      });

      return {
        user: userWithMemberships,
        workspace,
        workspaceCreated,
        role,
      };
    });
  }

  /**
   * Perform comprehensive security checks
   * @param {string} email - User email
   * @param {string} ip - IP address
   * @param {Object} req - Request object
   * @private
   */
  async _performSecurityChecks(email, ip, req) {
    // Check if account is locked
    if (this.lockedAccounts.has(email)) {
      const lockInfo = this.lockedAccounts.get(email);
      if (Date.now() < lockInfo.unlockTime) {
        throw new SecurityError(
          'Account is temporarily locked due to suspicious activity',
          AUTH_RESULT_CODES.ACCOUNT_LOCKED,
        );
      } else {
        // Unlock expired lock
        this.lockedAccounts.delete(email);
      }
    }

    // Check rate limiting
    const rateLimitKey = `${ip}:${email}`;
    const rateLimitInfo = this.rateLimitTracking.get(rateLimitKey);

    if (rateLimitInfo && rateLimitInfo.attempts >= 10) {
      if (Date.now() < rateLimitInfo.resetTime) {
        throw new SecurityError(
          'Too many authentication attempts. Please try again later.',
          AUTH_RESULT_CODES.RATE_LIMIT_EXCEEDED,
        );
      } else {
        // Reset expired rate limit
        this.rateLimitTracking.delete(rateLimitKey);
      }
    }

    // Check for suspicious patterns
    const userAgent = req.get('User-Agent');
    if (this._detectSuspiciousActivity(email, ip, userAgent)) {
      this.authMetrics.securityViolations++;

      await this._logAuthEvent(AUTH_EVENTS.SUSPICIOUS_ACTIVITY, {
        email,
        ip,
        userAgent,
        reason: 'unusual_access_pattern',
      });

      throw new SecurityError(
        'Suspicious activity detected. Please verify your identity.',
        AUTH_RESULT_CODES.SECURITY_VIOLATION,
      );
    }
  }

  /**
   * Handle failed authentication attempt
   * @param {string} email - User email
   * @param {string} ip - IP address
   * @param {string} reason - Failure reason
   * @private
   */
  async _handleFailedAttempt(email, ip, reason) {
    this.authMetrics.failedAttempts++;

    // Track failed attempts per email
    const failedAttempts = this._getFailedAttempts(email);
    this._setFailedAttempts(email, failedAttempts + 1);

    // Track rate limiting per IP + email
    const rateLimitKey = `${ip}:${email}`;
    const rateLimitInfo = this.rateLimitTracking.get(rateLimitKey) || {
      attempts: 0,
      resetTime: Date.now() + 15 * 60 * 1000, // 15 minutes
    };

    rateLimitInfo.attempts++;
    this.rateLimitTracking.set(rateLimitKey, rateLimitInfo);

    // Lock account if too many failures
    if (failedAttempts >= this.securityConfig.maxFailedAttempts) {
      this.lockedAccounts.set(email, {
        unlockTime: Date.now() + this.securityConfig.lockoutDuration,
        reason: 'max_failed_attempts',
      });

      this.authMetrics.accountsLocked++;

      await this._logAuthEvent(AUTH_EVENTS.ACCOUNT_LOCKED, {
        email,
        ip,
        reason,
        failedAttempts,
        lockoutDuration: this.securityConfig.lockoutDuration,
      });
    }

    await this._logAuthEvent(AUTH_EVENTS.LOGIN_FAILURE, {
      email,
      ip,
      reason,
      failedAttempts,
    });
  }

  /**
   * Handle authentication errors
   * @param {Error} error - Authentication error
   * @param {Object} context - Error context
   * @private
   */
  async _handleAuthError(error, context) {
    this.authMetrics.failedAttempts++;

    logger.error('Authentication error occurred', {
      error: error.message,
      stack: error.stack,
      context,
    });

    await this._logAuthEvent(AUTH_EVENTS.LOGIN_FAILURE, {
      ...context,
      error: error.message,
    });
  }

  /**
   * Validate user access
   * @param {Object} user - User object
   * @returns {Object} Validation result
   * @private
   */
  async _validateUserAccess(user) {
    // Check if email is verified
    if (!user.emailVerified) {
      return {
        valid: false,
        message: 'Please verify your email before signing in',
        code: AUTH_RESULT_CODES.EMAIL_NOT_VERIFIED,
      };
    }

    // Check if user is active
    if (!user.isActive) {
      return {
        valid: false,
        message: 'Your account has been deactivated',
        code: AUTH_RESULT_CODES.ACCOUNT_DEACTIVATED,
      };
    }

    // Check workspace membership
    if (!user.memberships || user.memberships.length === 0) {
      return {
        valid: false,
        message: 'No workspace access found',
        code: AUTH_RESULT_CODES.NO_WORKSPACE_ACCESS,
      };
    }

    return { valid: true };
  }

  /**
   * Update authentication metrics
   * @param {string} method - Authentication method
   * @param {number} authTime - Authentication time
   * @private
   */
  _updateAuthMetrics(method, authTime) {
    if (method === 'local') {
      this.authMetrics.localLogins++;
    } else if (method === 'oauth') {
      this.authMetrics.oauthLogins++;
    }

    this._updateAuthTime(authTime);
  }

  /**
   * Update authentication time metrics
   * @param {number} time - Authentication time
   * @private
   */
  _updateAuthTime(time) {
    this.authTimes.push(time);

    if (this.authTimes.length > this.maxAuthTimeHistory) {
      this.authTimes.shift();
    }

    this.authMetrics.averageAuthTime =
      this.authTimes.reduce((sum, t) => sum + t, 0) / this.authTimes.length;
  }

  /**
   * Generate workspace name from domain
   * @param {string} domain - Email domain
   * @returns {string} Workspace name
   * @private
   */
  _generateWorkspaceName(domain) {
    const name = domain
      .replace(/\.(com|org|net|edu|gov|mil|int|co\.uk|co\.in)$/, '')
      .split('.')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');

    return name || 'Workspace';
  }

  /**
   * Log authentication events for audit trail
   * @param {string} event - Event type
   * @param {Object} data - Event data
   * @private
   */
  async _logAuthEvent(event, data) {
    const logEntry = {
      event,
      timestamp: generateTimestamp(),
      data: {
        ...data,
        // Remove sensitive data
        password: undefined,
        passwordHash: undefined,
        accessToken: undefined,
        refreshToken: undefined,
      },
      source: 'AUTH_MANAGER',
      environment: config.NODE_ENV,
    };

    // Use logger's auth method for authentication events
    logger.auth(event, logEntry.data);

    // Debug logging in development
    if (config.isDevelopment() && config.logging.level === 'debug') {
      logger.debug('Authentication Event', logEntry);
    }
  }

  /**
   * Utility methods for email and domain handling
   */
  _normalizeEmail(email) {
    return email.toLowerCase().trim();
  }

  _extractDomain(email) {
    return email.split('@')[1];
  }

  _isPersonalEmail(email) {
    const domain = this._extractDomain(email);
    // Fallback to default list if config.workspace.blockedDomains is missing or empty
    const blocked =
      config.workspace &&
      Array.isArray(config.workspace.blockedDomains) &&
      config.workspace.blockedDomains.length > 0
        ? config.workspace.blockedDomains
        : [
            'gmail.com',
            'yahoo.com',
            'hotmail.com',
            'aol.com',
            'outlook.com',
            'icloud.com',
            'mail.com',
            'protonmail.com',
            'zoho.com',
            'gmx.com',
            'yandex.com',
            'msn.com',
          ];
    return blocked.includes(domain);
  }

  /**
   * Failed attempts tracking
   */
  _getFailedAttempts(email) {
    return this.rateLimitTracking.get(`failed:${email}`)?.attempts || 0;
  }

  _setFailedAttempts(email, count) {
    this.rateLimitTracking.set(`failed:${email}`, {
      attempts: count,
      resetTime: Date.now() + 3600000, // 1 hour
    });
  }

  _clearFailedAttempts(email) {
    this.rateLimitTracking.delete(`failed:${email}`);
  }

  /**
   * Detect suspicious activity patterns
   * @param {string} email - User email
   * @param {string} ip - IP address
   * @param {string} userAgent - User agent
   * @returns {boolean} True if suspicious
   * @private
   */
  _detectSuspiciousActivity(email, ip, userAgent) {
    // Basic suspicious activity detection
    // In production, this would be more sophisticated

    // Check for missing or suspicious user agent
    if (!userAgent || userAgent.length < 10) {
      return true;
    }

    // Check for known bot patterns
    const botPatterns = /bot|crawler|spider|scraper|curl|wget/i;
    if (botPatterns.test(userAgent)) {
      return true;
    }

    return false;
  }

  /**
   * Get configured strategies
   * @returns {Array} List of configured strategies
   * @private
   */
  _getConfiguredStrategies() {
    const strategies = [STRATEGIES.LOCAL, STRATEGIES.JWT];

    if (config.oauth.google.clientId) {
      strategies.push(STRATEGIES.GOOGLE);
    }

    if (config.oauth.microsoft.clientId) {
      strategies.push(STRATEGIES.MICROSOFT);
    }

    return strategies;
  }

  /**
   * Setup cleanup intervals for expired data
   * @private
   */
  _setupCleanupIntervals() {
    // Clean up expired rate limits and locks every 15 minutes
    setInterval(() => {
      const now = Date.now();

      // Clean rate limits
      for (const [key, info] of this.rateLimitTracking.entries()) {
        if (now > info.resetTime) {
          this.rateLimitTracking.delete(key);
        }
      }

      // Clean account locks
      for (const [email, lockInfo] of this.lockedAccounts.entries()) {
        if (now > lockInfo.unlockTime) {
          this.lockedAccounts.delete(email);
        }
      }

      logger.debug('Authentication cleanup completed', {
        rateLimitEntries: this.rateLimitTracking.size,
        lockedAccounts: this.lockedAccounts.size,
      });
    }, 15 * 60 * 1000); // 15 minutes
  }

  /**
   * Graceful shutdown
   * @returns {Promise<void>}
   */
  async gracefulShutdown() {
    logger.info('Authentication Manager shutting down gracefully');

    // Clear all tracking data
    this.rateLimitTracking.clear();
    this.lockedAccounts.clear();
    this.authTimes = [];

    logger.info('Authentication Manager shutdown completed', {
      finalMetrics: this.getMetrics(),
    });
  }
}

// Create singleton instance
const authManager = new AuthenticationManager();

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  await authManager.gracefulShutdown();
});

process.on('SIGINT', async () => {
  await authManager.gracefulShutdown();
});

// Export authentication manager and utilities
module.exports = {
  passport,
  authenticate: (strategy, options = {}) => {
    return passport.authenticate(strategy, {
      session: false, // We use JWT, not sessions
      ...options,
    });
  },
  initialize: () => passport.initialize(),
  AUTH_EVENTS,
};
