/**
 * Central Configuration Module
 *
 * This module serves as the single source of truth for all application configuration
 * in a multi-tenant SaaS environment. It provides enterprise-grade configuration
 * management with validation, type safety, and integration with the logging system.
 *
 * Key Features:
 * - Environment variable validation with detailed error reporting
 * - Type coercion and intelligent defaults
 * - Configuration grouping by functional domain
 * - Runtime validation with startup checks
 * - Integration with logger and error handling systems
 * - Security-focused configuration masking
 * - Development vs Production optimizations
 * - Configuration change detection and monitoring
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

require('dotenv').config();

const { generateTimestamp } = require('../utils/common');

/**
 * Configuration Error Class
 * Extends the standard Error with configuration-specific context
 */
class ConfigurationError extends Error {
  constructor(message, key, value, suggestions = []) {
    super(message);
    this.name = 'ConfigurationError';
    this.key = key;
    this.value = value;
    this.suggestions = suggestions;
    this.timestamp = generateTimestamp();
  }
}

/**
 * Configuration Validator Class
 * Handles all configuration validation and type coercion
 */
class ConfigurationValidator {
  constructor() {
    this.validationErrors = [];
    this.warnings = [];
  }

  /**
   * Validates that required environment variables are present
   * @param {string} key - The environment variable key
   * @param {string} defaultValue - Default value if not required
   * @param {Object} options - Validation options
   * @returns {string} The environment variable value
   * @throws {ConfigurationError} If required variable is missing
   */
  requireEnv(key, defaultValue = undefined, options = {}) {
    const value = process.env[key];
    const { description, suggestions = [] } = options;

    if (!value && defaultValue === undefined) {
      const error = new ConfigurationError(
        `Missing required environment variable: ${key}${
          description ? ` (${description})` : ''
        }`,
        key,
        null,
        suggestions,
      );
      this.validationErrors.push(error);
      throw error;
    }

    if (!value && defaultValue !== undefined) {
      this.warnings.push({
        key,
        message: `Using default value for ${key}: ${defaultValue}${
          description ? ` (${description})` : ''
        }`,
        defaultValue,
        timestamp: generateTimestamp(),
      });
    }

    return value || defaultValue;
  }

  /**
   * Converts string environment variable to integer with validation
   * @param {string} key - The environment variable key
   * @param {number} defaultValue - Default value
   * @param {Object} options - Validation options
   * @returns {number} Parsed integer value
   */
  getIntEnv(key, defaultValue, options = {}) {
    const value = process.env[key];
    const { min, max, description } = options;

    if (!value) {
      if (defaultValue !== undefined) {
        this.warnings.push({
          key,
          message: `Using default integer value for ${key}: ${defaultValue}${
            description ? ` (${description})` : ''
          }`,
          defaultValue,
          timestamp: generateTimestamp(),
        });
      }
      return defaultValue;
    }

    const parsed = parseInt(value, 10);

    if (isNaN(parsed)) {
      throw new ConfigurationError(
        `Invalid integer value for ${key}: ${value}${
          description ? ` (${description})` : ''
        }`,
        key,
        value,
        ['Provide a valid integer value'],
      );
    }

    if (min !== undefined && parsed < min) {
      throw new ConfigurationError(
        `Value for ${key} (${parsed}) is below minimum (${min})${
          description ? ` (${description})` : ''
        }`,
        key,
        value,
        [`Use a value >= ${min}`],
      );
    }

    if (max !== undefined && parsed > max) {
      throw new ConfigurationError(
        `Value for ${key} (${parsed}) exceeds maximum (${max})${
          description ? ` (${description})` : ''
        }`,
        key,
        value,
        [`Use a value <= ${max}`],
      );
    }

    return parsed;
  }

  /**
   * Converts string environment variable to boolean with validation
   * @param {string} key - The environment variable key
   * @param {boolean} defaultValue - Default value
   * @param {Object} options - Validation options
   * @returns {boolean} Parsed boolean value
   */
  getBoolEnv(key, defaultValue, options = {}) {
    const value = process.env[key];
    const { description } = options;

    if (!value) {
      if (defaultValue !== undefined) {
        this.warnings.push({
          key,
          message: `Using default boolean value for ${key}: ${defaultValue}${
            description ? ` (${description})` : ''
          }`,
          defaultValue,
          timestamp: generateTimestamp(),
        });
      }
      return defaultValue;
    }

    const normalizedValue = value.toLowerCase();
    const truthyValues = ['true', '1', 'yes', 'on', 'enabled'];
    const falsyValues = ['false', '0', 'no', 'off', 'disabled'];

    if (truthyValues.includes(normalizedValue)) {
      return true;
    }

    if (falsyValues.includes(normalizedValue)) {
      return false;
    }

    throw new ConfigurationError(
      `Invalid boolean value for ${key}: ${value}${
        description ? ` (${description})` : ''
      }`,
      key,
      value,
      ['Use: true, false, 1, 0, yes, no, on, off, enabled, disabled'],
    );
  }

  /**
   * Validates array environment variable
   * @param {string} key - The environment variable key
   * @param {Array} defaultValue - Default value
   * @param {Object} options - Validation options
   * @returns {Array} Parsed array value
   */
  getArrayEnv(key, defaultValue = [], options = {}) {
    const value = process.env[key];
    const { separator = ',', description } = options;

    if (!value) {
      if (defaultValue.length > 0) {
        this.warnings.push({
          key,
          message: `Using default array value for ${key}: [${defaultValue.join(
            ', ',
          )}]${description ? ` (${description})` : ''}`,
          defaultValue,
          timestamp: generateTimestamp(),
        });
      }
      return defaultValue;
    }

    return value
      .split(separator)
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  /**
   * Get validation summary
   * @returns {Object} Validation summary
   */
  getValidationSummary() {
    return {
      hasErrors: this.validationErrors.length > 0,
      hasWarnings: this.warnings.length > 0,
      errorCount: this.validationErrors.length,
      warningCount: this.warnings.length,
      errors: this.validationErrors,
      warnings: this.warnings,
    };
  }
}

// Create validator instance
const validator = new ConfigurationValidator();

/**
 * Application Configuration Object
 * Organized by functional domains for better maintainability
 */
const config = {
  // === Node Environment ===
  NODE_ENV: validator.requireEnv('NODE_ENV', 'development', {
    description: 'Application environment',
    suggestions: ['development', 'production', 'test', 'staging'],
  }),

  // === Application Settings ===
  app: {
    name: validator.requireEnv('APP_NAME', 'AI-Persona-Backend', {
      description: 'Application name for branding and logging',
    }),
    version: validator.requireEnv('APP_VERSION', '1.0.0', {
      description: 'Application version for API versioning',
    }),
    env: validator.requireEnv('NODE_ENV', 'development', {
      description: 'Runtime environment',
    }),
    timezone: validator.requireEnv('TZ', 'UTC', {
      description: 'Application timezone',
    }),

    // URLs
    apiUrl: validator.requireEnv('API_URL', 'http://localhost:3000', {
      description: 'Backend API base URL',
    }),
    clientUrl: validator.requireEnv('CLIENT_URL', 'http://localhost:3001', {
      description: 'Frontend client base URL',
    }),
  },

  // === Server Configuration ===
  server: {
    port: validator.getIntEnv('PORT', 3000, {
      min: 1,
      max: 65535,
      description: 'Server port number',
    }),
    host: validator.requireEnv('HOST', '0.0.0.0', {
      description: 'Server host address',
    }),

    // Server limits
    bodyLimit: validator.requireEnv('BODY_LIMIT', '10mb', {
      description: 'Request body size limit',
    }),
    socketTimeout: validator.getIntEnv('SOCKET_TIMEOUT', 120000, {
      min: 1000,
      description: 'Socket timeout in milliseconds',
    }),

    // Production settings
    trustProxy: validator.getBoolEnv('TRUST_PROXY', true, {
      description: 'Trust proxy headers (for load balancers)',
    }),
    enableCluster: validator.getBoolEnv('ENABLE_CLUSTER', false, {
      description: 'Enable cluster mode for multi-core systems',
    }),
    maxWorkers: validator.getIntEnv(
      'MAX_WORKERS',
      require('os').cpus().length,
      {
        min: 1,
        max: require('os').cpus().length * 2,
        description: 'Maximum worker processes in cluster mode',
      },
    ),

    // HTTPS settings
    enableHTTPS: validator.getBoolEnv('ENABLE_HTTPS', false, {
      description: 'Enable HTTPS server',
    }),

    // Health and monitoring
    healthCheckInterval: validator.getIntEnv('HEALTH_CHECK_INTERVAL', 30000, {
      min: 5000,
      description: 'Health check interval in milliseconds',
    }),
    shutdownTimeout: validator.getIntEnv('SHUTDOWN_TIMEOUT', 30000, {
      min: 5000,
      description: 'Graceful shutdown timeout in milliseconds',
    }),
    maxMemoryUsage: validator.getIntEnv('MAX_MEMORY_USAGE', 1024, {
      min: 128,
      description: 'Maximum memory usage in MB before warnings',
    }),
  },

  // === Database Configuration ===
  database: {
    url: validator.requireEnv(
      'DATABASE_URL',
      'postgresql://user:pass@localhost:5432/ai_persona_db',
      {
        description: 'PostgreSQL database connection string',
        suggestions: ['postgresql://user:pass@localhost:5432/dbname'],
      },
    ),
    ssl: validator.getBoolEnv('DATABASE_SSL', false, {
      description: 'Enable SSL for database connections',
    }),
    poolSize: validator.getIntEnv('DATABASE_POOL_SIZE', 10, {
      min: 1,
      max: 50,
      description: 'Database connection pool size',
    }),
    connectionTimeout: validator.getIntEnv(
      'DATABASE_CONNECTION_TIMEOUT',
      10000,
      {
        min: 1000,
        description: 'Database connection timeout in milliseconds',
      },
    ),
    queryTimeout: validator.getIntEnv('DATABASE_QUERY_TIMEOUT', 30000, {
      min: 1000,
      description: 'Database query timeout in milliseconds',
    }),

    // Migration settings
    runMigrationsOnStartup: validator.getBoolEnv(
      'RUN_MIGRATIONS_ON_STARTUP',
      false,
      {
        description: 'Automatically run migrations on startup',
      },
    ),
  },

  // === Authentication & Security ===
  auth: {
    // JWT Configuration
    jwt: {
      secret: validator.requireEnv('JWT_SECRET', 'your-fallback-secret-key', {
        description: 'JWT signing secret (minimum 32 characters)',
        suggestions: ['Generate a strong random string: openssl rand -hex 32'],
      }),
      refreshSecret: validator.requireEnv(
        'JWT_REFRESH_SECRET',
        'your-refresh-secret-key',
        {
          description: 'JWT refresh token signing secret',
          suggestions: [
            'Generate a strong random string: openssl rand -hex 32',
          ],
        },
      ),
      accessTokenExpiry: validator.requireEnv('JWT_EXPIRES_IN', '15m', {
        description: 'Access token expiration time',
      }),
      refreshTokenExpiry: validator.requireEnv('JWT_REFRESH_EXPIRES_IN', '7d', {
        description: 'Refresh token expiration time',
      }),
      issuer: validator.requireEnv('JWT_ISSUER', 'ai-persona-backend', {
        description: 'JWT token issuer',
      }),
      audience: validator.requireEnv('JWT_AUDIENCE', 'ai-persona-app', {
        description: 'JWT token audience',
      }),
    },

    // Password Security
    password: {
      bcryptRounds: validator.getIntEnv('BCRYPT_ROUNDS', 12, {
        min: 10,
        max: 15,
        description: 'Bcrypt hashing rounds',
      }),
      minLength: validator.getIntEnv('PASSWORD_MIN_LENGTH', 8, {
        min: 6,
        max: 128,
        description: 'Minimum password length',
      }),
      requireUppercase: validator.getBoolEnv(
        'PASSWORD_REQUIRE_UPPERCASE',
        true,
        {
          description: 'Require uppercase letters in passwords',
        },
      ),
      requireNumbers: validator.getBoolEnv('PASSWORD_REQUIRE_NUMBERS', true, {
        description: 'Require numbers in passwords',
      }),
      requireSpecialChars: validator.getBoolEnv(
        'PASSWORD_REQUIRE_SPECIAL',
        true,
        {
          description: 'Require special characters in passwords',
        },
      ),
    },

    // Session Management
    session: {
      maxConcurrentSessions: validator.getIntEnv('MAX_CONCURRENT_SESSIONS', 5, {
        min: 1,
        max: 20,
        description: 'Maximum concurrent sessions per user',
      }),
      cleanupInterval: validator.getIntEnv(
        'SESSION_CLEANUP_INTERVAL',
        3600000,
        {
          min: 300000,
          description: 'Session cleanup interval in milliseconds',
        },
      ),
    },
  },

  // === OAuth Providers ===
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl: validator.requireEnv(
        'GOOGLE_CALLBACK_URL',
        `${
          process.env.API_URL || `http://localhost:${process.env.PORT || 3001}`
        }/api/v1/auth/google/callback`,
        {
          description: 'Google OAuth callback URL',
        },
      ),
      scope: ['profile', 'email'],
    },

    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackUrl: validator.requireEnv(
        'MICROSOFT_CALLBACK_URL',
        `${
          process.env.API_URL || `http://localhost:${process.env.PORT || 3001}`
        }/api/v1/auth/microsoft/callback`,
        {
          description: 'Microsoft OAuth callback URL',
        },
      ),
      tenant: validator.requireEnv('MICROSOFT_TENANT', 'common', {
        description: 'Microsoft Azure AD tenant',
      }),
    },
  },

  // === Email Configuration ===
  email: {
    provider: validator.requireEnv('EMAIL_PROVIDER', 'smtp', {
      description: 'Email service provider',
      suggestions: ['smtp', 'sendgrid', 'ses', 'mailgun'],
    }),

    // SMTP Configuration
    smtp: {
      host: process.env.SMTP_HOST,
      port: validator.getIntEnv('SMTP_PORT', 587, {
        min: 1,
        max: 65535,
        description: 'SMTP server port',
      }),
      secure: validator.getBoolEnv('SMTP_SECURE', false, {
        description: 'Use secure SMTP connection (TLS)',
      }),
      user: process.env.SMTP_USER,
      password: process.env.SMTP_PASS,
    },

    // Email Settings
    from: {
      name: validator.requireEnv('FROM_NAME', 'AI-Persona', {
        description: 'Email sender name',
      }),
      email: validator.requireEnv('FROM_EMAIL', 'noreply@ai-persona.com', {
        description: 'Email sender address',
      }),
    },

    // Rate limiting
    rateLimit: {
      maxPerHour: validator.getIntEnv('EMAIL_RATE_LIMIT', 100, {
        min: 1,
        description: 'Maximum emails per hour',
      }),
      maxPerDay: validator.getIntEnv('EMAIL_DAILY_LIMIT', 1000, {
        min: 1,
        description: 'Maximum emails per day',
      }),
    },
  },

  // === Security Settings ===
  security: {
    // JWT and Cookie secrets
    jwtSecret: validator.requireEnv('JWT_SECRET', 'your-fallback-secret-key', {
      description: 'JWT signing secret',
    }),
    jwtExpiresIn: validator.requireEnv('JWT_EXPIRES_IN', '7d', {
      description: 'JWT token expiration time',
    }),
    jwtRefreshSecret: validator.requireEnv(
      'JWT_REFRESH_SECRET',
      'your-refresh-secret-key',
      {
        description: 'JWT refresh token secret',
      },
    ),
    cookieSecret: validator.requireEnv('COOKIE_SECRET', 'your-cookie-secret', {
      description: 'Secret for cookie signing',
      suggestions: ['Generate a strong random string: openssl rand -hex 32'],
    }),
    sessionSecret: validator.requireEnv(
      'SESSION_SECRET',
      'your-session-secret',
      {
        description: 'Session secret for express-session',
      },
    ),
    saltRounds: validator.getIntEnv('SALT_ROUNDS', 12, {
      min: 10,
      max: 15,
      description: 'Bcrypt salt rounds',
    }),

    // Rate Limiting
    rateLimit: {
      windowMs: validator.getIntEnv('RATE_LIMIT_WINDOW_MS', 900000, {
        min: 60000,
        description: 'Rate limit window in milliseconds',
      }),
      maxRequests: validator.getIntEnv('RATE_LIMIT_MAX_REQUESTS', 100, {
        min: 1,
        description: 'Maximum requests per window',
      }),

      // Auth-specific rate limiting
      auth: {
        windowMs: validator.getIntEnv('AUTH_RATE_LIMIT_WINDOW_MS', 900000, {
          min: 60000,
          description: 'Auth rate limit window in milliseconds',
        }),
        maxRequests: validator.getIntEnv('AUTH_RATE_LIMIT_MAX_REQUESTS', 5, {
          min: 1,
          description: 'Maximum auth requests per window',
        }),
      },
    },

    // CORS Configuration
    cors: {
      origin: validator.getArrayEnv(
        'CORS_ORIGIN',
        ['http://localhost:3001', 'http://localhost:5173'],
        {
          description: 'Allowed CORS origins',
        },
      ),
      credentials: validator.getBoolEnv('CORS_CREDENTIALS', true, {
        description: 'Allow credentials in CORS requests',
      }),
      optionsSuccessStatus: 200,
    },

    // Content Security Policy
    csp: {
      enabled: validator.getBoolEnv('CSP_ENABLED', true, {
        description: 'Enable Content Security Policy',
      }),
      reportOnly: validator.getBoolEnv('CSP_REPORT_ONLY', false, {
        description: 'CSP report-only mode',
      }),
    },

    // Helmet Security Headers Configuration
    helmet: {
      contentSecurityPolicy: validator.getBoolEnv('HELMET_CSP_ENABLED', true, {
        description: 'Enable Helmet Content Security Policy',
      }),
      hsts: validator.getBoolEnv('HELMET_HSTS_ENABLED', true, {
        description: 'Enable HTTP Strict Transport Security',
      }),
      frameguard: validator.getBoolEnv('HELMET_FRAMEGUARD_ENABLED', true, {
        description: 'Enable X-Frame-Options protection',
      }),
      xssFilter: validator.getBoolEnv('HELMET_XSS_FILTER_ENABLED', true, {
        description: 'Enable XSS protection',
      }),
      noSniff: validator.getBoolEnv('HELMET_NOSNIFF_ENABLED', true, {
        description: 'Enable X-Content-Type-Options nosniff',
      }),
      referrerPolicy: validator.getBoolEnv(
        'HELMET_REFERRER_POLICY_ENABLED',
        true,
        {
          description: 'Enable Referrer Policy',
        },
      ),
      permissionsPolicy: validator.getBoolEnv(
        'HELMET_PERMISSIONS_POLICY_ENABLED',
        true,
        {
          description: 'Enable Permissions Policy',
        },
      ),
    },
  },

  // === Compatibility with existing code ===
  // These maintain backward compatibility
  PORT: validator.getIntEnv('PORT', 3000, {
    min: 1,
    max: 65535,
    description: 'Server port number',
  }),
  DATABASE_URL: validator.requireEnv(
    'DATABASE_URL',
    'postgresql://user:pass@localhost:5432/ai_persona_db',
    {
      description: 'PostgreSQL database connection string',
    },
  ),
  FRONTEND_URL: validator.requireEnv('FRONTEND_URL', 'http://localhost:5173', {
    description: 'Frontend application URL',
  }),
  API_VERSION: 'v1',
  API_PREFIX: '/api/v1',
  RATE_LIMIT_WINDOW: validator.getIntEnv('RATE_LIMIT_WINDOW_MS', 900000, {
    min: 60000,
    description: 'Rate limit window in milliseconds',
  }),
  RATE_LIMIT_MAX: validator.getIntEnv('RATE_LIMIT_MAX_REQUESTS', 100, {
    min: 1,
    description: 'Maximum requests per window',
  }),
  BODY_LIMIT: validator.requireEnv('BODY_LIMIT', '10mb', {
    description: 'Request body size limit',
  }),
  LOG_LEVEL: validator.requireEnv('LOG_LEVEL', 'info', {
    description: 'Logging level',
    suggestions: ['error', 'warn', 'info', 'http', 'debug', 'trace'],
  }),
  LOG_FORMAT: validator.requireEnv('LOG_FORMAT', 'combined', {
    description: 'HTTP log format',
  }),

  // === Documentation ===
  docs: {
    enabled: validator.getBoolEnv('DOCS_ENABLED', true, {
      description: 'Enable API documentation',
    }),
    path: validator.requireEnv('DOCS_PATH', '/api-docs', {
      description: 'API documentation path',
    }),
  },

  // === Session Configuration ===
  session: {
    secret: validator.requireEnv('SESSION_SECRET', 'your-session-secret', {
      description: 'Session secret',
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: validator.getBoolEnv('SESSION_SECURE', false, {
        description: 'Use secure session cookies',
      }),
      httpOnly: true,
      maxAge: validator.getIntEnv('SESSION_MAX_AGE', 86400000, {
        min: 60000,
        description: 'Session max age in milliseconds',
      }),
    },
  },

  // === Development Settings ===
  development: {
    enableApiDocs: validator.getBoolEnv('ENABLE_API_DOCS', true, {
      description: 'Enable API documentation in development',
    }),
    enableDebugRoutes: validator.getBoolEnv('ENABLE_DEBUG_ROUTES', false, {
      description: 'Enable debug routes',
    }),
    seedDatabase: validator.getBoolEnv('SEED_DATABASE', false, {
      description: 'Seed database with test data',
    }),
    mockEmailSending: validator.getBoolEnv('MOCK_EMAIL_SENDING', true, {
      description: 'Mock email sending in development',
    }),
  },

  // === Helper functions ===
  isDevelopment() {
    return this.NODE_ENV === 'development';
  },

  isProduction() {
    return this.NODE_ENV === 'production';
  },

  isTest() {
    return this.NODE_ENV === 'test';
  },

  isStaging() {
    return this.NODE_ENV === 'staging';
  },
};

/**
 * Validates critical configuration on startup
 * @throws {ConfigurationError} If critical configuration is invalid
 */
const validateConfig = () => {
  const validationSummary = validator.getValidationSummary();

  // Check for validation errors
  if (validationSummary.hasErrors) {
    console.error('❌ Configuration validation failed:');
    validationSummary.errors.forEach((error, index) => {
      console.error(`  ${index + 1}. ${error.message}`);
      if (error.suggestions.length > 0) {
        console.error(`     Suggestions: ${error.suggestions.join(', ')}`);
      }
    });
    throw new ConfigurationError(
      `Configuration validation failed with ${validationSummary.errorCount} errors`,
    );
  }

  // Production-specific validations
  if (config.NODE_ENV === 'production') {
    const productionChecks = [
      {
        condition: config.auth.jwt.secret.length < 32,
        message: 'JWT secret must be at least 32 characters in production',
      },
      {
        condition: config.auth.jwt.refreshSecret.length < 32,
        message:
          'JWT refresh secret must be at least 32 characters in production',
      },
      {
        condition: config.security.cookieSecret.length < 32,
        message: 'Cookie secret must be at least 32 characters in production',
      },
      {
        condition: config.auth.password.bcryptRounds < 12,
        message: 'Bcrypt rounds should be at least 12 in production',
      },
    ];

    const productionErrors = productionChecks
      .filter((check) => check.condition)
      .map((check) => check.message);

    if (productionErrors.length > 0) {
      console.error('❌ Production configuration validation failed:');
      productionErrors.forEach((error, index) => {
        console.error(`  ${index + 1}. ${error}`);
      });
      throw new ConfigurationError(
        `Production configuration validation failed with ${productionErrors.length} errors`,
      );
    }
  }

  // Log warnings
  if (validationSummary.hasWarnings) {
    console.warn(
      `⚠️  Configuration warnings (${validationSummary.warningCount}):`,
    );
    validationSummary.warnings.forEach((warning, index) => {
      console.warn(`  ${index + 1}. ${warning.message}`);
    });
  }

  console.log(`✅ Configuration validated for ${config.NODE_ENV} environment`);
};

/**
 * Returns a masked version of sensitive configuration for logging
 * @returns {Object} Sanitized configuration object
 */
const getSafeConfig = () => {
  const safeConfig = JSON.parse(JSON.stringify(config));

  // Mask sensitive values
  const sensitiveKeys = [
    'auth.jwt.secret',
    'auth.jwt.refreshSecret',
    'security.cookieSecret',
    'security.jwtSecret',
    'security.jwtRefreshSecret',
    'security.sessionSecret',
    'email.smtp.password',
    'oauth.google.clientSecret',
    'oauth.microsoft.clientSecret',
  ];

  sensitiveKeys.forEach((keyPath) => {
    const keys = keyPath.split('.');
    let current = safeConfig;

    for (let i = 0; i < keys.length - 1; i++) {
      if (current[keys[i]]) {
        current = current[keys[i]];
      } else {
        return;
      }
    }

    if (current[keys[keys.length - 1]]) {
      current[keys[keys.length - 1]] = '***';
    }
  });

  // Mask database URL
  if (safeConfig.database?.url) {
    safeConfig.database.url = safeConfig.database.url.replace(
      /:[^:@]*@/,
      ':***@',
    );
  }

  if (safeConfig.DATABASE_URL) {
    safeConfig.DATABASE_URL = safeConfig.DATABASE_URL.replace(
      /:[^:@]*@/,
      ':***@',
    );
  }

  return safeConfig;
};

/**
 * Get configuration health status
 * @returns {Object} Configuration health information
 */
const getConfigHealth = () => {
  const validationSummary = validator.getValidationSummary();

  return {
    status: validationSummary.hasErrors ? 'unhealthy' : 'healthy',
    environment: config.NODE_ENV,
    validationSummary,
    timestamp: generateTimestamp(),
  };
};

// Validate configuration on module load
try {
  validateConfig();
} catch (error) {
  console.error('❌ Configuration initialization failed:', error.message);
  process.exit(1);
}

// Export configuration with utility functions
module.exports = {
  ...config,

  // Utility functions
  validateConfig,
  getSafeConfig,
  getConfigHealth,

  // Environment helpers
  isProduction: () => config.NODE_ENV === 'production',
  isDevelopment: () => config.NODE_ENV === 'development',
  isTest: () => config.NODE_ENV === 'test',
  isStaging: () => config.NODE_ENV === 'staging',

  // Configuration classes for advanced use cases
  ConfigurationError,
  ConfigurationValidator,
};
