const express = require('express');
const morgan = require('morgan');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const slowDown = require('express-slow-down');

// Import configurations
const config = require('./config');
const { helmetMiddleware } = require('./security/helmet');
const { corsMiddleware } = require('./security/cors');
const {
  rateLimitManager,
  general,
  auth,
  api,
  upload,
  RATE_LIMIT_TIERS,
  RATE_LIMIT_TYPES,
  createRateLimiter,
} = require('./security/rateLimit');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
// Import utilities
const logger = require('./utils/logger');
const { ApiError, errorHandler } = require('./utils/apiError');
const {
  ApiResponse,
  SuccessResponse,
  responseMiddleware,
} = require('./utils/apiResponse');
const { asyncHandler } = require('./utils/asyncHandler');
const { middleware: validationMiddleware } = require('./validations');

// Import database
const { checkDatabaseHealth } = require('./config/database');

/**
 * Create Express Application
 */
const app = express();

const swaggerDocument = YAML.load('./docs/swagger.yaml');

/**
 * Trust proxy settings for production deployment
 * This is essential for proper IP detection behind load balancers
 */
app.set('trust proxy', config.server.trustProxy);

/**
 * Security Middleware
 */

// Helmet - Security headers
app.use(helmetMiddleware);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// CORS - Cross-Origin Resource Sharing
app.use(corsMiddleware);

// Enterprise Rate Limiting - Multi-tier rate limiting system
// Apply general rate limiting to all API routes
app.use('/api/', general);

// Apply specific rate limiting to different endpoint categories
// Note: More specific routes should be applied before general routes
app.use('/api/*/auth', auth);
app.use('/api/*/upload', upload);

// Create development-friendly rate limiter for health checks
const healthLimiter = createRateLimiter({
  tier: RATE_LIMIT_TIERS.ADMIN,
  type: RATE_LIMIT_TYPES.GENERAL,
  customMessage: 'Health check rate limit exceeded',
});
app.use('/health', healthLimiter);

// Speed limiting - Slow down suspicious requests (fixed configuration)
app.use(
  slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 100, // Allow 100 requests per windowMs without delay
    delayMs: () => 500, // Fixed: Use function format for new version
    maxDelayMs: 20000, // Maximum delay of 20 seconds
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
    validate: { delayMs: false }, // Disable warning
  }),
);

/**
 * Request Processing Middleware
 */

// Compression - Reduce response size
app.use(
  compression({
    filter: (req, res) => {
      // Don't compress responses if the request includes a 'x-no-compression' header
      if (req.headers['x-no-compression']) {
        return false;
      }
      // Use compression filter function
      return compression.filter(req, res);
    },
    level: 6, // Compression level (1-9, 6 is default)
    threshold: 1024, // Only compress responses larger than 1KB
  }),
);

// Body parsing middleware
app.use(
  express.json({
    limit: config.server.bodyLimit,
    strict: true,
    type: 'application/json',
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: config.server.bodyLimit,
    parameterLimit: 1000,
  }),
);

// Cookie parsing
app.use(cookieParser(config.security.cookieSecret));

// Request logging
app.use(
  morgan(config.isProduction() ? 'combined' : 'dev', {
    stream: {
      write: (message) => logger.http(message.trim()),
    },
  }),
);

/**
 * Authentication Setup
 */

// Initialize Passport
app.use(passport.initialize());

// Initialize authentication strategies
const { initialize: initializeAuth } = require('./config/auth');
initializeAuth();

/**
 * Security Validation Middleware
 * Checks for common security threats in all requests
 */
app.use(
  validationMiddleware.validateSecurity({
    checkSQLInjection: true,
    checkXSS: true,
    checkCommandInjection: true,
    checkPathTraversal: true,
  }),
);

/**
 * Request Context Middleware
 * Adds useful information to each request
 */
app.use(
  asyncHandler(async (req, res, next) => {
    // Add request ID for tracking
    req.requestId = require('crypto').randomUUID();

    // Add request timestamp
    req.requestTime = generateTimestamp();
    req.startTime = Date.now();

    // Add client IP (considering proxy)
    req.clientIp = req.ip || req.connection.remoteAddress;

    // Add user agent info
    req.userAgent = req.get('User-Agent') || 'Unknown';

    // Initialize request context
    req.context = {
      requestId: req.requestId,
      timestamp: req.requestTime,
      ip: req.clientIp,
      userAgent: req.userAgent,
      method: req.method,
      url: req.originalUrl,
    };

    // Log request in development
    if (config.isDevelopment()) {
      logger.debug('Request received:', {
        id: req.requestId,
        method: req.method,
        url: req.originalUrl,
        ip: req.clientIp,
        userAgent: req.userAgent,
      });
    }

    next();
  }),
);

/**
 * Response Enhancement Middleware
 * Adds convenience methods to Express response object and tracks performance
 */
app.use(responseMiddleware);

/**
 * Rate Limiting Monitoring Middleware
 * Adds rate limiting metrics to request context
 */
app.use((req, res, next) => {
  // Add rate limiting metrics to request context
  if (req.context) {
    req.context.rateLimitMetrics = rateLimitManager.getMetrics();
  }

  // Add rate limiting info to response headers for debugging
  if (config.isDevelopment()) {
    res.set(
      'X-RateLimit-Metrics',
      JSON.stringify(rateLimitManager.getMetrics()),
    );
  }

  next();
});

/**
 * Health Check Endpoints
 * Essential for monitoring and load balancer health checks
 */
app.get(
  '/health',
  asyncHandler(async (req, res) => {
    const health = {
      status: 'healthy',
      timestamp: generateTimestamp(),
      uptime: process.uptime(),
      environment: config.NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      memory: process.memoryUsage(),
      requestId: req.requestId,
    };

    logger.info('Health check requested', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(health, 'Health check successful').send(
      res,
      req,
    );
  }),
);

app.get(
  '/health/detailed',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();

    // Check database connection
    let dbHealth = { status: 'healthy', responseTime: 0 };

    try {
      const dbStart = Date.now();
      const dbResult = await checkDatabaseHealth();
      dbHealth = {
        status: dbResult.status,
        responseTime: Date.now() - dbStart,
      };
    } catch (error) {
      dbHealth = {
        status: 'unhealthy',
        error: error.message,
        responseTime: Date.now() - startTime,
      };
      logger.error('Database health check failed:', error);
    }

    const health = {
      status: dbHealth.status === 'healthy' ? 'healthy' : 'degraded',
      timestamp: generateTimestamp(),
      uptime: process.uptime(),
      environment: config.NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      checks: {
        database: dbHealth,
        memory: {
          used: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          total: `${Math.round(
            process.memoryUsage().heapTotal / 1024 / 1024,
          )}MB`,
        },
        cpu: {
          usage: process.cpuUsage(),
        },
      },
      responseTime: `${Date.now() - startTime}ms`,
      requestId: req.requestId,
    };

    logger.info('Detailed health check requested', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
      dbStatus: dbHealth.status,
    });

    const statusCode = health.status === 'healthy' ? 200 : 503;

    if (health.status === 'healthy') {
      return new SuccessResponse(
        health,
        'Detailed health check successful',
      ).send(res, req);
    } else {
      return new ApiResponse(
        statusCode,
        health,
        'Detailed health check - system degraded',
      ).send(res, req);
    }
  }),
);

/**
 * Rate Limiting Status Endpoint
 * Provides rate limiting metrics and status information
 */
app.get(
  '/rate-limit-status',
  asyncHandler(async (req, res) => {
    const metrics = rateLimitManager.getMetrics();

    logger.info('Rate limit status requested', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(
      metrics,
      'Rate limiting status retrieved successfully',
    ).send(res, req);
  }),
);

/**
 * API Routes
 * All application routes are mounted here
 */
app.use(config.API_PREFIX, require('./routes'));

/**
 * API Documentation
 * Swagger/OpenAPI documentation endpoint
 */
// TODO: Implement when API documentation is ready
// if (config.isDevelopment() || config.docs.enabled) {
//   const swaggerUi = require('swagger-ui-express');
//   const swaggerSpec = require('./docs/swagger');
//   app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
// }

/**
 * 404 Handler
 * Handles requests to non-existent endpoints
 */
app.use(
  '*',
  asyncHandler(async (req, res) => {
    logger.warn('Route not found', {
      method: req.method,
      url: req.originalUrl,
      ip: req.clientIp,
      userAgent: req.userAgent,
      requestId: req.requestId,
    });

    throw new ApiError(
      404,
      'ROUTE_NOT_FOUND',
      `Route ${req.originalUrl} not found`,
    );
  }),
);

/**
 * Global Error Handler
 * Centralized error handling for the entire application
 */
app.use(errorHandler);

/**
 * Handle 404 for static files
 */
app.use((req, res, next) => {
  if (req.path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg)$/)) {
    return res.status(404).end();
  }
  next();
});

module.exports = app;
