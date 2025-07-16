/**
 * Key Features:
 * - Security middleware (Helmet, CORS, Rate limiting)
 * - Request parsing and validation
 * - Authentication and authorization
 * - Multi-tenant workspace scoping
 * - Comprehensive error handling
 * - API documentation integration
 * - Health monitoring endpoints
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Import configurations
const config = require('./config');
const { helmetConfig } = require('./security/helmet');
const { corsConfig } = require('./security/cors');
const { rateLimitConfig } = require('./security/rateLimit');

// Import utilities
const logger = require('./utils/logger');
const { ApiError } = require('./utils/apiError');
const { ApiResponse, responseMiddleware } = require('./utils/apiResponse');
const asyncHandler = require('./utils/asyncHandler');
const { validateSecurity } = require('./middlewares/validation');

// Import routes
const routes = require('./routes');

// Import database
const { prisma } = require('./config/database');

/**
 * Create Express Application
 */
const app = express();

/**
 * Trust proxy settings for production deployment
 * This is essential for proper IP detection behind load balancers
 */
app.set('trust proxy', config.server.trustProxy);

/**
 * Security Middleware
 * Applied early in the middleware stack for maximum protection
 */

// Helmet - Security headers
app.use(helmet(helmetConfig));

// CORS - Cross-Origin Resource Sharing
app.use(cors(corsConfig));

// Rate limiting - Prevent abuse and DDoS attacks
app.use(rateLimit(rateLimitConfig.global));

// Speed limiting - Slow down suspicious requests
app.use(
  slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 100, // Allow 100 requests per windowMs without delay
    delayMs: 500, // Add 500ms delay per request after delayAfter
    maxDelayMs: 20000, // Maximum delay of 20 seconds
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
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
if (config.isDevelopment()) {
  app.use(morgan('dev'));
} else {
  app.use(
    morgan('combined', {
      stream: {
        write: (message) => logger.info(message.trim()),
      },
    }),
  );
}

/**
 * Authentication Setup
 */

// Initialize Passport
app.use(passport.initialize());

// Load Passport strategies
require('./config/auth')(passport);

/**
 * Security Validation Middleware
 * Checks for common security threats in all requests
 */
app.use(
  validateSecurity({
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
    req.requestTime = new Date().toISOString();

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
 * Health Check Endpoints
 * Essential for monitoring and load balancer health checks
 */
app.get(
  '/health',
  asyncHandler(async (req, res) => {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
    };

    res.success(health, 'Health check successful');
  }),
);

app.get(
  '/health/detailed',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();

    // Check database connection
    let dbStatus = 'healthy';
    let dbResponseTime = 0;

    try {
      const dbStart = Date.now();
      await prisma.$queryRaw`SELECT 1`;
      dbResponseTime = Date.now() - dbStart;
    } catch (error) {
      dbStatus = 'unhealthy';
      logger.error('Database health check failed:', error);
    }

    const health = {
      status: dbStatus === 'healthy' ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      checks: {
        database: {
          status: dbStatus,
          responseTime: `${dbResponseTime}ms`,
        },
        memory: {
          used: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          total: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
        },
        cpu: {
          usage: process.cpuUsage(),
        },
      },
      responseTime: `${Date.now() - startTime}ms`,
    };

    const statusCode = health.status === 'healthy' ? 200 : 503;

    // Use enhanced response method with automatic status code handling
    if (health.status === 'healthy') {
      res.success(health, 'Detailed health check');
    } else {
      res
        .status(statusCode)
        .json(new ApiResponse(statusCode, health, 'Detailed health check'));
    }
  }),
);

/**
 * API Routes
 * All application routes are mounted here
 */
app.use('/api', routes);

/**
 * API Documentation
 * Swagger/OpenAPI documentation endpoint
 */
if (config.isDevelopment() || config.docs.enabled) {
  const swaggerUi = require('swagger-ui-express');
  const swaggerSpec = require('./docs/swagger');

  app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'AI-Persona API Documentation',
    }),
  );

  // JSON endpoint for API specification
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });
}

/**
 * 404 Handler
 * Handles requests to non-existent endpoints
 */
app.use('*', (req, res, next) => {
  const error = new ApiError(
    404,
    `Route ${req.originalUrl} not found`,
    'ROUTE_NOT_FOUND',
  );

  logger.warn('Route not found:', {
    method: req.method,
    url: req.originalUrl,
    ip: req.clientIp,
    userAgent: req.userAgent,
  });

  next(error);
});

/**
 * Global Error Handler
 * Centralized error handling for the entire application
 */
app.use((error, req, res, next) => {
  // Set default error values
  let statusCode = error.statusCode || 500;
  let message = error.message || 'Internal Server Error';
  let errorCode = error.code || 'INTERNAL_ERROR';

  // Handle specific error types
  if (error.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation failed';
    errorCode = 'VALIDATION_ERROR';
  } else if (error.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized access';
    errorCode = 'UNAUTHORIZED';
  } else if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
    errorCode = 'INVALID_TOKEN';
  } else if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
    errorCode = 'TOKEN_EXPIRED';
  } else if (error.code === 'P2002') {
    // Prisma unique constraint violation
    statusCode = 409;
    message = 'Resource already exists';
    errorCode = 'DUPLICATE_RESOURCE';
  }

  // Log error details
  const errorLog = {
    requestId: req.requestId,
    error: {
      name: error.name,
      message: error.message,
      code: errorCode,
      statusCode,
      stack: error.stack,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      ip: req.clientIp,
      userAgent: req.userAgent,
      body: req.body,
      query: req.query,
      params: req.params,
    },
    user: req.user
      ? {
          id: req.user.id,
          email: req.user.email,
          workspaceId: req.user.workspaceId,
        }
      : null,
    timestamp: new Date().toISOString(),
  };

  // Log based on severity
  if (statusCode >= 500) {
    logger.error('Server error:', errorLog);
  } else if (statusCode >= 400) {
    logger.warn('Client error:', errorLog);
  }

  // Prepare error response
  const errorResponse = {
    success: false,
    error: {
      code: errorCode,
      message,
      statusCode,
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
    },
  };

  // Add error details in development
  if (config.isDevelopment()) {
    errorResponse.error.stack = error.stack;
    errorResponse.error.details = error.details || null;
  }

  res.status(statusCode).json(errorResponse);
});

module.exports = app;
