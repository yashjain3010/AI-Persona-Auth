const express = require('express');
const router = express.Router();

// Import utilities
const { asyncHandler } = require('../utils/asyncHandler');
const { SuccessResponse } = require('../utils/apiResponse');
const logger = require('../utils/logger');
const config = require('../config');
const { generateTimestamp } = require('../utils/common');

// Import rate limiting utilities
const {
  createRateLimiter,
  createEndpointRateLimiter,
  RATE_LIMIT_TIERS,
  RATE_LIMIT_TYPES,
} = require('../security/rateLimit');

// API info endpoint with utilities
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const apiInfo = {
      name: 'AI-Persona API',
      version: '1.0.0',
      environment: config.NODE_ENV,
      timestamp: generateTimestamp(),
      endpoints: {
        health: '/health',
        api: config.API_PREFIX,
        // Add more endpoints as you create them
      },
    };

    logger.info('API info requested', {
      requestId: req.requestId,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });

    return new SuccessResponse(
      apiInfo,
      'AI-Persona API is running successfully!',
    ).send(res, req);
  }),
);

/**
 * Example: Public API endpoint with basic rate limiting
 */
router.get(
  '/public',
  asyncHandler(async (req, res) => {
    logger.info('Public endpoint accessed', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(
      { message: 'This is a public endpoint with basic rate limiting' },
      'Public endpoint accessed successfully',
    ).send(res, req);
  }),
);

/**
 * Example: Premium API endpoint with higher rate limits
 */
router.get(
  '/premium',
  createRateLimiter({
    tier: RATE_LIMIT_TIERS.PREMIUM,
    type: RATE_LIMIT_TYPES.API,
    customMessage:
      'Premium API rate limit exceeded - upgrade to enterprise for higher limits',
  }),
  asyncHandler(async (req, res) => {
    logger.info('Premium endpoint accessed', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(
      {
        message: 'This is a premium endpoint with higher rate limits',
        rateLimits: {
          tier: RATE_LIMIT_TIERS.PREMIUM,
          type: RATE_LIMIT_TYPES.API,
        },
      },
      'Premium endpoint accessed successfully',
    ).send(res, req);
  }),
);

/**
 * Example: Admin-only endpoint with very high rate limits
 */
router.get(
  '/admin',
  createRateLimiter({
    tier: RATE_LIMIT_TIERS.ADMIN,
    type: RATE_LIMIT_TYPES.GENERAL,
    customMessage: 'Admin endpoint rate limit exceeded',
  }),
  asyncHandler(async (req, res) => {
    logger.info('Admin endpoint accessed', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(
      {
        message: 'This is an admin endpoint with very high rate limits',
        rateLimits: {
          tier: RATE_LIMIT_TIERS.ADMIN,
          type: RATE_LIMIT_TYPES.GENERAL,
        },
      },
      'Admin endpoint accessed successfully',
    ).send(res, req);
  }),
);

/**
 * Example: Endpoint-specific rate limiting
 */
router.get(
  '/special',
  createEndpointRateLimiter('/special', {
    tier: RATE_LIMIT_TIERS.BASIC,
    type: RATE_LIMIT_TYPES.API,
    customMessage: 'Special endpoint rate limit exceeded',
  }),
  asyncHandler(async (req, res) => {
    logger.info('Special endpoint accessed', {
      requestId: req.requestId,
      ip: req.clientIp,
      userAgent: req.userAgent,
    });

    return new SuccessResponse(
      {
        message:
          'This endpoint has custom rate limiting specific to this route',
        rateLimits: {
          tier: RATE_LIMIT_TIERS.BASIC,
          type: RATE_LIMIT_TYPES.API,
          scope: 'endpoint-specific',
        },
      },
      'Special endpoint accessed successfully',
    ).send(res, req);
  }),
);

// Route modules
const authRoutes = require('./authRoutes');

// Mount auth routes
router.use('/auth', authRoutes);

module.exports = router;
