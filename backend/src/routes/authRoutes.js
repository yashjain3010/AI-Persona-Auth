/**
 * Authentication Routes
 *
 * This module provides all authentication endpoints for the multi-tenant SaaS application.
 * Supports local authentication, OAuth (Google, Microsoft), JWT token management,
 * and password reset flows.
 *
 * Key Features:
 * - Local email/password authentication
 * - OAuth 2.0 (Google, Microsoft) with automatic workspace assignment
 * - JWT token refresh and validation
 * - Email verification and password reset
 * - Multi-tenant workspace handling
 * - Comprehensive error handling and logging
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/authController');

// Local registration and login
router.post('/register', ...authController.register);
router.post('/login', ...authController.login);

// Google OAuth
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  }),
);
router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth_failed`,
  }),
  authController.googleCallback,
);

// Microsoft OAuth
router.get(
  '/microsoft',
  passport.authenticate('microsoft', { scope: ['user.read'], session: false }),
);
router.get(
  '/microsoft/callback',
  passport.authenticate('microsoft', {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth_failed`,
  }),
  authController.microsoftCallback,
);

// Token management
router.post('/refresh', ...authController.refresh);
router.post('/logout', ...authController.logout);

// Email verification & password reset
router.post('/verify-email', ...authController.verifyEmail);
router.post('/forgot-password', ...authController.forgotPassword);
router.post('/reset-password', ...authController.resetPassword);

// Profile
router.get('/me', ...authController.me);

// Health
router.get('/health', authController.health);

module.exports = router;
