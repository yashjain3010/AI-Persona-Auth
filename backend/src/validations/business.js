/**
 * Business Logic Validation Module
 *
 * This module provides validation for business-specific rules and constraints
 * that go beyond simple format validation. It handles complex business logic
 * validation including user roles, permissions, data consistency, and domain rules.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  VALIDATION_RESULT,
  VALIDATION_SEVERITY,
  FIELD_LIMITS,
} = require("./patterns");

const { generateTimestamp, generateRequestId } = require("../utils/common");
const logger = require("../utils/logger");

/**
 * Business Validator Class
 * Handles all business logic validation with domain-specific rules
 */
class BusinessValidator {
  constructor() {
    this.validationMetrics = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      userValidations: 0,
      roleValidations: 0,
      permissionValidations: 0,
      dataConsistencyValidations: 0,
      lastReset: generateTimestamp(),
    };

    this.businessRules = {
      userRoles: ["admin", "user", "moderator", "guest"],
      permissions: ["read", "write", "delete", "admin"],
      maxLoginAttempts: 5,
      passwordExpiryDays: 90,
      sessionTimeoutMinutes: 30,
      maxFileSize: 10 * 1024 * 1024, // 10MB
      allowedFileTypes: ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx"],
    };
  }

  /**
   * Validate user registration data
   * @param {Object} userData - User registration data
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateUserRegistration(userData, options = {}) {
    const requestId = generateRequestId();
    this.validationMetrics.totalValidations++;
    this.validationMetrics.userValidations++;

    const {
      requireEmailVerification = true,
      requirePasswordStrength = true,
      allowDuplicateEmails = false,
    } = options;

    const errors = [];

    // Validate required fields
    if (!userData.email || !userData.password) {
      errors.push({
        field: "required",
        message: "Email and password are required",
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    // Validate email format and uniqueness
    if (userData.email) {
      if (!this._isValidEmail(userData.email)) {
        errors.push({
          field: "email",
          message: "Invalid email format",
          severity: VALIDATION_SEVERITY.MEDIUM,
        });
      }

      if (!allowDuplicateEmails && this._isEmailTaken(userData.email)) {
        errors.push({
          field: "email",
          message: "Email is already registered",
          severity: VALIDATION_SEVERITY.HIGH,
        });
      }
    }

    // Validate password strength
    if (userData.password && requirePasswordStrength) {
      const passwordValidation = this._validatePasswordStrength(
        userData.password
      );
      if (!passwordValidation.isValid) {
        errors.push({
          field: "password",
          message: passwordValidation.message,
          severity: VALIDATION_SEVERITY.HIGH,
        });
      }
    }

    // Validate username if provided
    if (userData.username && this._isUsernameTaken(userData.username)) {
      errors.push({
        field: "username",
        message: "Username is already taken",
        severity: VALIDATION_SEVERITY.MEDIUM,
      });
    }

    // Validate user role
    if (
      userData.role &&
      !this.businessRules.userRoles.includes(userData.role)
    ) {
      errors.push({
        field: "role",
        message: `Invalid user role. Must be one of: ${this.businessRules.userRoles.join(
          ", "
        )}`,
        severity: VALIDATION_SEVERITY.MEDIUM,
      });
    }

    const isValid = errors.length === 0;

    if (isValid) {
      this.validationMetrics.successfulValidations++;
    } else {
      this.validationMetrics.failedValidations++;
    }

    return {
      isValid,
      result: isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      errors,
      requestId,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Validate user login data
   * @param {Object} loginData - User login data
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateUserLogin(loginData, options = {}) {
    const requestId = generateRequestId();
    this.validationMetrics.totalValidations++;
    this.validationMetrics.userValidations++;

    const {
      checkAccountStatus = true,
      checkLoginAttempts = true,
      allowInactiveUsers = false,
    } = options;

    const errors = [];

    // Validate required fields
    if (!loginData.email || !loginData.password) {
      errors.push({
        field: "required",
        message: "Email and password are required",
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    // Check if user exists
    if (loginData.email && !this._userExists(loginData.email)) {
      errors.push({
        field: "email",
        message: "User not found",
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    // Check account status
    if (checkAccountStatus && loginData.email) {
      const accountStatus = this._getAccountStatus(loginData.email);

      if (accountStatus === "suspended") {
        errors.push({
          field: "account",
          message: "Account is suspended",
          severity: VALIDATION_SEVERITY.CRITICAL,
        });
      }

      if (accountStatus === "inactive" && !allowInactiveUsers) {
        errors.push({
          field: "account",
          message: "Account is inactive",
          severity: VALIDATION_SEVERITY.HIGH,
        });
      }
    }

    // Check login attempts
    if (checkLoginAttempts && loginData.email) {
      const loginAttempts = this._getLoginAttempts(loginData.email);
      if (loginAttempts >= this.businessRules.maxLoginAttempts) {
        errors.push({
          field: "security",
          message: "Too many login attempts. Account temporarily locked.",
          severity: VALIDATION_SEVERITY.CRITICAL,
        });
      }
    }

    const isValid = errors.length === 0;

    if (isValid) {
      this.validationMetrics.successfulValidations++;
    } else {
      this.validationMetrics.failedValidations++;
    }

    return {
      isValid,
      result: isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      errors,
      requestId,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Validate user permissions
   * @param {string} userId - User ID
   * @param {string} permission - Permission to check
   * @param {string} resource - Resource being accessed
   * @returns {Object} Validation result
   */
  validateUserPermission(userId, permission, resource) {
    const requestId = generateRequestId();
    this.validationMetrics.totalValidations++;
    this.validationMetrics.permissionValidations++;

    const errors = [];

    // Validate permission format
    if (!this.businessRules.permissions.includes(permission)) {
      errors.push({
        field: "permission",
        message: `Invalid permission. Must be one of: ${this.businessRules.permissions.join(
          ", "
        )}`,
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    // Check if user has permission
    if (!this._userHasPermission(userId, permission, resource)) {
      errors.push({
        field: "authorization",
        message: `User does not have ${permission} permission for ${resource}`,
        severity: VALIDATION_SEVERITY.CRITICAL,
      });
    }

    const isValid = errors.length === 0;

    if (isValid) {
      this.validationMetrics.successfulValidations++;
    } else {
      this.validationMetrics.failedValidations++;
    }

    return {
      isValid,
      result: isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      errors,
      requestId,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Validate file upload
   * @param {Object} fileData - File upload data
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateFileUpload(fileData, options = {}) {
    const requestId = generateRequestId();
    this.validationMetrics.totalValidations++;

    const {
      maxSize = this.businessRules.maxFileSize,
      allowedTypes = this.businessRules.allowedFileTypes,
      requireAuthentication = true,
    } = options;

    const errors = [];

    // Validate file exists
    if (!fileData || !fileData.size || !fileData.name) {
      errors.push({
        field: "file",
        message: "File data is required",
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    // Validate file size
    if (fileData.size > maxSize) {
      errors.push({
        field: "size",
        message: `File size exceeds limit of ${maxSize} bytes`,
        severity: VALIDATION_SEVERITY.MEDIUM,
      });
    }

    // Validate file type
    if (fileData.name) {
      const fileExtension = fileData.name.split(".").pop().toLowerCase();
      if (!allowedTypes.includes(fileExtension)) {
        errors.push({
          field: "type",
          message: `File type not allowed. Allowed types: ${allowedTypes.join(
            ", "
          )}`,
          severity: VALIDATION_SEVERITY.MEDIUM,
        });
      }
    }

    // Validate authentication if required
    if (requireAuthentication && !fileData.userId) {
      errors.push({
        field: "authentication",
        message: "User authentication required for file upload",
        severity: VALIDATION_SEVERITY.HIGH,
      });
    }

    const isValid = errors.length === 0;

    if (isValid) {
      this.validationMetrics.successfulValidations++;
    } else {
      this.validationMetrics.failedValidations++;
    }

    return {
      isValid,
      result: isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      errors,
      requestId,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Validate data consistency
   * @param {Object} data - Data to validate
   * @param {Object} constraints - Consistency constraints
   * @returns {Object} Validation result
   */
  validateDataConsistency(data, constraints) {
    const requestId = generateRequestId();
    this.validationMetrics.totalValidations++;
    this.validationMetrics.dataConsistencyValidations++;

    const errors = [];

    // Validate foreign key constraints
    if (constraints.foreignKeys) {
      for (const [field, table] of Object.entries(constraints.foreignKeys)) {
        if (data[field] && !this._recordExists(table, data[field])) {
          errors.push({
            field,
            message: `Referenced record not found in ${table}`,
            severity: VALIDATION_SEVERITY.HIGH,
          });
        }
      }
    }

    // Validate unique constraints
    if (constraints.unique) {
      for (const field of constraints.unique) {
        if (
          data[field] &&
          this._isValueDuplicate(field, data[field], data.id)
        ) {
          errors.push({
            field,
            message: `Value must be unique`,
            severity: VALIDATION_SEVERITY.MEDIUM,
          });
        }
      }
    }

    // Validate required relationships
    if (constraints.requiredRelationships) {
      for (const [field, relation] of Object.entries(
        constraints.requiredRelationships
      )) {
        if (!this._relationshipExists(relation, data.id)) {
          errors.push({
            field,
            message: `Required relationship ${relation} not found`,
            severity: VALIDATION_SEVERITY.HIGH,
          });
        }
      }
    }

    const isValid = errors.length === 0;

    if (isValid) {
      this.validationMetrics.successfulValidations++;
    } else {
      this.validationMetrics.failedValidations++;
    }

    return {
      isValid,
      result: isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      errors,
      requestId,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get validation metrics
   * @returns {Object} Current validation metrics
   */
  getMetrics() {
    return {
      ...this.validationMetrics,
      successRate:
        this.validationMetrics.totalValidations > 0
          ? (this.validationMetrics.successfulValidations /
              this.validationMetrics.totalValidations) *
            100
          : 0,
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Reset validation metrics
   */
  resetMetrics() {
    this.validationMetrics = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      userValidations: 0,
      roleValidations: 0,
      permissionValidations: 0,
      dataConsistencyValidations: 0,
      lastReset: generateTimestamp(),
    };
  }

  /**
   * Update business rules
   * @param {Object} rules - New business rules
   */
  updateBusinessRules(rules) {
    this.businessRules = { ...this.businessRules, ...rules };

    logger.info("Business rules updated", {
      updatedRules: Object.keys(rules),
      timestamp: generateTimestamp(),
    });
  }

  // Private helper methods
  _isValidEmail(email) {
    // Use centralized validation from common utils
    const { validation } = require('../utils/common');
    return validation.isValidEmail(email);
  }

  _isEmailTaken(email) {
    // This would check against the database
    // For now, return false (not taken)
    return false;
  }

  _isUsernameTaken(username) {
    // This would check against the database
    // For now, return false (not taken)
    return false;
  }

  _userExists(email) {
    // This would check against the database
    // For now, return true (exists)
    return true;
  }

  _getAccountStatus(email) {
    // This would check against the database
    // For now, return 'active'
    return "active";
  }

  _getLoginAttempts(email) {
    // This would check against the database or cache
    // For now, return 0
    return 0;
  }

  _userHasPermission(userId, permission, resource) {
    // This would check against the database
    // For now, return true (has permission)
    return true;
  }

  _recordExists(table, id) {
    // This would check against the database
    // For now, return true (exists)
    return true;
  }

  _isValueDuplicate(field, value, excludeId) {
    // This would check against the database
    // For now, return false (not duplicate)
    return false;
  }

  _relationshipExists(relation, id) {
    // This would check against the database
    // For now, return true (exists)
    return true;
  }

  _validatePasswordStrength(password) {
    // This would integrate with the input validator
    const minLength = 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      return {
        isValid: false,
        message: `Password must be at least ${minLength} characters long`,
      };
    }

    if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
      return {
        isValid: false,
        message:
          "Password must contain uppercase, lowercase, number, and special character",
      };
    }

    return { isValid: true };
  }
}

// Create singleton instance
const businessValidator = new BusinessValidator();

// Export convenience functions
const validateUserRegistration = (userData, options) =>
  businessValidator.validateUserRegistration(userData, options);

const validateUserLogin = (loginData, options) =>
  businessValidator.validateUserLogin(loginData, options);

const validateUserPermission = (userId, permission, resource) =>
  businessValidator.validateUserPermission(userId, permission, resource);

const validateFileUpload = (fileData, options) =>
  businessValidator.validateFileUpload(fileData, options);

const validateDataConsistency = (data, constraints) =>
  businessValidator.validateDataConsistency(data, constraints);

module.exports = {
  // Main class
  BusinessValidator,

  // Singleton instance
  businessValidator,

  // Validation functions
  validateUserRegistration,
  validateUserLogin,
  validateUserPermission,
  validateFileUpload,
  validateDataConsistency,

  // Utility functions
  getBusinessMetrics: () => businessValidator.getMetrics(),
  resetBusinessMetrics: () => businessValidator.resetMetrics(),
  updateBusinessRules: (rules) => businessValidator.updateBusinessRules(rules),
};
