/**
 * Input Validation Module
 *
 * This module provides comprehensive input format validation
 * for common data types including emails, phone numbers, URLs,
 * passwords, and other standard input formats.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const {
  EMAIL_PATTERN,
  PHONE_PATTERNS,
  URL_PATTERN,
  UUID_PATTERNS,
  PASSWORD_PATTERNS,
  INPUT_PATTERNS,
  DATE_PATTERNS,
  CREDIT_CARD_PATTERNS,
  FIELD_LIMITS,
  VALIDATION_RESULT,
  VALIDATION_SEVERITY,
} = require("./patterns");

const {
  generateTimestamp,
  validation: commonValidation,
} = require("../utils/common");
const BaseValidator = require("./baseValidator");

/**
 * Input Validator Class
 * Handles all input format validation with comprehensive checks
 */
class InputValidator extends BaseValidator {
  constructor() {
    super({
      emailValidations: 0,
      phoneValidations: 0,
      urlValidations: 0,
      passwordValidations: 0,
    });
  }

  /**
   * Validate email format
   * @param {string} email - Email to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateEmail(email, options = {}) {
    const { required = true, maxLength = FIELD_LIMITS.EMAIL.max } = options;

    this.metrics.totalValidations++;
    this.metrics.emailValidations++;

    // Check if required
    if (required && (!email || typeof email !== "string")) {
      this.metrics.failedValidations++;
      return this.createValidationResult(
        false,
        "Email is required",
        "email",
        VALIDATION_SEVERITY.MEDIUM
      );
    }

    // Skip validation if not required and empty
    if (!required && (!email || email.trim() === "")) {
      this.metrics.successfulValidations++;
      return this.createValidationResult(true, "Email validation passed");
    }

    // Length validation
    if (email.length > maxLength) {
      this.metrics.failedValidations++;
      return this.createValidationResult(
        false,
        `Email must be less than ${maxLength} characters`,
        "email",
        VALIDATION_SEVERITY.LOW
      );
    }

    // Format validation
    if (!EMAIL_PATTERN.test(email)) {
      this.metrics.failedValidations++;
      return this.createValidationResult(
        false,
        "Invalid email format",
        "email",
        VALIDATION_SEVERITY.LOW
      );
    }

    this.metrics.successfulValidations++;
    return this.createValidationResult(
      true,
      "Email validation passed",
      null,
      null,
      email.toLowerCase().trim()
    );
  }

  /**
   * Validate phone number format
   * @param {string} phone - Phone number to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validatePhone(phone, options = {}) {
    const { required = true, format = "INTERNATIONAL" } = options;

    this.metrics.totalValidations++;
    this.metrics.phoneValidations++;

    // Check if required
    if (required && (!phone || typeof phone !== "string")) {
      this.metrics.failedValidations++;
      return this.createValidationResult(
        false,
        "Phone number is required",
        "phone",
        VALIDATION_SEVERITY.MEDIUM
      );
    }

    // Skip validation if not required and empty
    if (!required && (!phone || phone.trim() === "")) {
      this.validationMetrics.successfulValidations++;
      return {
        isValid: true,
        result: VALIDATION_RESULT.VALID,
        message: "Phone validation passed",
      };
    }

    // Format validation
    const pattern = PHONE_PATTERNS[format] || PHONE_PATTERNS.INTERNATIONAL;
    if (!pattern.test(phone)) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: `Invalid phone number format for ${format}`,
        field: "phone",
        severity: VALIDATION_SEVERITY.LOW,
      };
    }

    this.validationMetrics.successfulValidations++;
    return {
      isValid: true,
      result: VALIDATION_RESULT.VALID,
      message: "Phone validation passed",
      value: phone.replace(/\D/g, ""), // Return digits only
    };
  }

  /**
   * Validate URL format
   * @param {string} url - URL to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateURL(url, options = {}) {
    const { required = true, maxLength = FIELD_LIMITS.URL.max } = options;

    this.validationMetrics.totalValidations++;
    this.validationMetrics.urlValidations++;

    // Check if required
    if (required && (!url || typeof url !== "string")) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: "URL is required",
        field: "url",
        severity: VALIDATION_SEVERITY.MEDIUM,
      };
    }

    // Skip validation if not required and empty
    if (!required && (!url || url.trim() === "")) {
      this.validationMetrics.successfulValidations++;
      return {
        isValid: true,
        result: VALIDATION_RESULT.VALID,
        message: "URL validation passed",
      };
    }

    // Length validation
    if (url.length > maxLength) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: `URL must be less than ${maxLength} characters`,
        field: "url",
        severity: VALIDATION_SEVERITY.LOW,
      };
    }

    // Format validation
    if (!URL_PATTERN.test(url)) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: "Invalid URL format",
        field: "url",
        severity: VALIDATION_SEVERITY.LOW,
      };
    }

    this.validationMetrics.successfulValidations++;
    return {
      isValid: true,
      result: VALIDATION_RESULT.VALID,
      message: "URL validation passed",
      value: url.trim(),
    };
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validatePassword(password, options = {}) {
    const {
      required = true,
      minLength = FIELD_LIMITS.PASSWORD.min,
      maxLength = FIELD_LIMITS.PASSWORD.max,
      strength = "MEDIUM",
    } = options;

    this.validationMetrics.totalValidations++;
    this.validationMetrics.passwordValidations++;

    // Check if required
    if (required && (!password || typeof password !== "string")) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: "Password is required",
        field: "password",
        severity: VALIDATION_SEVERITY.HIGH,
      };
    }

    // Skip validation if not required and empty
    if (!required && (!password || password.trim() === "")) {
      this.validationMetrics.successfulValidations++;
      return {
        isValid: true,
        result: VALIDATION_RESULT.VALID,
        message: "Password validation passed",
      };
    }

    // Length validation
    if (password.length < minLength || password.length > maxLength) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: `Password must be between ${minLength} and ${maxLength} characters`,
        field: "password",
        severity: VALIDATION_SEVERITY.HIGH,
      };
    }

    // Strength validation
    const pattern = PASSWORD_PATTERNS[strength] || PASSWORD_PATTERNS.MEDIUM;
    if (!pattern.test(password)) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: this._getPasswordStrengthMessage(strength),
        field: "password",
        severity: VALIDATION_SEVERITY.HIGH,
      };
    }

    this.validationMetrics.successfulValidations++;
    return {
      isValid: true,
      result: VALIDATION_RESULT.VALID,
      message: "Password validation passed",
      strength: this._calculatePasswordStrength(password),
    };
  }

  /**
   * Validate UUID format
   * @param {string} uuid - UUID to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateUUID(uuid, options = {}) {
    const { required = true, version = "ANY" } = options;

    this.validationMetrics.totalValidations++;

    // Check if required
    if (required && (!uuid || typeof uuid !== "string")) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: "UUID is required",
        field: "uuid",
        severity: VALIDATION_SEVERITY.MEDIUM,
      };
    }

    // Skip validation if not required and empty
    if (!required && (!uuid || uuid.trim() === "")) {
      this.validationMetrics.successfulValidations++;
      return {
        isValid: true,
        result: VALIDATION_RESULT.VALID,
        message: "UUID validation passed",
      };
    }

    // Format validation
    const pattern = UUID_PATTERNS[version] || UUID_PATTERNS.ANY;
    if (!pattern.test(uuid)) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: `Invalid UUID format for version ${version}`,
        field: "uuid",
        severity: VALIDATION_SEVERITY.LOW,
      };
    }

    this.validationMetrics.successfulValidations++;
    return {
      isValid: true,
      result: VALIDATION_RESULT.VALID,
      message: "UUID validation passed",
      value: uuid.toLowerCase(),
    };
  }

  /**
   * Validate username format
   * @param {string} username - Username to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateUsername(username, options = {}) {
    const {
      required = true,
      minLength = FIELD_LIMITS.USERNAME.min,
      maxLength = FIELD_LIMITS.USERNAME.max,
    } = options;

    this.validationMetrics.totalValidations++;

    // Check if required
    if (required && (!username || typeof username !== "string")) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: "Username is required",
        field: "username",
        severity: VALIDATION_SEVERITY.MEDIUM,
      };
    }

    // Skip validation if not required and empty
    if (!required && (!username || username.trim() === "")) {
      this.validationMetrics.successfulValidations++;
      return {
        isValid: true,
        result: VALIDATION_RESULT.VALID,
        message: "Username validation passed",
      };
    }

    // Length validation
    if (username.length < minLength || username.length > maxLength) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message: `Username must be between ${minLength} and ${maxLength} characters`,
        field: "username",
        severity: VALIDATION_SEVERITY.MEDIUM,
      };
    }

    // Format validation
    if (!INPUT_PATTERNS.USERNAME.test(username)) {
      this.validationMetrics.failedValidations++;
      return {
        isValid: false,
        result: VALIDATION_RESULT.INVALID,
        message:
          "Username can only contain letters, numbers, underscores, and hyphens",
        field: "username",
        severity: VALIDATION_SEVERITY.LOW,
      };
    }

    this.validationMetrics.successfulValidations++;
    return {
      isValid: true,
      result: VALIDATION_RESULT.VALID,
      message: "Username validation passed",
      value: username.toLowerCase().trim(),
    };
  }

  /**
   * Validate multiple inputs at once
   * @param {Object} inputs - Key-value pairs to validate
   * @param {Object} schema - Validation schema
   * @returns {Object} Validation results
   */
  validateMultiple(inputs, schema) {
    const results = {};
    let hasErrors = false;

    for (const [field, value] of Object.entries(inputs)) {
      const fieldSchema = schema[field];
      if (!fieldSchema) continue;

      let result;
      switch (fieldSchema.type) {
        case "email":
          result = this.validateEmail(value, fieldSchema.options);
          break;
        case "phone":
          result = this.validatePhone(value, fieldSchema.options);
          break;
        case "url":
          result = this.validateURL(value, fieldSchema.options);
          break;
        case "password":
          result = this.validatePassword(value, fieldSchema.options);
          break;
        case "uuid":
          result = this.validateUUID(value, fieldSchema.options);
          break;
        case "username":
          result = this.validateUsername(value, fieldSchema.options);
          break;
        default:
          result = { isValid: true, result: VALIDATION_RESULT.VALID };
      }

      results[field] = result;
      if (!result.isValid) {
        hasErrors = true;
      }
    }

    return {
      isValid: !hasErrors,
      results,
      summary: {
        total: Object.keys(inputs).length,
        valid: Object.values(results).filter((r) => r.isValid).length,
        invalid: Object.values(results).filter((r) => !r.isValid).length,
      },
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Get validation metrics
   * @returns {Object} Current validation metrics
   */
  getMetrics() {
    const baseMetrics = super.getMetrics();
    return {
      ...baseMetrics,
      emailValidations: this.metrics.emailValidations,
      phoneValidations: this.metrics.phoneValidations,
      urlValidations: this.metrics.urlValidations,
      passwordValidations: this.metrics.passwordValidations,
    };
  }

  /**
   * Reset validation metrics
   */
  resetMetrics() {
    super.resetMetrics();
    this.metrics.emailValidations = 0;
    this.metrics.phoneValidations = 0;
    this.metrics.urlValidations = 0;
    this.metrics.passwordValidations = 0;
  }

  /**
   * Get password strength message
   * @param {string} strength - Password strength level
   * @returns {string} Strength message
   * @private
   */
  _getPasswordStrengthMessage(strength) {
    const messages = {
      WEAK: "Password must be at least 6 characters long",
      MEDIUM:
        "Password must contain at least one uppercase letter, one lowercase letter, and one number",
      STRONG:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      VERY_STRONG:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 12 characters long",
    };

    return messages[strength] || messages.MEDIUM;
  }

  /**
   * Calculate password strength
   * @param {string} password - Password to analyze
   * @returns {string} Password strength level
   * @private
   */
  _calculatePasswordStrength(password) {
    if (PASSWORD_PATTERNS.VERY_STRONG.test(password)) return "VERY_STRONG";
    if (PASSWORD_PATTERNS.STRONG.test(password)) return "STRONG";
    if (PASSWORD_PATTERNS.MEDIUM.test(password)) return "MEDIUM";
    if (PASSWORD_PATTERNS.WEAK.test(password)) return "WEAK";
    return "INVALID";
  }
}

// Create singleton instance
const inputValidator = new InputValidator();

// Export convenience functions
const validateEmail = (email, options) =>
  inputValidator.validateEmail(email, options);
const validatePhone = (phone, options) =>
  inputValidator.validatePhone(phone, options);
const validateURL = (url, options) => inputValidator.validateURL(url, options);
const validatePassword = (password, options) =>
  inputValidator.validatePassword(password, options);
const validateUUID = (uuid, options) =>
  inputValidator.validateUUID(uuid, options);
const validateUsername = (username, options) =>
  inputValidator.validateUsername(username, options);

module.exports = {
  // Main class
  InputValidator,

  // Singleton instance
  inputValidator,

  // Validation functions
  validateEmail,
  validatePhone,
  validateURL,
  validatePassword,
  validateUUID,
  validateUsername,

  // Utility functions
  getInputMetrics: () => inputValidator.getMetrics(),
  resetInputMetrics: () => inputValidator.resetMetrics(),
  validateMultipleInputs: (inputs, schema) =>
    inputValidator.validateMultiple(inputs, schema),
};
