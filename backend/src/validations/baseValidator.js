/**
 * Base Validator Class
 *
 * Provides common validation functionality to eliminate code duplication
 * across all validator classes.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const MetricsMixin = require("../utils/metricsMixin");
const { generateTimestamp, generateRequestId } = require("../utils/common");
const { VALIDATION_RESULT, VALIDATION_SEVERITY } = require("./patterns");

/**
 * Base Validator Class
 * Provides common validation functionality for all validator classes
 */
class BaseValidator extends MetricsMixin {
  constructor(initialMetrics = {}) {
    super({
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      ...initialMetrics,
    });
  }

  /**
   * Create a standard validation result
   * @param {boolean} isValid - Whether validation passed
   * @param {string} message - Validation message
   * @param {Object} options - Additional options
   * @returns {Object} Standardized validation result
   */
  createValidationResult(isValid, message, options = {}) {
    const {
      field = null,
      severity = isValid ? VALIDATION_SEVERITY.LOW : VALIDATION_SEVERITY.MEDIUM,
      value = null,
      result = isValid ? VALIDATION_RESULT.VALID : VALIDATION_RESULT.INVALID,
      requestId = generateRequestId(),
    } = options;

    const validationResult = {
      isValid,
      result,
      message,
      severity,
      timestamp: generateTimestamp(),
      requestId,
    };

    if (field) validationResult.field = field;
    if (value !== null) validationResult.value = value;

    // Record metrics
    if (isValid) {
      this.recordSuccess({
        successfulValidations: this.metrics.successfulValidations + 1,
      });
    } else {
      this.recordFailure({
        failedValidations: this.metrics.failedValidations + 1,
      });
    }

    return validationResult;
  }

  /**
   * Validate required field
   * @param {*} value - Value to validate
   * @param {string} fieldName - Name of the field
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateRequired(value, fieldName, options = {}) {
    const isValid = value !== null && value !== undefined && value !== "";

    if (!isValid) {
      return this.createValidationResult(false, `${fieldName} is required`, {
        field: fieldName,
        severity: VALIDATION_SEVERITY.HIGH,
        ...options,
      });
    }

    return this.createValidationResult(true, `${fieldName} validation passed`, {
      field: fieldName,
      ...options,
    });
  }

  /**
   * Validate field length
   * @param {string} value - Value to validate
   * @param {string} fieldName - Name of the field
   * @param {Object} limits - Length limits
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateLength(value, fieldName, limits, options = {}) {
    const { min, max } = limits;

    if (min !== undefined && value.length < min) {
      return this.createValidationResult(
        false,
        `${fieldName} must be at least ${min} characters`,
        {
          field: fieldName,
          severity: VALIDATION_SEVERITY.MEDIUM,
          ...options,
        }
      );
    }

    if (max !== undefined && value.length > max) {
      return this.createValidationResult(
        false,
        `${fieldName} must be less than ${max} characters`,
        {
          field: fieldName,
          severity: VALIDATION_SEVERITY.MEDIUM,
          ...options,
        }
      );
    }

    return this.createValidationResult(
      true,
      `${fieldName} length validation passed`,
      {
        field: fieldName,
        ...options,
      }
    );
  }

  /**
   * Validate against pattern
   * @param {string} value - Value to validate
   * @param {RegExp} pattern - Pattern to test against
   * @param {string} fieldName - Name of the field
   * @param {string} errorMessage - Error message
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validatePattern(value, pattern, fieldName, errorMessage, options = {}) {
    const isValid = pattern.test(value);

    if (!isValid) {
      return this.createValidationResult(false, errorMessage, {
        field: fieldName,
        severity: VALIDATION_SEVERITY.LOW,
        ...options,
      });
    }

    return this.createValidationResult(
      true,
      `${fieldName} format validation passed`,
      {
        field: fieldName,
        ...options,
      }
    );
  }

  /**
   * Get validation metrics
   * @returns {Object} Validation metrics
   */
  getValidationMetrics() {
    const baseMetrics = this.getMetrics();

    return {
      ...baseMetrics,
      validationSuccessRate: baseMetrics.successRate,
      validationErrorRate: baseMetrics.errorRate,
    };
  }

  /**
   * Reset validation metrics
   */
  resetValidationMetrics() {
    this.resetMetrics({
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
    });
  }
}

module.exports = BaseValidator;
