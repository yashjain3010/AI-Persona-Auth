/**
 * Metrics Mixin
 *
 * Provides common metrics functionality to eliminate code duplication
 * across all manager and validator classes.
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const { generateTimestamp } = require("./common");

/**
 * Base Metrics Mixin Class
 * Provides common metrics functionality for all manager classes
 */
class MetricsMixin {
  constructor(initialMetrics = {}) {
    this.metrics = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      lastReset: generateTimestamp(),
      ...initialMetrics,
    };
  }

  /**
   * Get current metrics
   * @returns {Object} Current metrics with timestamp
   */
  getMetrics() {
    return {
      ...this.metrics,
      successRate:
        this.metrics.totalOperations > 0
          ? (this.metrics.successfulOperations / this.metrics.totalOperations) *
            100
          : 0,
      errorRate:
        this.metrics.totalOperations > 0
          ? (this.metrics.failedOperations / this.metrics.totalOperations) * 100
          : 0,
      uptime: Date.now() - new Date(this.metrics.lastReset).getTime(),
      timestamp: generateTimestamp(),
    };
  }

  /**
   * Reset metrics to initial state
   * @param {Object} initialMetrics - Initial metrics state
   */
  resetMetrics(initialMetrics = {}) {
    this.metrics = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      lastReset: generateTimestamp(),
      ...initialMetrics,
    };
  }

  /**
   * Record successful operation
   * @param {Object} additionalMetrics - Additional metrics to record
   */
  recordSuccess(additionalMetrics = {}) {
    this.metrics.totalOperations++;
    this.metrics.successfulOperations++;

    // Merge additional metrics
    Object.assign(this.metrics, additionalMetrics);
  }

  /**
   * Record failed operation
   * @param {Object} additionalMetrics - Additional metrics to record
   */
  recordFailure(additionalMetrics = {}) {
    this.metrics.totalOperations++;
    this.metrics.failedOperations++;

    // Merge additional metrics
    Object.assign(this.metrics, additionalMetrics);
  }

  /**
   * Get health status
   * @returns {Object} Health status information
   */
  getHealthStatus() {
    const metrics = this.getMetrics();

    return {
      status: metrics.errorRate < 10 ? "healthy" : "degraded",
      metrics: {
        totalOperations: metrics.totalOperations,
        successRate: Math.round(metrics.successRate * 100) / 100,
        errorRate: Math.round(metrics.errorRate * 100) / 100,
        uptime: metrics.uptime,
      },
      timestamp: generateTimestamp(),
    };
  }
}

module.exports = MetricsMixin;
