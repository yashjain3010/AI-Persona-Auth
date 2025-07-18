/**
 * Server Initialization and Startup
 *
 * This file is responsible for starting the HTTP server, initializing database
 * connections, and managing the application lifecycle for the AI-Persona backend.
 *
 * Key Features:
 * - HTTP/HTTPS server initialization
 * - Database connection management
 * - Environment validation
 * - Graceful startup and shutdown
 * - Process monitoring and health checks
 * - Error handling and recovery
 * - Production-ready logging
 *
 * @author AI-Persona Backend
 * @version 1.0.0
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const cluster = require("cluster");
const os = require("os");

// Import application and configurations
const app = require("./app");
const config = require("./config");
const {
  connectDatabase,
  disconnectDatabase,
  checkDatabaseHealth,
} = require("./config/database");
const logger = require("./utils/logger");
const { generateTimestamp } = require("./utils/common");

/**
 * Server Configuration
 */
const SERVER_CONFIG = {
  port: config.server.port,
  host: config.server.host,
  environment: config.NODE_ENV,
  enableCluster: config.server.enableCluster,
  enableHTTPS: config.server.enableHTTPS,
  maxMemoryUsage: config.server.maxMemoryUsage,
  healthCheckInterval: config.server.healthCheckInterval,
  shutdownTimeout: config.server.shutdownTimeout,
};

/**
 * Server Instance
 */
let server = null;
let isShuttingDown = false;

/**
 * Health Check Timer
 */
let healthCheckTimer = null;

/**
 * Startup Validation
 * Validates environment and configuration before starting the server
 */
const validateEnvironment = () => {
  logger.info("🔍 Validating environment and configuration...");

  // Basic environment validation
  const requiredEnvVars = ["NODE_ENV", "PORT"];
  const missingVars = requiredEnvVars.filter(
    (varName) => !process.env[varName]
  );

  if (missingVars.length > 0) {
    logger.warn("⚠️  Missing optional environment variables:", missingVars);
    logger.info("ℹ️  Using default values for missing variables");
  }

  // Validate port
  const port = parseInt(SERVER_CONFIG.port, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    logger.error("❌ Invalid port number:", SERVER_CONFIG.port);
    process.exit(1);
  }

  // Validate JWT secret length if provided
  if (config.security.jwtSecret && config.security.jwtSecret.length < 32) {
    logger.warn(
      "⚠️  JWT secret should be at least 32 characters long for security"
    );
  }

  logger.info("✅ Environment validation completed successfully");
};

/**
 * Database Initialization
 * Connects to the database and runs health checks
 */
const initializeDatabase = async () => {
  logger.info("🗄️  Initializing database connection...");

  try {
    // Connect to database
    await connectDatabase();
    logger.info("✅ Database connection established");

    // Run health check
    const healthResult = await checkDatabaseHealth();
    if (healthResult.status === "healthy") {
      logger.info("✅ Database health check passed");
    } else {
      logger.warn("⚠️  Database not available:", healthResult.error);
      if (config.isProduction()) {
        logger.error("❌ Database is required in production");
        process.exit(1);
      }
    }
  } catch (error) {
    logger.error("❌ Database initialization failed:", error);
    if (config.isProduction()) {
      process.exit(1);
    } else {
      logger.warn("⚠️  Continuing without database in development mode");
    }
  }
};

/**
 * SSL Configuration
 * Loads SSL certificates for HTTPS server
 */
const getSSLConfig = () => {
  if (!SERVER_CONFIG.enableHTTPS) {
    return null;
  }

  try {
    const keyPath = path.join(__dirname, "../ssl/private.key");
    const certPath = path.join(__dirname, "../ssl/certificate.crt");

    if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
      logger.warn("⚠️  SSL certificates not found, falling back to HTTP");
      return null;
    }

    const sslConfig = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };

    // Optional: Add CA bundle if available
    const caPath = path.join(__dirname, "../ssl/ca-bundle.crt");
    if (fs.existsSync(caPath)) {
      sslConfig.ca = fs.readFileSync(caPath);
    }

    logger.info("✅ SSL certificates loaded successfully");
    return sslConfig;
  } catch (error) {
    logger.error("❌ Failed to load SSL certificates:", error);
    logger.warn("⚠️  Falling back to HTTP server");
    return null;
  }
};

/**
 * Create HTTP/HTTPS Server
 * Creates the appropriate server based on configuration
 */
const createServer = (sslConfig = null) => {
  if (sslConfig) {
    logger.info("🔒 Creating HTTPS server...");
    return https.createServer(sslConfig, app);
  } else {
    logger.info("🌐 Creating HTTP server...");
    return http.createServer(app);
  }
};

/**
 * Start Server
 * Initializes and starts the HTTP/HTTPS server
 */
const startServer = async () => {
  try {
    // Get SSL configuration once
    const sslConfig = getSSLConfig();

    // Create server instance
    server = createServer(sslConfig);

    // Store server reference in app for graceful shutdown
    app.server = server;

    // Configure server settings
    server.keepAliveTimeout = 65000; // Slightly higher than load balancer timeout
    server.headersTimeout = 66000; // Slightly higher than keepAliveTimeout

    // Server event handlers
    server.on("error", (error) => {
      if (error.code === "EADDRINUSE") {
        logger.error(`❌ Port ${SERVER_CONFIG.port} is already in use`);
        process.exit(1);
      } else if (error.code === "EACCES") {
        logger.error(
          `❌ Permission denied to bind to port ${SERVER_CONFIG.port}`
        );
        process.exit(1);
      } else {
        logger.error("❌ Server error:", error);
        process.exit(1);
      }
    });

    server.on("listening", () => {
      const address = server.address();
      const protocol = sslConfig ? "https" : "http";

      logger.info(`🚀 Server started successfully!`);
      logger.info(
        `📍 Server running on ${protocol}://${SERVER_CONFIG.host}:${address.port}`
      );
      logger.info(`🌍 Environment: ${SERVER_CONFIG.environment}`);
      logger.info(`🔧 Process ID: ${process.pid}`);
      logger.info(
        `💾 Memory Usage: ${Math.round(
          process.memoryUsage().heapUsed / 1024 / 1024
        )}MB`
      );

      if (config.isDevelopment()) {
        logger.info(
          `🏥 Health Check: ${protocol}://${SERVER_CONFIG.host}:${address.port}/health`
        );
        logger.info(
          `📊 Detailed Health: ${protocol}://${SERVER_CONFIG.host}:${address.port}/health/detailed`
        );
        logger.info(
          `🔗 API Endpoint: ${protocol}://${SERVER_CONFIG.host}:${address.port}/api/v1`
        );
      }
    });

    server.on("connection", (socket) => {
      // Set socket timeout
      socket.setTimeout(config.server.socketTimeout);

      // Handle socket errors
      socket.on("error", (error) => {
        logger.debug("Socket error:", error);
      });
    });

    // Start listening
    server.listen(SERVER_CONFIG.port, SERVER_CONFIG.host);

    // Start health monitoring
    startHealthMonitoring();
  } catch (error) {
    logger.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

/**
 * Health Monitoring
 * Monitors server health and performance metrics
 */
const startHealthMonitoring = () => {
  if (healthCheckTimer) {
    clearInterval(healthCheckTimer);
  }

  healthCheckTimer = setInterval(async () => {
    try {
      const memoryUsage = process.memoryUsage();
      const memoryUsageMB = Math.round(memoryUsage.heapUsed / 1024 / 1024);

      // Check memory usage
      if (memoryUsageMB > SERVER_CONFIG.maxMemoryUsage) {
        logger.warn(
          `⚠️  High memory usage: ${memoryUsageMB}MB (limit: ${SERVER_CONFIG.maxMemoryUsage}MB)`
        );

        // Force garbage collection if available
        if (global.gc) {
          global.gc();
          logger.info("🗑️  Garbage collection triggered");
        }
      }

      // Check database health
      const dbHealth = await checkDatabaseHealth();
      if (dbHealth.status === "unhealthy") {
        logger.warn("⚠️  Database health check failed:", dbHealth.error);
      }

      // Log health metrics in development
      if (config.isDevelopment()) {
        logger.debug("Health metrics:", {
          memory: `${memoryUsageMB}MB`,
          uptime: `${Math.round(process.uptime())}s`,
          database: dbHealth.status,
        });
      }
    } catch (error) {
      logger.error("Health monitoring error:", error);
    }
  }, SERVER_CONFIG.healthCheckInterval);
};

/**
 * Graceful Shutdown
 * Handles graceful shutdown of the server
 */
const gracefulShutdown = async (signal) => {
  if (isShuttingDown) {
    logger.warn("⚠️  Shutdown already in progress, forcing exit...");
    process.exit(1);
  }

  isShuttingDown = true;
  logger.info(`🛑 Received ${signal}. Starting graceful shutdown...`);

  // Stop health monitoring
  if (healthCheckTimer) {
    clearInterval(healthCheckTimer);
  }

  // Set shutdown timeout
  const shutdownTimeout = setTimeout(() => {
    logger.error("❌ Shutdown timeout exceeded, forcing exit");
    process.exit(1);
  }, SERVER_CONFIG.shutdownTimeout);

  try {
    // Stop accepting new connections
    if (server) {
      server.close(async () => {
        logger.info("✅ HTTP server closed");

        try {
          // Close database connections
          await disconnectDatabase();
          logger.info("✅ Database connections closed");

          // Clear shutdown timeout
          clearTimeout(shutdownTimeout);

          logger.info("✅ Graceful shutdown completed");
          process.exit(0);
        } catch (error) {
          logger.error("❌ Error during database shutdown:", error);
          process.exit(1);
        }
      });
    } else {
      // No server to close, just close database
      await disconnectDatabase();
      logger.info("✅ Database connections closed");
      clearTimeout(shutdownTimeout);
      process.exit(0);
    }
  } catch (error) {
    logger.error("❌ Error during graceful shutdown:", error);
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
};

/**
 * Cluster Mode
 * Runs the server in cluster mode for better performance
 */
const runCluster = () => {
  const numCPUs = os.cpus().length;
  const numWorkers = Math.min(numCPUs, config.server.maxWorkers);

  logger.info(`🔄 Starting cluster with ${numWorkers} workers`);

  // Fork workers
  for (let i = 0; i < numWorkers; i++) {
    cluster.fork();
  }

  // Handle worker events
  cluster.on("exit", (worker, code, signal) => {
    logger.warn(
      `Worker ${worker.process.pid} died with code ${code} and signal ${signal}`
    );

    if (!isShuttingDown) {
      logger.info("Starting a new worker");
      cluster.fork();
    }
  });

  cluster.on("listening", (worker, address) => {
    logger.info(
      `Worker ${worker.process.pid} listening on ${address.address}:${address.port}`
    );
  });

  // Handle shutdown in cluster mode
  const shutdownCluster = (signal) => {
    logger.info(`Master received ${signal}, shutting down workers...`);
    isShuttingDown = true;

    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }

    setTimeout(() => {
      logger.info("Cluster shutdown completed");
      process.exit(0);
    }, 5000);
  };

  process.on("SIGTERM", () => shutdownCluster("SIGTERM"));
  process.on("SIGINT", () => shutdownCluster("SIGINT"));
};

/**
 * Single Process Mode
 * Runs the server in single process mode
 */
const runSingle = async () => {
  logger.info("🚀 Starting server in single process mode");

  // Validate environment
  validateEnvironment();

  // Initialize database
  await initializeDatabase();

  // Start server
  await startServer();

  // Setup shutdown handlers
  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  process.on("SIGQUIT", () => gracefulShutdown("SIGQUIT"));

  // Handle uncaught exceptions
  process.on("uncaughtException", (error) => {
    logger.error("💥 Uncaught Exception:", {
      error: error.message,
      stack: error.stack,
      timestamp: generateTimestamp(),
    });
    gracefulShutdown("UNCAUGHT_EXCEPTION");
  });

  // Handle unhandled promise rejections
  process.on("unhandledRejection", (reason, promise) => {
    logger.error("💥 Unhandled Rejection:", {
      reason: reason.toString(),
      promise: promise.toString(),
      timestamp: generateTimestamp(),
    });
    gracefulShutdown("UNHANDLED_REJECTION");
  });
};

/**
 * Main Entry Point
 * Determines whether to run in cluster or single process mode
 */
const main = async () => {
  try {
    // Display startup banner
    logger.info("");
    logger.info(
      "╔══════════════════════════════════════════════════════════════╗"
    );
    logger.info(
      "║                    AI-Persona Backend                       ║"
    );
    logger.info(
      "║                   Enhanced Server v1.0.0                    ║"
    );
    logger.info(
      "╚══════════════════════════════════════════════════════════════╝"
    );
    logger.info("");

    // Check if cluster mode is enabled and if we're the master process
    if (
      SERVER_CONFIG.enableCluster &&
      cluster.isMaster &&
      config.isProduction()
    ) {
      runCluster();
    } else {
      await runSingle();
    }
  } catch (error) {
    logger.error("❌ Failed to start application:", error);
    process.exit(1);
  }
};

// Start the application
if (require.main === module) {
  main();
}

module.exports = {
  startServer,
  gracefulShutdown,
  server: () => server,
};
