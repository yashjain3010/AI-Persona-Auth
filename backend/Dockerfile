# ===================================
# AI-Persona Backend - Dockerfile
# ===================================
# Multi-stage production Dockerfile for Node.js backend
# Optimized for security, performance, and multi-tenant SaaS deployment
#
# @author AI-Persona Backend
# @version 1.0.0

# ===================================
# BUILD STAGE
# ===================================
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install system dependencies for native modules
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    openssl \
    ca-certificates \
    && update-ca-certificates

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Generate Prisma client
RUN npx prisma generate

# ===================================
# PRODUCTION STAGE
# ===================================
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    dumb-init \
    && update-ca-certificates

# Copy built application from builder stage
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Copy application source code
COPY --chown=nodejs:nodejs src ./src

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/uploads /app/ssl && \
    chown -R nodejs:nodejs /app/logs /app/uploads /app/ssl

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })" || exit 1

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "src/index.js"]

# ===================================
# DEVELOPMENT STAGE (Optional)
# ===================================
FROM node:18-alpine AS development

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    openssl \
    ca-certificates \
    && update-ca-certificates

# Copy package files
COPY package*.json ./

# Install all dependencies (including devDependencies)
RUN npm install

# Copy application source
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Expose port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=development
ENV PORT=3000

# Start development server with nodemon
CMD ["npm", "run", "dev"]

# ===================================
# METADATA
# ===================================
LABEL maintainer="AI-Persona Backend Team"
LABEL version="1.0.0"
LABEL description="AI-Persona Multi-tenant SaaS Backend"
LABEL org.opencontainers.image.source="https://github.com/your-org/ai-persona-backend"