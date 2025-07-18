# AI-Persona Backend

## Project Overview

AI-Persona is a modern, secure, multi-tenant SaaS backend system designed for enterprise collaboration platforms (similar to Slack). Each company (tenant) has its own isolated workspace, and users are automatically assigned to workspaces based on their company email domain (e.g., `@acme.com` users join the “Acme” workspace).

### Key Objectives

- **Securely authenticate users** (OAuth, SSO, email/password)
- **Automatic workspace assignment** based on email domain
- **Strict data isolation** between workspaces (row-level security)
- **Role-based access control** (admin/member)
- **Enterprise-grade security** (rate limiting, audit logs, encryption)

## Core Features

- **Multi-tenant architecture** with workspace isolation
- **OAuth (Google/Microsoft) & SSO (SAML/OIDC) authentication**
- **Email/password fallback with verification**
- **Automatic or admin-invite user onboarding**
- **Personal email policy enforcement** (block/allow/invite-only)
- **Comprehensive audit logging and security events**
- **Rate limiting, CORS, Helmet, and secure session management**
- **Extensible validation, error handling, and logging utilities**

## File Structure

```
backend/
├── Dockerfile, docker-compose.yml         # Containerization
├── package.json, package-lock.json        # Node.js dependencies
├── README.md                             # Project documentation
├── prisma/
│   └── schema.prisma                     # Database schema (PostgreSQL, Prisma)
├── src/
│   ├── app.js, index.js                  # Main app entry points
│   ├── config/                           # Centralized configuration (auth, db, jwt, email)
│   ├── controllers/                      # (To be implemented) Route controllers
│   ├── jobs/                             # (Reserved) Background jobs
│   ├── logs/                             # Log files (rotated, audit, error, security)
│   ├── middlewares/                      # Express middlewares
│   ├── routes/                           # API route definitions
│   ├── security/                         # Security modules (rate limiting, CORS, Helmet)
│   ├── services/                         # (Reserved) Business logic/services
│   ├── utils/                            # Utilities (logger, error, async, metrics)
│   └── validations/                      # Input and business validation modules
└── test-validation.js                    # (Sample) Validation test script
```

## Database Schema (Prisma)

- **User**: Core user entity, supports OAuth and password auth, email verification, 2FA, soft delete
- **Workspace**: Tenant entity, mapped to company domain, supports branding, plan, and settings
- **Membership**: User-workspace relationship, with role and permissions
- **Invite**: Workspace invitation system, with expiry and tracking
- **Session**: JWT session management, device and security tracking
- **EmailToken**: Email verification and password reset tokens
- **SecurityEvent**: Audit and security event logging

## Setup Instructions

1. **Install dependencies:**
   ```bash
   cd backend
   npm install
   ```
2. **Configure environment variables:**
   - Copy `.env.example` to `.env` and fill in required values (database, OAuth, JWT, email, etc.)
3. **Setup the database:**
   ```bash
   npx prisma migrate dev --name init
   npx prisma generate
   ```
4. **Run the development server:**
   ```bash
   npm run dev
   ```

## Security Checklist

- All data access is scoped by `workspace_id`
- Never expose data from other workspaces
- Require email verification for all users
- Hash all passwords (bcrypt/argon2)
- Enforce HTTPS in production
- Limit invite links (expiry, one-time use)
- Block or handle personal emails as required

## Contributing

- Please open issues or pull requests for bugs, features, or improvements.

---

_This backend is designed for extensibility, security, and compliance. For more details, see the code comments and configuration files._