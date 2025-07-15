# Spring Boot JWT Authentication & Authorization – Technical Guide

## 1. Project Overview

This project is a modern, production-grade Spring Boot application implementing robust authentication and authorization using JWT (JSON Web Tokens). It supports secure user registration, login, password management, session management, role-based access control, and advanced security features such as rate limiting, session concurrency, and device fingerprinting.

---

## 2. Key Technical Approaches

- **Modular Package Structure:**
  - `Auth`: Authentication, registration, password reset, and related flows.
  - `Config`: Security, JWT, and application configuration.
  - `dto`: Data Transfer Objects for API communication.
  - `service`: Business logic for users and tokens.
  - `session`: Session management, including device and concurrency controls.
  - `token`: Token entity, repository, and type definitions.
  - `User`: User entity, roles, permissions, and repository.
  - `Demo`: Example secured endpoints for demonstration/testing.

- **Security Best Practices:**
  - JWT with RSA for stateless, secure authentication.
  - Role-based access control (RBAC) with enums and permissions.
  - Device fingerprinting and session concurrency control.
  - Rate limiting and security monitoring.
  - Centralized exception handling and audit logging.

---

## 3. Detailed Process Explanations

### 3.1 Authentication & Authorization Flow

#### A. Login & JWT Token Issuance
- User submits credentials to `/auth/login`.
- `AuthenticationController` delegates to `AuthenticationService`.
- Credentials are validated (`UserService`).
- If valid, `JwtService` generates JWT access and refresh tokens.
- A new `UserSession` is created and stored.
- Tokens are saved in the `Token` table, linked to the user and session.
- Response includes tokens and session info.
- **Security:** Passwords are hashed; account lockout and failed attempt tracking are enforced.

#### B. JWT Token Validation (How Filters Work)
- Every secured API request passes through `JwtAuthenticationFilter`.
- The filter extracts the JWT from the `Authorization` header.
- The token is validated using `JwtService` (signature, claims, revocation, session linkage).
- If valid, user is authenticated in the Spring Security context; otherwise, request is rejected.
- **Security:** Only valid, non-expired, non-revoked tokens allow access; all others are blocked.

#### C. Role-Based Access Control (RBAC)
- Endpoints are annotated with `@PreAuthorize` or similar.
- User roles and permissions are checked against required authorities.
- If the user lacks the required role/permission, access is denied.
- **Security:** Roles and permissions are defined in enums and mapped to authorities.

---

### 3.2 JWT Service (Token Generation & Validation)
- **Token Generation:**
  - Uses RSA key pair for signing and verification.
  - Includes claims: subject, audience, issuer, issued-at, expiration, JWT ID.
  - Supports both access and refresh tokens with different expirations.
- **Token Validation:**
  - Verifies signature and claims.
  - Checks for expiration, audience, issuer, and JWT ID.
  - Ensures the token matches the user and is not revoked.
- **Claim Extraction:**
  - Allows extracting any claim from a JWT.
- **Security:** Asymmetric cryptography (RSA) prevents token forgery; all validation is centralized and logged.

---

### 3.3 Session Management
- On successful login, a new `UserSession` is created (user, session ID, device fingerprint, IP, user agent, creation/expiry times, status).
- Each session is linked to tokens and tracked in the database.
- **Concurrency Control:** Limits active sessions per user; oldest session is revoked if limit is reached.
- **Session Validation:** On each request, session is checked for validity, expiration, and revocation; device fingerprint and IP are validated.
- **Session Cleanup:** Expired sessions are periodically cleaned up by `SessionCleanupScheduler`.
- **Session Revocation:** Sessions can be revoked on logout, password change, or admin action.
- **Security:** Prevents session hijacking and enforces per-user session limits; all session events are logged and monitored.

---

### 3.4 Device Fingerprinting
- On login, a device fingerprint is generated from client IP, user agent, accept-language, accept-encoding, and a device cookie (if present).
- This fingerprint is stored in the `UserSession`.
- On subsequent requests, the fingerprint is regenerated and compared.
- If the fingerprint does not match, the session is considered suspicious and can be revoked or flagged.
- **Security:** Prevents session reuse from different devices; detects and blocks session hijacking attempts.

---

### 3.5 Password Management
- **Password Reset:**
  - User requests reset via `/auth/password-reset/request`.
  - `PasswordResetToken` is generated, stored, and a reset link is sent/logged.
  - User submits new password with the token; token is validated (single-use, time-limited).
  - Password is updated, and all sessions/tokens are revoked.
- **Password Change:**
  - Authenticated user submits old and new passwords; old password is verified.
  - New password is validated and saved; all sessions/tokens are revoked.
- **Security:** Passwords are always hashed; reset tokens are single-use and expire quickly; all password changes are logged.

---

### 3.6 Rate Limiting & Security Monitoring
- **Rate Limiting:**
  - Implemented via `RateLimitFilter` and `RateLimitConfiguration`.
  - Limits requests per user/IP to prevent brute-force and abuse.
- **Security Monitoring:**
  - `SecurityMonitoringService` tracks logins, session creations, anomalies, account lockouts, password changes, and suspicious activity.
  - All events are logged for audit and compliance.

---

### 3.7 Exception Handling & Unauthorized Access Prevention
- **GlobalExceptionHandler:**
  - Catches and handles all exceptions, returning consistent error responses.
  - Handles authentication, authorization, validation, and business logic errors.
- **Unauthorized Access Prevention:**
  - All endpoints except `/auth/**` are protected by Spring Security.
  - JWT filter blocks requests with missing/invalid/expired tokens.
  - RBAC ensures users can only access what they’re permitted.
  - Session and device checks prevent session hijacking and reuse.

---

### 3.8 How Everything Connects (Request Flow Example)
1. User logs in → JWT issued, session created, device fingerprint stored.
2. User makes API request → JWT filter validates token, session filter checks session/device.
3. Controller method is called only if all checks pass and user has required role/permission.
4. Any suspicious activity (invalid token, session, device) is logged and access is denied.

---

## 4. Extensibility & Customization
- Add new roles/permissions: update enums and security annotations.
- Change session/device policy: update `SessionService` logic.
- Add new security features: implement new filters/aspects and register in `SecurityConfiguration`.
- Audit/monitoring: extend `SecurityMonitoringService` for more events.

---

## 5. Summary Table: Where Each Process Is Handled

| Process                        | Main Classes/Files Involved                                 |
|--------------------------------|------------------------------------------------------------|
| JWT Generation/Validation      | `JwtService`, `JwtAuthenticationFilter`, `TokenService`    |
| Authentication/Registration    | `AuthenticationController`, `AuthenticationService`        |
| Session Management             | `SessionService`, `UserSession`, `SessionCleanupScheduler` |
| Device Fingerprinting          | `SessionService`, `UserSession`                            |
| Password Reset/Change          | `AuthenticationService`, `PasswordResetToken`, DTOs        |
| RBAC Enforcement               | `Role`, `Permission`, `SecurityConfiguration`              |
| Rate Limiting                  | `RateLimitFilter`, `RateLimitConfiguration`                |
| Security Monitoring            | `SecurityMonitoringService`                                |
| Exception Handling             | `GlobalExceptionHandler`                                   |
| User/Token CRUD                | `UserService`, `TokenService`, `UserRepository`, `TokenRepository` |

---
