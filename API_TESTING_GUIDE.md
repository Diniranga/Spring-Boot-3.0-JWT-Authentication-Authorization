# JWT Authentication API Testing Guide

## Base URL
```
http://localhost:8080
```

## Authentication Endpoints

### 1. User Registration
**POST** `/auth/register`

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "role": "USER"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "userEmail": "john.doe@example.com",
  "userRole": "USER",
  "message": "Registration successful"
}
```

### 2. User Login
**POST** `/auth/login`

**Request Body:**
```json
{
  "email": "admin@gmail.com",
  "password": "root"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "userEmail": "admin@gmail.com",
  "userRole": "ADMIN",
  "message": "Login successful"
}
```

### 3. Token Refresh
**POST** `/auth/refresh-token`

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

### 4. Token Validation
**POST** `/auth/validateToken`

**Request Body:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "email": "admin@gmail.com"
}
```

**Response:**
```json
true
```

### 5. Get Security Context
**POST** `/auth/security-context`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "authenticated": true,
  "principal": "admin@gmail.com",
  "authorities": [
    {
      "authority": "ADMIN:READ"
    },
    {
      "authority": "ROLE_ADMIN"
    }
  ],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": null
  }
}
```

### 6. Verify Authentication
**POST** `/auth/verify-authentication`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "authenticated": true,
  "userEmail": "admin@gmail.com",
  "authorities": [
    {
      "authority": "ADMIN:READ"
    }
  ],
  "message": "User is authenticated"
}
```

### 7. Logout
**POST** `/auth/logout`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

### 8. Logout All Sessions
**POST** `/auth/logout-all`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "All sessions logged out successfully"
}
```

## Session Management Endpoints

### 1. Get Active Sessions
**GET** `/auth/sessions`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "userEmail": "admin@gmail.com",
  "activeSessions": 2,
  "maxConcurrentSessions": 3,
  "sessions": [
    {
      "sessionId": "550e8400-e29b-41d4-a716-446655440000",
      "tokenType": "BEARER",
      "ipAddress": "192.168.1.100",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "createdAt": "2024-01-15T10:30:00",
      "lastUsedAt": "2024-01-15T11:45:00",
      "deviceFingerprint": "a1b2c3d4",
      "hasAccessToken": true,
      "hasRefreshToken": true,
      "accessTokenValid": true,
      "refreshTokenValid": true
    }
  ],
  "message": "Active sessions retrieved"
}
```

### 2. Change Password
**POST** `/auth/change-password`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "newPassword": "NewSecurePass123!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully. All sessions have been invalidated for security."
}
```

### 3. Cleanup Expired Sessions
**POST** `/auth/cleanup-sessions`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Expired sessions cleaned up successfully"
}
```

## Security Monitoring Endpoints (Admin Only)

### 1. Get Security Statistics
**GET** `/auth/security/statistics`

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "statistics": {
    "totalFailedLoginAttempts": 15,
    "totalSuspiciousActivities": 3,
    "failedLoginAttempts": {
      "user1@example.com:192.168.1.100": 2,
      "user2@example.com:192.168.1.101": 1
    },
    "suspiciousActivityCount": {
      "user1@example.com": 2,
      "user2@example.com": 1
    },
    "lastFailedLogins": {
      "user1@example.com:192.168.1.100": "2024-01-15T11:30:00",
      "user2@example.com:192.168.1.101": "2024-01-15T11:25:00"
    }
  },
  "message": "Security statistics retrieved"
}
```

### 2. Reset Security Counters
**POST** `/auth/security/reset-counters`

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Request Body:**
```json
{
  "userEmail": "user@example.com"
}
```

**Response:**
```json
{
  "message": "Security counters reset for user: user@example.com"
}
```

### 3. Get Security Events
**GET** `/auth/security/events`

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "securityEvents": {
    "totalFailedLoginAttempts": 15,
    "totalSuspiciousActivities": 3,
    "failedLoginAttempts": {...},
    "suspiciousActivityCount": {...},
    "lastFailedLogins": {...}
  },
  "message": "Security events retrieved"
}
```

## Test Endpoints

### Public Endpoints (No Authentication Required)

#### 1. Public Test
**GET** `/test/public`

**Response:**
```json
{
  "message": "This is a public endpoint - no authentication required",
  "timestamp": 1703123456789,
  "status": "success"
}
```

#### 2. Rate Limit Test
**GET** `/test/test-rate-limit`

**Response:**
```json
{
  "message": "Rate limit test endpoint",
  "timestamp": 1703123456789,
  "note": "This endpoint is rate limited to 10 requests per minute"
}
```

#### 3. HTTPS Test
**GET** `/test/test-https`

**Response:**
```json
{
  "message": "HTTPS configuration test",
  "httpsEnabled": true,
  "timestamp": 1703123456789,
  "note": "If you can see this, HTTPS is working correctly"
}
```

### Protected Endpoints (Authentication Required)

#### 1. Authenticated Endpoint
**GET** `/test/authenticated`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "This endpoint requires authentication",
  "user": "admin@gmail.com",
  "authenticated": true,
  "timestamp": 1703123456789
}
```

#### 2. User Role Only
**GET** `/test/user-only`

**Headers:**
```
Authorization: Bearer <user_token>
```

**Response:**
```json
{
  "message": "This endpoint is accessible only to users with USER role",
  "user": "user@gmail.com",
  "authorities": [
    {
      "authority": "USER:READ"
    },
    {
      "authority": "ROLE_USER"
    }
  ],
  "timestamp": 1703123456789
}
```

#### 3. Admin Role Only
**GET** `/test/admin-only`

**Headers:**
```
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "message": "This endpoint is accessible only to users with ADMIN role",
  "user": "admin@gmail.com",
  "authorities": [
    {
      "authority": "ADMIN:READ"
    },
    {
      "authority": "ROLE_ADMIN"
    }
  ],
  "timestamp": 1703123456789
}
```

### Permission-Based Endpoints

#### User Permissions

**GET** `/test/user-read` - Requires `USER:READ`
**POST** `/test/user-create` - Requires `USER:CREATE`
**PUT** `/test/user-update` - Requires `USER:UPDATE`
**DELETE** `/test/user-delete` - Requires `USER:DELETE`

#### Admin Permissions

**GET** `/test/admin-read` - Requires `ADMIN:READ`
**POST** `/test/admin-create` - Requires `ADMIN:CREATE`

#### Current User Info
**GET** `/test/current-user-info`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "authenticated": true,
  "userEmail": "admin@gmail.com",
  "authorities": [
    {
      "authority": "ADMIN:READ"
    }
  ],
  "principal": "admin@gmail.com",
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": null
  },
  "timestamp": 1703123456789
}
```

#### Error Test
**POST** `/test/test-error`

**Response:**
```json
{
  "error": "Internal server error",
  "message": "An unexpected error occurred"
}
```

## Security Configuration Endpoints (Admin Only)

### HTTPS Configuration Management

**GET** `/config/security/https-status` - Get HTTPS configuration status
**POST** `/config/security/https/enable` - Enable HTTPS enforcement
**POST** `/config/security/https/disable` - Disable HTTPS enforcement
**POST** `/config/security/https/redirect/enable` - Enable HTTP to HTTPS redirect
**POST** `/config/security/https/redirect/disable` - Disable HTTP to HTTPS redirect
**POST** `/config/security/https/hsts/enable` - Enable HSTS
**POST** `/config/security/https/hsts/disable` - Disable HSTS

## Demo Endpoints

### Demo Controller Endpoints

**GET** `/demo/get` - Requires `USER:READ` or `ADMIN:READ`
**POST** `/demo/post` - Requires `ADMIN:CREATE`

## Testing Scenarios

### 1. Complete Authentication Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Test",
    "lastName": "User",
    "email": "test@example.com",
    "password": "TestPass123!",
    "role": "USER"
  }'

# 2. Login with the user
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'

# 3. Use the access token to access protected endpoints
curl -X GET http://localhost:8080/test/authenticated \
  -H "Authorization: Bearer <access_token>"

# 4. Test role-based access
curl -X GET http://localhost:8080/test/user-only \
  -H "Authorization: Bearer <access_token>"

# 5. Test permission-based access
curl -X GET http://localhost:8080/test/user-read \
  -H "Authorization: Bearer <access_token>"

# 6. Logout
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

### 2. Session Management Testing

```bash
# 1. Login and get token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@gmail.com",
    "password": "root"
  }'

# 2. Get active sessions
curl -X GET http://localhost:8080/auth/sessions \
  -H "Authorization: Bearer <access_token>"

# 3. Change password (invalidates all sessions)
curl -X POST http://localhost:8080/auth/change-password \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "newPassword": "NewSecurePass123!"
  }'

# 4. Try to use old token (should fail)
curl -X GET http://localhost:8080/test/authenticated \
  -H "Authorization: Bearer <old_token>"
```

### 3. Security Monitoring Testing (Admin Only)

```bash
# 1. Login as admin
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@gmail.com",
    "password": "root"
  }'

# 2. Get security statistics
curl -X GET http://localhost:8080/auth/security/statistics \
  -H "Authorization: Bearer <admin_token>"

# 3. Get security events
curl -X GET http://localhost:8080/auth/security/events \
  -H "Authorization: Bearer <admin_token>"

# 4. Reset security counters for a user
curl -X POST http://localhost:8080/auth/security/reset-counters \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "userEmail": "user@example.com"
  }'
```

### 4. Admin Testing

```bash
# Login as admin
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@gmail.com",
    "password": "root"
  }'

# Test admin-only endpoints
curl -X GET http://localhost:8080/test/admin-only \
  -H "Authorization: Bearer <admin_token>"

curl -X GET http://localhost:8080/test/admin-read \
  -H "Authorization: Bearer <admin_token>"
```

### 5. Error Testing

```bash
# Test with invalid token
curl -X GET http://localhost:8080/test/authenticated \
  -H "Authorization: Bearer invalid_token"

# Test with expired token
curl -X GET http://localhost:8080/test/authenticated \
  -H "Authorization: Bearer <expired_token>"

# Test rate limiting
for i in {1..15}; do
  curl -X GET http://localhost:8080/test/test-rate-limit
done
```

### 6. Security Testing

```bash
# Test access without token
curl -X GET http://localhost:8080/test/authenticated

# Test user accessing admin endpoint
curl -X GET http://localhost:8080/test/admin-only \
  -H "Authorization: Bearer <user_token>"

# Test invalid permissions
curl -X POST http://localhost:8080/test/admin-create \
  -H "Authorization: Bearer <user_token>"
```

## Default Users

The application creates two default users on startup:

### Admin User
- **Email:** admin@gmail.com
- **Password:** root
- **Role:** ADMIN
- **Permissions:** All permissions (ADMIN_READ, ADMIN_CREATE, ADMIN_UPDATE, ADMIN_DELETE, USER_READ, USER_CREATE, USER_UPDATE, USER_DELETE)

### Regular User
- **Email:** user@gmail.com
- **Password:** root
- **Role:** USER
- **Permissions:** User permissions only (USER_READ, USER_CREATE, USER_UPDATE, USER_DELETE)

## Security Features

### Core Security Features
1. **JWT Token Authentication** - Stateless authentication
2. **Role-Based Access Control (RBAC)** - ADMIN and USER roles
3. **Permission-Based Authorization** - Fine-grained permissions
4. **Rate Limiting** - 10 requests per minute per IP
5. **Token Revocation** - Proper logout with token blacklisting
6. **Password Validation** - Strong password requirements
7. **Security Audit Logging** - Complete audit trail
8. **Global Exception Handling** - Consistent error responses

### Advanced Security Features
9. **HTTPS Enforcement** - Configurable HTTPS with HSTS
10. **Security Headers** - Comprehensive security headers (CSP, XSS protection, etc.)
11. **Account Lockout** - Protection against brute force attacks
12. **JWT Claims Validation** - iat, aud, iss, jti validation
13. **Refresh Token Rotation** - Invalidate old refresh tokens
14. **Centralized Security Context Management** - Best practices for SecurityContextHolder

### Session Management & Token Security Enhancements
15. **Token Fingerprinting** - Bind tokens to specific devices/browsers
16. **Concurrent Session Limits** - Limit number of active sessions per user (default: 3)
17. **Session Invalidation on Password Change** - Automatically logout all sessions when password changes
18. **Session Activity Tracking** - Track and log session activities with timestamps
19. **Device Fingerprint Validation** - Validate device consistency across requests
20. **Session Timeout Management** - Automatic session expiration (default: 30 minutes)
21. **Scheduled Session Cleanup** - Automatic cleanup of expired sessions every 5 minutes

### Security Monitoring & Alerts
22. **Suspicious Activity Detection** - Track and alert on suspicious login patterns
23. **Failed Authentication Alerts** - Monitor and log failed login attempts
24. **Session Anomaly Detection** - Detect unusual session behavior
25. **Security Event Dashboard** - Admin-only security statistics and monitoring
26. **Device Fingerprint Mismatch Detection** - Alert on potential token theft
27. **Concurrent Session Limit Monitoring** - Track session limit violations

## Testing Tools

### cURL Examples
All examples above use cURL for testing.

### Postman Collection
You can import these endpoints into Postman for easier testing.

### Automated Testing
Consider creating automated tests using tools like:
- JUnit with Spring Boot Test
- REST Assured
- Postman Collections with Newman
- Insomnia or similar API testing tools

## Monitoring and Logs

The application provides comprehensive logging:
- Security audit logs for all secured method calls
- Rate limiting violation logs
- Authentication success/failure logs
- Token operations logs
- Session management logs
- Security monitoring and alerting logs
- Error logs with proper exception handling

Check the application logs to monitor security events and troubleshoot issues.

## Configuration

### Session Management Configuration
```yaml
spring:
  application:
    security:
      session:
        max-concurrent-sessions: 3          # Maximum concurrent sessions per user
        session-timeout-minutes: 30         # Session timeout in minutes
        cleanup-interval-minutes: 5         # Session cleanup interval
```

### Security Configuration
```yaml
spring:
  application:
    security:
      lockout:
        max-failed-attempts: 5              # Maximum failed login attempts
        cooldown-minutes: 15                # Account lockout duration
      jwt:
        expiration: 86400000                # Access token expiration (24 hours)
        refresh-token:
          expiration: 604800000             # Refresh token expiration (7 days)
```

## Database Optimization

### Token Storage Optimization
The system has been optimized to store both access and refresh tokens in a **single database record** instead of creating separate records for each token type. This provides:

- **Reduced Database Overhead** - Only one record per session instead of two
- **Better Performance** - Fewer database operations during login/logout
- **Simplified Session Management** - Easier to track and manage sessions
- **Consistent Data** - Both tokens are always in sync within the same session

### Token Entity Structure
```java
@Entity
public class Token {
    private String accessToken;      // JWT access token
    private String refreshToken;     // JWT refresh token
    private String deviceFingerprint; // Device fingerprint for security
    private String ipAddress;        // Client IP address
    private String userAgent;        // Browser/client information
    private String sessionId;        // Unique session identifier
    private boolean isActive;        // Session status
    // ... other fields
}
```

### Benefits of Single Record Approach
1. **Efficiency** - 50% reduction in database records
2. **Atomicity** - Both tokens are created/invalidated together
3. **Consistency** - No orphaned tokens or inconsistent states
4. **Performance** - Faster session lookups and management
5. **Simplicity** - Cleaner code and easier maintenance 