# Spring Boot JWT Authentication & Authorization - Session Management Guide

## Overview

This project implements a comprehensive session management system for Spring Boot JWT authentication with advanced security features including device fingerprinting, concurrent session limits, automatic cleanup, and security monitoring.

## Session Management Architecture

### Core Components

1. **UserSession Entity** - Database representation of user sessions
2. **SessionService** - Core session management logic
3. **SessionManagementService** - High-level session operations
4. **JwtAuthenticationFilter** - JWT validation with session checks
5. **SessionCleanupScheduler** - Automated session cleanup

## How Session Management Works

### 1. Session Creation Process

When a user logs in, the system creates a new session with the following steps:

```java
// 1. Generate device fingerprint
String deviceFingerprint = generateDeviceFingerprint(request);

// 2. Check for existing sessions on the same device
List<UserSession> existingSessions = userSessionRepository.findByUserAndDeviceFingerprint(user, deviceFingerprint);

// 3. Revoke existing sessions from the same device
for (UserSession existingSession : existingSessions) {
    if (!existingSession.isRevoked() && !existingSession.isExpired()) {
        existingSession.revoke("New session created from same device", "SYSTEM");
        tokenService.revokeTokensBySessionId(existingSession.getSessionId());
    }
}

// 4. Enforce concurrent session limits
checkAndEnforceSessionLimits(user);

// 5. Create new session
UserSession session = UserSession.builder()
    .user(user)
    .sessionId(UUID.randomUUID().toString())
    .deviceFingerprint(deviceFingerprint)
    .ipAddress(getClientIpAddress(request))
    .userAgent(request.getHeader("User-Agent"))
    .createdAt(LocalDateTime.now())
    .lastUsedAt(LocalDateTime.now())
    .expiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes))
    .isActive(true)
    .isRevoked(false)
    .sessionType(UserSession.SessionType.WEB)
    .loginMethod(UserSession.LoginMethod.PASSWORD)
    .deviceInfo(extractDeviceInfo(request))
    .build();
```

### 2. Device Fingerprinting

The system generates a unique device fingerprint using multiple request attributes:

```java
private String generateDeviceFingerprint(HttpServletRequest request) {
    String clientIp = getClientIpAddress(request);
    String userAgent = request.getHeader("User-Agent");
    String acceptLanguage = request.getHeader("Accept-Language");
    String acceptEncoding = request.getHeader("Accept-Encoding");
    String fingerprintCookie = extractFingerprintCookie(request);
    
    String fingerprint = String.format("%s|%s|%s|%s|%s",
        clientIp != null ? clientIp : "",
        userAgent != null ? userAgent : "",
        acceptLanguage != null ? acceptLanguage : "",
        acceptEncoding != null ? acceptEncoding : "",
        fingerprintCookie != null ? fingerprintCookie : "");
    
    return Integer.toHexString(fingerprint.hashCode());
}
```

**Components of Device Fingerprint:**
- **Client IP Address** - Real IP considering proxy headers (X-Forwarded-For, X-Real-IP)
- **User-Agent** - Browser/client identification
- **Accept-Language** - Language preferences
- **Accept-Encoding** - Compression preferences
- **Device Fingerprint Cookie** - Client-side generated fingerprint

### 3. Session Validation Process

Every authenticated request goes through session validation:

```java
public boolean validateSession(String sessionId, HttpServletRequest request) {
    // 1. Find session by ID
    Optional<UserSession> sessionOpt = userSessionRepository.findBySessionId(sessionId);
    if (sessionOpt.isEmpty()) {
        return false;
    }

    UserSession session = sessionOpt.get();
    
    // 2. Check if session is valid (active, not expired, not revoked)
    if (!session.isValid()) {
        securityMonitoringService.trackSessionAnomaly(
            session.getUser().getEmail(), 
            session.getSessionId(), 
            getClientIpAddress(request), 
            "Session invalid"
        );
        return false;
    }

    // 3. Check if session is expired
    if (session.isExpired()) {
        session.setIsActive(false);
        userSessionRepository.save(session);
        return false;
    }

    // 4. Validate device fingerprint
    if (session.getDeviceFingerprint() != null) {
        String currentFingerprint = generateDeviceFingerprint(request);
        if (!session.getDeviceFingerprint().equals(currentFingerprint)) {
            securityMonitoringService.trackDeviceFingerprintMismatch(
                session.getUser().getEmail(),
                session.getDeviceFingerprint(),
                currentFingerprint,
                getClientIpAddress(request)
            );
            return false;
        }
    }

    // 5. Update last used time
    session.updateLastUsed();
    userSessionRepository.save(session);

    return true;
}
```

### 4. JWT Authentication Filter Integration

The JWT filter integrates session validation with token validation:

```java
@Override
protected void doFilterInternal(HttpServletRequest request, 
                               HttpServletResponse response, 
                               FilterChain filterChain) {
    // 1. Extract JWT token
    final String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
        return;
    }
    
    String jwtToken = authHeader.substring(7);
    String userEmail = jwtService.extractUserEmail(jwtToken);
    
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        
        // 2. Validate both token and session
        boolean isSessionValid = sessionManagementService.validateSession(jwtToken, request);
        boolean isTokenValid = jwtService.isTokenValid(jwtToken, userDetails);
        
        if (isTokenValid && isSessionValid) {
            SecurityContextUtils.setSecurityContext(userDetails, jwtToken, request);
        } else {
            log.warn("Invalid session detected for user: {} - Token valid: {} - Session valid: {}", 
                    userEmail, isTokenValid, isSessionValid);
        }
    }
    
    filterChain.doFilter(request, response);
}
```

### 5. Concurrent Session Management

The system enforces limits on concurrent sessions per user:

```java
private void checkAndEnforceSessionLimits(User user) {
    long activeSessions = userSessionRepository.countActiveSessionsByUser(user);
    
    if (activeSessions >= maxConcurrentSessions) {
        // Track concurrent session limit exceeded
        securityMonitoringService.trackConcurrentSessionLimitExceeded(
            user.getEmail(), 
            (int) activeSessions, 
            maxConcurrentSessions
        );
        
        // Invalidate oldest session
        List<UserSession> activeSessionsList = userSessionRepository.findByUserOrderByCreatedAtAsc(user);
        
        if (!activeSessionsList.isEmpty()) {
            UserSession oldestSession = activeSessionsList.get(0);
            oldestSession.revoke("Session limit exceeded", "SYSTEM");
            userSessionRepository.save(oldestSession);
        }
    }
}
```

### 6. Automatic Session Cleanup

Expired sessions are automatically cleaned up by a scheduled task:

```java
@Component
public class SessionCleanupScheduler {
    
    @Scheduled(fixedRateString = "#{${spring.application.security.session.cleanup-interval-minutes} * 60 * 1000}")
    public void cleanupExpiredSessions() {
        try {
            log.info("Starting scheduled session cleanup...");
            sessionService.cleanupExpiredSessions();
            log.info("Scheduled session cleanup completed");
        } catch (Exception e) {
            log.error("Error during scheduled session cleanup: {}", e.getMessage());
        }
    }
}
```

The cleanup process:
```java
public void cleanupExpiredSessions() {
    List<UserSession> expiredSessions = userSessionRepository.findSessionsToExpire(LocalDateTime.now());
    
    expiredSessions.forEach(session -> {
        session.setIsActive(false);
        
        securityMonitoringService.trackSessionInvalidation(
            session.getUser().getEmail(), 
            session.getSessionId(), 
            "Session cleanup"
        );
    });
    
    userSessionRepository.saveAll(expiredSessions);
    log.info("Cleaned up {} expired sessions", expiredSessions.size());
}
```

## Session Security Features

### 1. Session Revocation

Sessions can be revoked for various reasons:
- **Manual logout** - User explicitly logs out
- **Security violation** - Device fingerprint mismatch
- **Session limit exceeded** - Too many concurrent sessions
- **Account lockout** - Failed login attempts
- **Administrative action** - Admin revokes sessions

### 2. Security Monitoring

The system tracks various security events:
- Session creation and invalidation
- Device fingerprint mismatches
- Concurrent session limit violations
- Session anomalies and suspicious activities

### 3. Session Statistics

Users can view their session statistics:
```java
public SessionStatistics getSessionStatistics(User user) {
    long activeSessions = userSessionRepository.countActiveSessionsByUser(user);
    List<UserSession> allSessions = userSessionRepository.findByUser(user);
    
    return SessionStatistics.builder()
            .totalSessions(allSessions.size())
            .activeSessions((int) activeSessions)
            .maxConcurrentSessions(maxConcurrentSessions)
            .build();
}
```

## Configuration

Session management is configured through application properties:

```yaml
spring:
  application:
    security:
      session:
        max-concurrent-sessions: 3          # Maximum concurrent sessions per user
        session-timeout-minutes: 30         # Session timeout in minutes
        cleanup-interval-minutes: 5         # Cleanup interval in minutes
```

## Database Schema

### UserSession Table
```sql
CREATE TABLE user_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    user_agent TEXT,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    session_type ENUM('WEB', 'MOBILE', 'API', 'DESKTOP') NOT NULL DEFAULT 'WEB',
    login_method ENUM('PASSWORD', 'OAUTH', 'SSO', 'API_KEY') NOT NULL DEFAULT 'PASSWORD',
    device_info TEXT,
    revoked_reason VARCHAR(255),
    revoked_at DATETIME,
    revoked_by VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Token Table
```sql
CREATE TABLE token (
    id INT AUTO_INCREMENT PRIMARY KEY,
    access_token TEXT,
    refresh_token TEXT,
    token_type ENUM('BEARER', 'REFRESH') NOT NULL DEFAULT 'BEARER',
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    user_id BIGINT,
    created_at DATETIME,
    session_id VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## API Endpoints

### Session Management Endpoints

1. **Get Active Sessions**
   ```
   GET /api/v1/auth/sessions/active
   ```

2. **Get All Sessions**
   ```
   GET /api/v1/auth/sessions/all
   ```

3. **Get Session Statistics**
   ```
   GET /api/v1/auth/sessions/statistics
   ```

4. **Logout (Invalidate Current Session)**
   ```
   POST /api/v1/auth/logout
   ```

5. **Logout All Sessions**
   ```
   POST /api/v1/auth/logout-all
   ```

6. **Extend Session**
   ```
   POST /api/v1/auth/sessions/{sessionId}/extend
   ```

## Security Best Practices Implemented

1. **Device Fingerprinting** - Prevents session hijacking
2. **Concurrent Session Limits** - Prevents account sharing
3. **Automatic Cleanup** - Reduces database bloat
4. **Security Monitoring** - Tracks suspicious activities
5. **Session Revocation** - Immediate invalidation capability
6. **IP Address Tracking** - Geographic session monitoring
7. **User Agent Validation** - Browser/client verification

## Monitoring and Logging

The system provides comprehensive logging for:
- Session creation and destruction
- Security violations and anomalies
- Performance metrics
- Error conditions

All security events are tracked through the `SecurityMonitoringService` for audit purposes.

## Performance Considerations

1. **Database Indexing** - Proper indexes on session_id, user_id, and expires_at
2. **Batch Cleanup** - Efficient cleanup of expired sessions
3. **Lazy Loading** - User entity loaded lazily in sessions
4. **Connection Pooling** - Optimized database connections
5. **Caching** - Session validation results cached where appropriate

This session management system provides enterprise-grade security while maintaining performance and usability for end users. 