package com.ead.posgateway.session;

import com.ead.posgateway.Auth.SecurityMonitoringService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.token.Token;
import com.ead.posgateway.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;
    private final SecurityMonitoringService securityMonitoringService;
    private final TokenRepository tokenRepository;

    @Value("${spring.application.security.session.max-concurrent-sessions:3}")
    private int maxConcurrentSessions;

    @Value("${spring.application.security.session.session-timeout-minutes:30}")
    private int sessionTimeoutMinutes;

    /**
     * Create a new user session or reuse existing session from same device
     * @return SessionCreationResult containing the session and whether it was reused
     */
    public SessionCreationResult createSession(User user, HttpServletRequest request, UserSession.SessionType sessionType) {
        String deviceFingerprint = generateDeviceFingerprint(request);
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Check for existing active session from the same device
        Optional<UserSession> existingSessionOpt = userSessionRepository.findByUserAndDeviceFingerprint(user, deviceFingerprint);
        if (existingSessionOpt.isPresent()) {
            UserSession existingSession = existingSessionOpt.get();
            
            // Check if the existing session is still valid
            if (existingSession.isValid() && !existingSession.isExpired() && !existingSession.isRevoked()) {
                // Reuse existing session - update last used time and extend expiration
                existingSession.updateLastUsed();
                existingSession.setExpiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes));
                existingSession.setIpAddress(ipAddress); // Update IP in case it changed
                existingSession.setUserAgent(userAgent); // Update user agent in case it changed
                
                UserSession updatedSession = userSessionRepository.save(existingSession);
                
                log.info("Reusing existing session for user: {} with session ID: {} from IP: {}", 
                        user.getEmail(), existingSession.getSessionId(), ipAddress);
                
                return new SessionCreationResult(updatedSession, true);
            } else {
                // Existing session is invalid, remove it
                log.info("Removing invalid existing session for user: {} with session ID: {}", 
                        user.getEmail(), existingSession.getSessionId());
                userSessionRepository.delete(existingSession);
            }
        }

        // Check and enforce session limits
        checkAndEnforceSessionLimits(user);

        // Create new session
        String sessionId = UUID.randomUUID().toString();
        UserSession session = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .deviceFingerprint(deviceFingerprint)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .lastUsedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes))
                .isActive(true)
                .isExpired(false)
                .isRevoked(false)
                .sessionType(sessionType)
                .loginMethod(UserSession.LoginMethod.PASSWORD)
                .deviceInfo(extractDeviceInfo(request))
                .build();

        UserSession savedSession = userSessionRepository.save(session);

        // Update user session count
        updateUserSessionCount(user);

        // Track session creation
        securityMonitoringService.trackSessionCreation(user.getEmail(), sessionId, ipAddress, userAgent);

        log.info("New session created for user: {} with session ID: {} from IP: {}", 
                user.getEmail(), sessionId, ipAddress);

        return new SessionCreationResult(savedSession, false);
    }

    /**
     * Force create a new session (ignoring existing sessions from same device)
     * Use this when you want to ensure a fresh session is created
     */
    public SessionCreationResult createNewSession(User user, HttpServletRequest request, UserSession.SessionType sessionType) {
        String deviceFingerprint = generateDeviceFingerprint(request);
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Check and enforce session limits
        checkAndEnforceSessionLimits(user);

        // Create new session
        String sessionId = UUID.randomUUID().toString();
        UserSession session = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .deviceFingerprint(deviceFingerprint)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .lastUsedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes))
                .isActive(true)
                .isExpired(false)
                .isRevoked(false)
                .sessionType(sessionType)
                .loginMethod(UserSession.LoginMethod.PASSWORD)
                .deviceInfo(extractDeviceInfo(request))
                .build();

        UserSession savedSession = userSessionRepository.save(session);

        // Update user session count
        updateUserSessionCount(user);

        // Track session creation
        securityMonitoringService.trackSessionCreation(user.getEmail(), sessionId, ipAddress, userAgent);

        log.info("New session forced for user: {} with session ID: {} from IP: {}", 
                user.getEmail(), sessionId, ipAddress);

        return new SessionCreationResult(savedSession, false);
    }

    /**
     * Validate session and update last used time
     */
    public boolean validateSession(String sessionId, HttpServletRequest request) {
        Optional<UserSession> sessionOpt = userSessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isEmpty()) {
            return false;
        }

        UserSession session = sessionOpt.get();
        
        // Check if session is valid
        if (!session.isValid()) {
            securityMonitoringService.trackSessionAnomaly(
                session.getUser().getEmail(), 
                session.getSessionId(), 
                getClientIpAddress(request), 
                "Session invalid"
            );
            return false;
        }

        // Check if session is expired
        if (session.isExpired()) {
            session.setIsExpired(true);
            session.setIsActive(false);
            userSessionRepository.save(session);
            
            securityMonitoringService.trackSessionAnomaly(
                session.getUser().getEmail(), 
                session.getSessionId(), 
                getClientIpAddress(request), 
                "Session expired"
            );
            
            log.info("Session expired for user: {}", session.getUser().getEmail());
            return false;
        }

        // Validate device fingerprint if present
        if (session.getDeviceFingerprint() != null) {
            String currentFingerprint = generateDeviceFingerprint(request);
            if (!session.getDeviceFingerprint().equals(currentFingerprint)) {
                securityMonitoringService.trackDeviceFingerprintMismatch(
                    session.getUser().getEmail(),
                    session.getDeviceFingerprint(),
                    currentFingerprint,
                    getClientIpAddress(request)
                );
                log.warn("Device fingerprint mismatch for user: {}", session.getUser().getEmail());
                return false;
            }
        }

        // Update last used time and extend session if needed
        session.updateLastUsed();
        userSessionRepository.save(session);

        return true;
    }

    /**
     * Invalidate session
     */
    public void invalidateSession(String sessionId, String reason) {
        Optional<UserSession> sessionOpt = userSessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isPresent()) {
            UserSession session = sessionOpt.get();
            session.revoke(reason, "SYSTEM");
            userSessionRepository.save(session);

            // Update user session count
            updateUserSessionCount(session.getUser());

            // Track session invalidation
            securityMonitoringService.trackSessionInvalidation(
                session.getUser().getEmail(), 
                session.getSessionId(), 
                reason
            );

            log.info("Session invalidated for user: {}", session.getUser().getEmail());
        }
    }

    /**
     * Invalidate all sessions for a user
     */
    public void invalidateAllSessions(User user, String reason) {
        List<UserSession> activeSessions = userSessionRepository.findByUserAndIsActiveTrueAndIsExpiredFalseAndIsRevokedFalse(user);
        
        activeSessions.forEach(session -> {
            session.revoke(reason, "SYSTEM");
            securityMonitoringService.trackSessionInvalidation(
                user.getEmail(), 
                session.getSessionId(), 
                "All sessions logout"
            );
        });
        
        userSessionRepository.saveAll(activeSessions);

        // Reset user session count
        user.setActiveSessions(0);
        userRepository.save(user);

        log.info("All sessions invalidated for user: {}", user.getEmail());
    }

    /**
     * Get active sessions for a user
     */
    public List<UserSession> getActiveSessions(User user) {
        return userSessionRepository.findByUserAndIsActiveTrueAndIsExpiredFalseAndIsRevokedFalse(user);
    }

    /**
     * Get all sessions for a user
     */
    public List<UserSession> getAllSessions(User user) {
        return userSessionRepository.findByUserOrderByCreatedAtDesc(user);
    }

    /**
     * Cleanup expired sessions
     */
    public void cleanupExpiredSessions() {
        List<UserSession> expiredSessions = userSessionRepository.findSessionsToExpire(LocalDateTime.now());
        
        expiredSessions.forEach(session -> {
            session.setIsExpired(true);
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

    /**
     * Extend session
     */
    public void extendSession(String sessionId, int additionalMinutes) {
        Optional<UserSession> sessionOpt = userSessionRepository.findBySessionId(sessionId);
        if (sessionOpt.isPresent()) {
            UserSession session = sessionOpt.get();
            session.extendSession(additionalMinutes);
            userSessionRepository.save(session);
            log.info("Session extended for user: {}", session.getUser().getEmail());
        }
    }

    /**
     * Get session statistics
     */
    public SessionStatistics getSessionStatistics(User user) {
        long activeSessions = userSessionRepository.countActiveSessionsByUser(user);
        List<UserSession> allSessions = userSessionRepository.findByUser(user);
        
        return SessionStatistics.builder()
                .totalSessions(allSessions.size())
                .activeSessions((int) activeSessions)
                .maxConcurrentSessions(maxConcurrentSessions)
                .build();
    }

    /**
     * Validate session by token
     */
    public boolean validateSessionByToken(String tokenValue, HttpServletRequest request) {
        // Find the token first
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isEmpty()) {
            log.warn("Token not found for session validation: {}", tokenValue);
            return false;
        }
        
        Token tokenEntity = tokenOpt.get();
        
        // Check if token is valid
        if (tokenEntity.isExpired() || tokenEntity.isRevoked()) {
            log.warn("Token is expired or revoked: {}", tokenValue);
            return false;
        }
        
        String sessionId = tokenEntity.getSessionId();
        if (sessionId == null) {
            log.warn("Token has no associated session: {}", tokenValue);
            return false;
        }
        
        // Validate the session using existing method
        return validateSession(sessionId, request);
    }

    /**
     * Invalidate session by token
     */
    public void invalidateSessionByToken(String token, String reason) {
        // Find the token first
        Optional<Token> tokenOpt = tokenRepository.findByToken(token);
        if (tokenOpt.isPresent()) {
            Token tokenEntity = tokenOpt.get();
            String sessionId = tokenEntity.getSessionId();
            
            if (sessionId != null) {
                // Invalidate the session
                invalidateSession(sessionId, reason);
                
                // Also mark the token as revoked
                tokenEntity.setRevoked(true);
                tokenEntity.setExpired(true);
                tokenRepository.save(tokenEntity);
                
                log.info("Session and token invalidated for user: {} with session ID: {}", 
                        tokenEntity.getUser().getEmail(), sessionId);
            } else {
                log.warn("Token found but no session ID associated: {}", token);
                // Still revoke the token even if no session
                tokenEntity.setRevoked(true);
                tokenEntity.setExpired(true);
                tokenRepository.save(tokenEntity);
            }
        } else {
            log.warn("Token not found for invalidation: {}", token);
        }
    }

    /**
     * Get session by token
     */
    public Optional<UserSession> getSessionByToken(String token) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(token);
        if (tokenOpt.isPresent()) {
            Token tokenEntity = tokenOpt.get();
            String sessionId = tokenEntity.getSessionId();
            if (sessionId != null) {
                return userSessionRepository.findBySessionId(sessionId);
            }
        }
        return Optional.empty();
    }

    /**
     * Revoke token and session
     */
    public void revokeTokenAndSession(String token, String reason) {
        // This is a convenience method that combines token and session revocation
        invalidateSessionByToken(token, reason);
    }

    /**
     * Check and enforce session limits
     */
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
                
                securityMonitoringService.trackSessionInvalidation(
                    user.getEmail(), 
                    oldestSession.getSessionId(), 
                    "Session limit exceeded"
                );
                
                log.info("Session limit reached for user: {}. Invalidated oldest session.", user.getEmail());
            }
        }
    }

    /**
     * Update user session count
     */
    private void updateUserSessionCount(User user) {
        long activeSessions = userSessionRepository.countActiveSessionsByUser(user);
        user.setActiveSessions((int) activeSessions);
        userRepository.save(user);
    }

    /**
     * Generate device fingerprint from request
     */
    private String generateDeviceFingerprint(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");
        String acceptEncoding = request.getHeader("Accept-Encoding");
        
        String fingerprint = String.format("%s|%s|%s", 
                userAgent != null ? userAgent : "",
                acceptLanguage != null ? acceptLanguage : "",
                acceptEncoding != null ? acceptEncoding : "");
        
        return Integer.toHexString(fingerprint.hashCode());
    }

    /**
     * Get client IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0];
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Extract device information
     */
    private String extractDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");
        String acceptEncoding = request.getHeader("Accept-Encoding");
        
        return String.format("User-Agent: %s, Language: %s, Encoding: %s", 
                userAgent != null ? userAgent : "Unknown",
                acceptLanguage != null ? acceptLanguage : "Unknown",
                acceptEncoding != null ? acceptEncoding : "Unknown");
    }

    /**
     * Session statistics DTO
     */
    @lombok.Data
    @lombok.Builder
    public static class SessionStatistics {
        private int totalSessions;
        private int activeSessions;
        private int maxConcurrentSessions;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class SessionCreationResult {
        private UserSession session;
        private boolean wasReused;
    }
} 