package com.ead.posgateway.session;

import com.ead.posgateway.Auth.SecurityMonitoringService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
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

    @Value("${spring.application.security.session.max-concurrent-sessions:3}")
    private int maxConcurrentSessions;

    @Value("${spring.application.security.session.session-timeout-minutes:30}")
    private int sessionTimeoutMinutes;

    /**
     * Create a new user session
     */
    public UserSession createSession(User user, HttpServletRequest request, UserSession.SessionType sessionType) {
        String deviceFingerprint = generateDeviceFingerprint(request);
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String sessionId = UUID.randomUUID().toString();

        // Check and enforce session limits
        checkAndEnforceSessionLimits(user);

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

        log.info("Session created for user: {} with session ID: {} from IP: {}", 
                user.getEmail(), sessionId, ipAddress);

        return savedSession;
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
} 