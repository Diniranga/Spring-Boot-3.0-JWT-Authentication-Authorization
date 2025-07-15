/*
 * SecurityMonitoringService.java
 *
 * Service for monitoring and logging security-related events.
 * Tracks failed logins, suspicious activity, session anomalies, device mismatches, and provides security statistics.
 */
package com.example.auth.Auth;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;


/**
 * Service for monitoring and logging security-related events.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringService {
    private static final int SUSPICIOUS_LOGIN_THRESHOLD = 3;
    private static final int HIGH_SUSPICIOUS_ACTIVITY_THRESHOLD = 5;

    private final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastFailedLogin = new ConcurrentHashMap<>();
    private final Map<String, Integer> suspiciousActivityCount = new ConcurrentHashMap<>();

    /**
     * Track a failed login attempt for a user and IP address.
     * @param email user email
     * @param ipAddress IP address
     */
    public void trackFailedLogin(String email, String ipAddress) {
        String key = email + ":" + ipAddress;
        int attempts = failedLoginAttempts.getOrDefault(key, 0) + 1;
        failedLoginAttempts.put(key, attempts);
        lastFailedLogin.put(key, LocalDateTime.now());
        log.warn("Failed login attempt for user: {} from IP: {} (attempt {})", email, ipAddress, attempts);
        if (attempts >= SUSPICIOUS_LOGIN_THRESHOLD) {
            log.error("SUSPICIOUS ACTIVITY: Multiple failed login attempts for user: {} from IP: {}", email, ipAddress);
            trackSuspiciousActivity(email, "Multiple failed login attempts", ipAddress);
        }
    }

    /**
     * Track a successful login and clear failed attempts.
     * @param email user email
     * @param ipAddress IP address
     */
    public void trackSuccessfulLogin(String email, String ipAddress) {
        String key = email + ":" + ipAddress;
        failedLoginAttempts.remove(key);
        lastFailedLogin.remove(key);
        log.info("Successful login for user: {} from IP: {}", email, ipAddress);
    }

    /**
     * Track suspicious activity for a user.
     * @param email user email
     * @param activity activity description
     * @param ipAddress IP address
     */
    public void trackSuspiciousActivity(String email, String activity, String ipAddress) {
        int count = suspiciousActivityCount.getOrDefault(email, 0) + 1;
        suspiciousActivityCount.put(email, count);
        log.error("SUSPICIOUS ACTIVITY DETECTED - User: {}, Activity: {}, IP: {}, Count: {}", email, activity, ipAddress, count);
        if (count >= HIGH_SUSPICIOUS_ACTIVITY_THRESHOLD) {
            log.error("HIGH SUSPICIOUS ACTIVITY ALERT - User: {} has {} suspicious activities", email, count);
        }
    }

    /**
     * Track session anomalies for a user.
     * @param email user email
     * @param sessionId session ID
     * @param ipAddress IP address
     * @param reason anomaly reason
     */
    public void trackSessionAnomaly(String email, String sessionId, String ipAddress, String reason) {
        log.warn("SESSION ANOMALY - User: {}, Session: {}, IP: {}, Reason: {}", email, sessionId, ipAddress, reason);
        trackSuspiciousActivity(email, "Session anomaly: " + reason, ipAddress);
    }

    /**
     * Track device fingerprint mismatches for a user.
     * @param email user email
     * @param expectedFingerprint expected fingerprint
     * @param actualFingerprint actual fingerprint
     * @param ipAddress IP address
     */
    public void trackDeviceFingerprintMismatch(String email, String expectedFingerprint, String actualFingerprint, String ipAddress) {
        log.warn("DEVICE FINGERPRINT MISMATCH - User: {}, Expected: {}, Actual: {}, IP: {}", email, expectedFingerprint, actualFingerprint, ipAddress);
        trackSuspiciousActivity(email, "Device fingerprint mismatch", ipAddress);
    }

    /**
     * Track when a user exceeds the concurrent session limit.
     * @param email user email
     * @param currentSessions current session count
     * @param maxSessions max allowed sessions
     */
    public void trackConcurrentSessionLimitExceeded(String email, int currentSessions, int maxSessions) {
        log.warn("CONCURRENT SESSION LIMIT EXCEEDED - User: {}, Current: {}, Max: {}", email, currentSessions, maxSessions);
    }

    /**
     * Track password changes for a user.
     * @param email user email
     * @param ipAddress IP address
     */
    public void trackPasswordChange(String email, String ipAddress) {
        log.info("Password changed for user: {} from IP: {}", email, ipAddress);
        suspiciousActivityCount.remove(email);
    }

    /**
     * Track session creation for a user.
     * @param email user email
     * @param sessionId session ID
     * @param ipAddress IP address
     * @param userAgent user agent string
     */
    public void trackSessionCreation(String email, String sessionId, String ipAddress, String userAgent) {
        log.info("Session created - User: {}, Session: {}, IP: {}, User-Agent: {}", email, sessionId, ipAddress, userAgent);
    }

    /**
     * Track session invalidation for a user.
     * @param email user email
     * @param sessionId session ID
     * @param reason invalidation reason
     */
    public void trackSessionInvalidation(String email, String sessionId, String reason) {
        log.info("Session invalidated - User: {}, Session: {}, Reason: {}", email, sessionId, reason);
    }

    /**
     * Get security statistics for all users.
     * @return map of security statistics
     */
    public Map<String, Object> getSecurityStatistics() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        stats.put("totalFailedLoginAttempts", failedLoginAttempts.size());
        stats.put("totalSuspiciousActivities", suspiciousActivityCount.size());
        stats.put("failedLoginAttempts", new ConcurrentHashMap<>(failedLoginAttempts));
        stats.put("suspiciousActivityCount", new ConcurrentHashMap<>(suspiciousActivityCount));
        stats.put("lastFailedLogins", new ConcurrentHashMap<>(lastFailedLogin));
        return stats;
    }

    /**
     * Reset security counters for a user.
     * @param email user email
     */
    public void resetUserSecurityCounters(String email) {
        failedLoginAttempts.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        lastFailedLogin.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        suspiciousActivityCount.remove(email);
        log.info("Security counters reset for user: {}", email);
    }
} 