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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for monitoring and logging security-related events.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class SecurityMonitoringService {
    @Value("${spring.application.security.lockout.suspicious-login-threshold}")
    private int suspiciousLoginThreshold;

    @Value("${spring.application.security.lockout.high-suspicious-activity-threshold}")
    private int highSuspiciousActivityThreshold;

    private final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastFailedLogin = new ConcurrentHashMap<>();
    private final Map<String, Integer> suspiciousActivityCount = new ConcurrentHashMap<>();
    // Track locked state per user (email)
    private final Map<String, Boolean> accountLockedState = new ConcurrentHashMap<>();

    private final SecurityEventRepository securityEventRepository;

    /**
     * Call this when a failed login occurs (before account is locked).
     * Returns true if account is now locked, false otherwise.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackFailedLoginWithLockCheck(String email, String ipAddress, int attempts, int threshold, boolean isLocked) {
        // If account is already locked, do not log further failed logins
        if (accountLockedState.getOrDefault(email, false)) {
            return;
        }
        // If this attempt locks the account
        if (isLocked) {
            String details = String.format(
                "attempt=%d, threshold=%d, ip=%s, action=LOCK_ACCOUNT",
                attempts, threshold, ipAddress
            );
            log.warn("FAILED LOGIN AND ACCOUNT LOCKED - User: {}, Attempts: {}, IP: {}", email, attempts, ipAddress);
            securityEventRepository.save(SecurityEvent.builder()
                    .eventType("FAILED_LOGIN_AND_ACCOUNT_LOCKED")
                    .email(email)
                    .ipAddress(ipAddress)
                    .details(details)
                    .eventTime(LocalDateTime.now())
                    .build());
            accountLockedState.put(email, true);
            return;
        }
        // Log normal failed login
        String details = String.format(
            "attempt=%d, threshold=%d, ip=%s",
            attempts, threshold, ipAddress
        );
        log.warn("Failed login attempt for user: {} from IP: {} (attempt {})", email, ipAddress, attempts);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("FAILED_LOGIN")
                .email(email)
                .ipAddress(ipAddress)
                .details(details)
                .eventTime(LocalDateTime.now())
                .build());
        // Log SUSPICIOUS_ACTIVITY only once per threshold crossing
        if (attempts == suspiciousLoginThreshold) {
            String suspiciousDetails = String.format(
                "Multiple failed login attempts (threshold reached), attempts=%d, threshold=%d, ip=%s, action=LOCK_ACCOUNT",
                attempts, suspiciousLoginThreshold, ipAddress
            );
            log.error("SUSPICIOUS ACTIVITY: Multiple failed login attempts for user: {} from IP: {} (threshold reached)", email, ipAddress);
            securityEventRepository.save(SecurityEvent.builder()
                    .eventType("SUSPICIOUS_ACTIVITY")
                    .email(email)
                    .ipAddress(ipAddress)
                    .details(suspiciousDetails)
                    .eventTime(LocalDateTime.now())
                    .build());
        }
    }

    /**
     * Track a successful login and clear failed attempts.
     * @param email user email
     * @param ipAddress IP address
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSuccessfulLogin(String email, String ipAddress) {
        String key = email + ":" + ipAddress;
        failedLoginAttempts.remove(key);
        lastFailedLogin.remove(key);
        log.info("Successful login for user: {} from IP: {}", email, ipAddress);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SUCCESSFUL_LOGIN")
                .email(email)
                .ipAddress(ipAddress)
                .details(null)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Track suspicious activity for a user.
     * @param email user email
     * @param activity activity description
     * @param ipAddress IP address
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSuspiciousActivity(String email, String activity, String ipAddress, boolean thresholdReached) {
        int count = suspiciousActivityCount.getOrDefault(email, 0) + 1;
        suspiciousActivityCount.put(email, count);
        String details = String.format(
            "%s, count=%d%s",
            activity, count,
            thresholdReached ? ", action=LOCK_ACCOUNT" : ""
        );
        log.error("SUSPICIOUS ACTIVITY DETECTED - User: {}, Activity: {}, IP: {}, Count: {}", email, activity, ipAddress, count);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SUSPICIOUS_ACTIVITY")
                .email(email)
                .ipAddress(ipAddress)
                .details(details)
                .eventTime(LocalDateTime.now())
                .build());
        if (count >= highSuspiciousActivityThreshold) {
            log.error("HIGH SUSPICIOUS ACTIVITY ALERT - User: {} has {} suspicious activities", email, count);
        }
    }

    // Keep the original for other usages
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSuspiciousActivity(String email, String activity, String ipAddress) {
        trackSuspiciousActivity(email, activity, ipAddress, false);
    }

    /**
     * Track session anomalies for a user.
     * @param email user email
     * @param sessionId session ID
     * @param ipAddress IP address
     * @param reason anomaly reason
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSessionAnomaly(String email, String sessionId, String ipAddress, String reason) {
        log.warn("SESSION ANOMALY - User: {}, Session: {}, IP: {}, Reason: {}", email, sessionId, ipAddress, reason);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SESSION_ANOMALY")
                .email(email)
                .ipAddress(ipAddress)
                .details("sessionId=" + sessionId + ", reason=" + reason)
                .eventTime(LocalDateTime.now())
                .build());
        trackSuspiciousActivity(email, "Session anomaly: " + reason, ipAddress);
    }

    /**
     * Track device fingerprint mismatches for a user.
     * @param email user email
     * @param expectedFingerprint expected fingerprint
     * @param actualFingerprint actual fingerprint
     * @param ipAddress IP address
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackDeviceFingerprintMismatch(String email, String expectedFingerprint, String actualFingerprint, String ipAddress) {
        log.warn("DEVICE FINGERPRINT MISMATCH - User: {}, Expected: {}, Actual: {}, IP: {}", email, expectedFingerprint, actualFingerprint, ipAddress);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("DEVICE_FINGERPRINT_MISMATCH")
                .email(email)
                .ipAddress(ipAddress)
                .details("expected=" + expectedFingerprint + ", actual=" + actualFingerprint)
                .eventTime(LocalDateTime.now())
                .build());
        trackSuspiciousActivity(email, "Device fingerprint mismatch", ipAddress);
    }

    /**
     * Track when a user exceeds the concurrent session limit.
     * @param email user email
     * @param currentSessions current session count
     * @param maxSessions max allowed sessions
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackConcurrentSessionLimitExceeded(String email, int currentSessions, int maxSessions) {
        log.warn("CONCURRENT SESSION LIMIT EXCEEDED - User: {}, Current: {}, Max: {}", email, currentSessions, maxSessions);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("CONCURRENT_SESSION_LIMIT_EXCEEDED")
                .email(email)
                .ipAddress(null)
                .details("currentSessions=" + currentSessions + ", maxSessions=" + maxSessions)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Track password changes for a user.
     * @param email user email
     * @param ipAddress IP address
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackPasswordChange(String email, String ipAddress) {
        log.info("Password changed for user: {} from IP: {}", email, ipAddress);
        suspiciousActivityCount.remove(email);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("PASSWORD_CHANGE")
                .email(email)
                .ipAddress(ipAddress)
                .details(null)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Track session creation for a user.
     * @param email user email
     * @param sessionId session ID
     * @param ipAddress IP address
     * @param userAgent user agent string
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSessionCreation(String email, String sessionId, String ipAddress, String userAgent) {
        log.info("Session created - User: {}, Session: {}, IP: {}, User-Agent: {}", email, sessionId, ipAddress, userAgent);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SESSION_CREATION")
                .email(email)
                .ipAddress(ipAddress)
                .details("sessionId=" + sessionId + ", userAgent=" + userAgent)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Track session invalidation for a user.
     * @param email user email
     * @param sessionId session ID
     * @param reason invalidation reason
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackSessionInvalidation(String email, String sessionId, String reason) {
        log.info("Session invalidated - User: {}, Session: {}, Reason: {}", email, sessionId, reason);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SESSION_INVALIDATION")
                .email(email)
                .ipAddress(null)
                .details("sessionId=" + sessionId + ", reason=" + reason)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Track account lock events for a user.
     * @param email user email
     * @param ipAddress IP address
     * @param reason reason for locking
     * @param attempts number of failed attempts before lock
     * @param threshold threshold for lock
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackAccountLocked(String email, String ipAddress, String reason, int attempts, int threshold) {
        String details = String.format(
            "Account locked due to: %s, attempts=%d, threshold=%d, ip=%s, action=LOCK_ACCOUNT",
            reason, attempts, threshold, ipAddress
        );
        log.warn("ACCOUNT LOCKED - User: {}, Reason: {}, Attempts: {}, IP: {}", email, reason, attempts, ipAddress);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("ACCOUNT_LOCKED")
                .email(email)
                .ipAddress(ipAddress)
                .details(details)
                .eventTime(LocalDateTime.now())
                .build());
    }

    /**
     * Call this when an account is unlocked (reset failed attempts or admin unlock).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trackAccountUnlocked(String email, String ipAddress, String reason) {
        String details = String.format(
            "Account unlocked, reason=%s, ip=%s, action=UNLOCK_ACCOUNT",
            reason, ipAddress
        );
        log.info("ACCOUNT UNLOCKED - User: {}, Reason: {}, IP: {}", email, reason, ipAddress);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("ACCOUNT_UNLOCKED")
                .email(email)
                .ipAddress(ipAddress)
                .details(details)
                .eventTime(LocalDateTime.now())
                .build());
        accountLockedState.put(email, false);
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
        // Optionally, add DB event counts:
        stats.put("totalSecurityEventsInDb", securityEventRepository.count());
        return stats;
    }

    /**
     * Reset security counters for a user.
     * @param email user email
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetUserSecurityCounters(String email) {
        failedLoginAttempts.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        lastFailedLogin.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        suspiciousActivityCount.remove(email);
        log.info("Security counters reset for user: {}", email);
        securityEventRepository.save(SecurityEvent.builder()
                .eventType("SECURITY_COUNTERS_RESET")
                .email(email)
                .ipAddress(null)
                .details(null)
                .eventTime(LocalDateTime.now())
                .build());
    }
} 