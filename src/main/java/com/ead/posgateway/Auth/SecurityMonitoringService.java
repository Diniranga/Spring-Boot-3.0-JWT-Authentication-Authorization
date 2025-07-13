package com.ead.posgateway.Auth;

import com.ead.posgateway.User.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringService {

    private final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastFailedLogin = new ConcurrentHashMap<>();
    private final Map<String, Integer> suspiciousActivityCount = new ConcurrentHashMap<>();

    /**
     * Track failed login attempt
     */
    public void trackFailedLogin(String email, String ipAddress) {
        String key = email + ":" + ipAddress;
        int attempts = failedLoginAttempts.getOrDefault(key, 0) + 1;
        failedLoginAttempts.put(key, attempts);
        lastFailedLogin.put(key, LocalDateTime.now());

        log.warn("Failed login attempt for user: {} from IP: {} (attempt {})", email, ipAddress, attempts);

        if (attempts >= 3) {
            log.error("SUSPICIOUS ACTIVITY: Multiple failed login attempts for user: {} from IP: {}", email, ipAddress);
            trackSuspiciousActivity(email, "Multiple failed login attempts", ipAddress);
        }
    }

    /**
     * Track successful login
     */
    public void trackSuccessfulLogin(String email, String ipAddress) {
        String key = email + ":" + ipAddress;
        failedLoginAttempts.remove(key);
        lastFailedLogin.remove(key);

        log.info("Successful login for user: {} from IP: {}", email, ipAddress);
    }

    /**
     * Track suspicious activity
     */
    public void trackSuspiciousActivity(String email, String activity, String ipAddress) {
        int count = suspiciousActivityCount.getOrDefault(email, 0) + 1;
        suspiciousActivityCount.put(email, count);

        log.error("SUSPICIOUS ACTIVITY DETECTED - User: {}, Activity: {}, IP: {}, Count: {}", 
                email, activity, ipAddress, count);

        // Alert if suspicious activity count is high
        if (count >= 5) {
            log.error("HIGH SUSPICIOUS ACTIVITY ALERT - User: {} has {} suspicious activities", email, count);
        }
    }

    /**
     * Track session anomaly
     */
    public void trackSessionAnomaly(String email, String sessionId, String ipAddress, String reason) {
        log.warn("SESSION ANOMALY - User: {}, Session: {}, IP: {}, Reason: {}", 
                email, sessionId, ipAddress, reason);
        
        trackSuspiciousActivity(email, "Session anomaly: " + reason, ipAddress);
    }

    /**
     * Track device fingerprint mismatch
     */
    public void trackDeviceFingerprintMismatch(String email, String expectedFingerprint, 
                                             String actualFingerprint, String ipAddress) {
        log.warn("DEVICE FINGERPRINT MISMATCH - User: {}, Expected: {}, Actual: {}, IP: {}", 
                email, expectedFingerprint, actualFingerprint, ipAddress);
        
        trackSuspiciousActivity(email, "Device fingerprint mismatch", ipAddress);
    }

    /**
     * Track concurrent session limit exceeded
     */
    public void trackConcurrentSessionLimitExceeded(String email, int currentSessions, int maxSessions) {
        log.warn("CONCURRENT SESSION LIMIT EXCEEDED - User: {}, Current: {}, Max: {}", 
                email, currentSessions, maxSessions);
    }

    /**
     * Track password change
     */
    public void trackPasswordChange(String email, String ipAddress) {
        log.info("Password changed for user: {} from IP: {}", email, ipAddress);
        
        // Reset suspicious activity count on password change
        suspiciousActivityCount.remove(email);
    }

    /**
     * Track session creation
     */
    public void trackSessionCreation(String email, String sessionId, String ipAddress, String userAgent) {
        log.info("Session created - User: {}, Session: {}, IP: {}, User-Agent: {}", 
                email, sessionId, ipAddress, userAgent);
    }

    /**
     * Track session invalidation
     */
    public void trackSessionInvalidation(String email, String sessionId, String reason) {
        log.info("Session invalidated - User: {}, Session: {}, Reason: {}", 
                email, sessionId, reason);
    }

    /**
     * Get security statistics
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
     * Reset security counters for a user
     */
    public void resetUserSecurityCounters(String email) {
        failedLoginAttempts.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        lastFailedLogin.entrySet().removeIf(entry -> entry.getKey().startsWith(email + ":"));
        suspiciousActivityCount.remove(email);
        
        log.info("Security counters reset for user: {}", email);
    }
} 