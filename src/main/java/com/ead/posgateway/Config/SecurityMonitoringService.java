package com.ead.posgateway.Config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@Slf4j
public class SecurityMonitoringService {

    private final Map<String, AtomicInteger> failedLoginCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> rateLimitViolations = new ConcurrentHashMap<>();

    @Value("${security.enable-logging:true}")
    private boolean enableLogging;
    @Value("${security.logging.failed-logins:true}")
    private boolean logFailedLogins;
    @Value("${security.logging.successful-logins:true}")
    private boolean logSuccessfulLogins;
    @Value("${security.logging.account-lockout:true}")
    private boolean logAccountLockout;
    @Value("${security.logging.rate-limit:true}")
    private boolean logRateLimit;
    @Value("${security.logging.token-revocation:true}")
    private boolean logTokenRevocation;
    @Value("${security.logging.suspicious-activity:true}")
    private boolean logSuspiciousActivity;

    public void logFailedLogin(String email, String ipAddress, String reason) {
        if (!enableLogging || !logFailedLogins) return;
        log.warn("SECURITY_ALERT: Failed login attempt for user: {} from IP: {} - Reason: {} at {}", 
                email, ipAddress, reason, LocalDateTime.now());
        
        // Track failed attempts per IP
        String key = ipAddress + ":" + email;
        int attempts = failedLoginCounts.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();
        
        if (attempts >= 10) {
            log.error("SECURITY_ALERT: High number of failed login attempts ({}) for user: {} from IP: {}", 
                    attempts, email, ipAddress);
        }
    }

    public void logRateLimitViolation(String ipAddress, String endpoint) {
        if (!enableLogging || !logRateLimit) return;
        log.warn("SECURITY_ALERT: Rate limit violation from IP: {} on endpoint: {} at {}", 
                ipAddress, endpoint, LocalDateTime.now());
        
        int violations = rateLimitViolations.computeIfAbsent(ipAddress, k -> new AtomicInteger(0)).incrementAndGet();
        
        if (violations >= 5) {
            log.error("SECURITY_ALERT: Multiple rate limit violations ({}) from IP: {}", violations, ipAddress);
        }
    }

    public void logSuccessfulLogin(String email, String ipAddress) {
        if (!enableLogging || !logSuccessfulLogins) return;
        log.info("SECURITY_EVENT: Successful login for user: {} from IP: {} at {}", 
                email, ipAddress, LocalDateTime.now());
    }

    public void logAccountLockout(String email, String ipAddress, long lockoutDuration) {
        if (!enableLogging || !logAccountLockout) return;
        log.error("SECURITY_ALERT: Account locked for user: {} from IP: {} for {} minutes at {}", 
                email, ipAddress, lockoutDuration / 60000, LocalDateTime.now());
    }

    public void logTokenRevocation(String email, String reason) {
        if (!enableLogging || !logTokenRevocation) return;
        log.info("SECURITY_EVENT: Token revoked for user: {} - Reason: {} at {}", 
                email, reason, LocalDateTime.now());
    }

    public void logSuspiciousActivity(String activity, String details) {
        if (!enableLogging || !logSuspiciousActivity) return;
        log.warn("SECURITY_ALERT: Suspicious activity detected - Activity: {} - Details: {} at {}", 
                activity, details, LocalDateTime.now());
    }

    // Extensible method for future alerting (email, webhook, etc.)
    public void sendAlert(String alertType, String message, Map<String, Object> context) {
        if (!enableLogging) return;
        log.error("SECURITY_ALERT: {} - {} - Context: {} at {}", 
                alertType, message, context, LocalDateTime.now());
        
        // TODO: In the future, this could send emails, webhooks, or other notifications
        // Example:
        // emailService.sendSecurityAlert(alertType, message, context);
        // webhookService.sendAlert(alertType, message, context);
    }
} 