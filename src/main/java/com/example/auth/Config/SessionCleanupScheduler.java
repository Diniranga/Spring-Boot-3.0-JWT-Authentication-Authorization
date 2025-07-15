/*
 * SessionCleanupScheduler.java
 *
 * Scheduled task for cleaning up expired sessions at a configurable interval.
 */
package com.example.auth.Config;

import com.example.auth.session.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled task for cleaning up expired sessions at a configurable interval.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SessionCleanupScheduler {

    private final SessionService sessionService;

    @Value("${spring.application.security.session.cleanup-interval-minutes}")
    private int cleanupIntervalMinutes;

    /**
     * Cleanup expired sessions every X minutes (configurable).
     */
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