package com.ead.posgateway.Config;

import com.ead.posgateway.session.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class SessionCleanupScheduler {

    private final SessionService sessionService;

    /**
     * Cleanup expired sessions every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
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