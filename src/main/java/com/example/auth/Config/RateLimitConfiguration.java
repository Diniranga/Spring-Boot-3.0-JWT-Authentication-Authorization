/*
 * RateLimitConfiguration.java
 *
 * Configuration properties for rate limiting authentication endpoints.
 */
package com.example.auth.Config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for rate limiting authentication endpoints.
 */
@Data
@Component
@ConfigurationProperties(prefix = "spring.application.security.rate-limit")
public class RateLimitConfiguration {
    /** Max requests per minute per client. */
    private int maxRequestsPerMinute = 10;
    /** Reset interval in milliseconds. */
    private long resetIntervalMs = 60000; // 1 minute
    /** Whether rate limiting is enabled. */
    private boolean enabled = true;
    /** Paths to exclude from rate limiting. */
    private String[] excludedPaths = {"/auth/refresh-token"};
} 