package com.ead.posgateway.Config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "spring.application.security.rate-limit")
public class RateLimitConfiguration {

    private int maxRequestsPerMinute = 10;
    private long resetIntervalMs = 60000; // 1 minute
    private boolean enabled = true;
    private String[] excludedPaths = {"/auth/refresh-token"};
} 