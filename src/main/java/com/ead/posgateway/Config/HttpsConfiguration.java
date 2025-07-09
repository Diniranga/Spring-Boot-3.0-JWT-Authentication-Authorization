package com.ead.posgateway.Config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.application.security.https")
public class HttpsConfiguration {
    
    /**
     * Enable/disable HTTPS enforcement
     */
    private boolean enabled = true;
    
    /**
     * Redirect HTTP requests to HTTPS
     */
    private boolean redirectHttp = true;
    
    /**
     * Enable HTTP Strict Transport Security (HSTS)
     */
    private boolean hstsEnabled = true;
    
    /**
     * HSTS max age in seconds (default: 1 year)
     */
    private long hstsMaxAge = 31536000;
} 