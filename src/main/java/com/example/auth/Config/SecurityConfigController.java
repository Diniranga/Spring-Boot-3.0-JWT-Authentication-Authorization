/*
 * SecurityConfigController.java
 * REST controller for managing security and HTTPS configuration.
 */
package com.example.auth.Config;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for managing security and HTTPS configuration.
 * Only accessible to users with ADMIN role.
 */
@RestController
@RequestMapping("/config/security")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class SecurityConfigController {

    private final HttpsConfiguration httpsConfiguration;

    /**
     * Returns the current HTTPS configuration status.
     * @return ResponseEntity with HTTPS status details
     */
    @GetMapping("/https-status")
    public ResponseEntity<Map<String, Object>> getHttpsStatus() {
        final Map<String, Object> response = new HashMap<>();
        response.put("httpsEnabled", httpsConfiguration.isEnabled());
        response.put("redirectHttp", httpsConfiguration.isRedirectHttp());
        response.put("hstsEnabled", httpsConfiguration.isHstsEnabled());
        response.put("hstsMaxAge", httpsConfiguration.getHstsMaxAge());
        response.put("message", "HTTPS configuration status");
        return ResponseEntity.ok(response);
    }

    /**
     * Enables HTTPS enforcement.
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/enable")
    public ResponseEntity<Map<String, String>> enableHttps() {
        httpsConfiguration.setEnabled(true);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HTTPS enforcement enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * Disables HTTPS enforcement.
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/disable")
    public ResponseEntity<Map<String, String>> disableHttps() {
        httpsConfiguration.setEnabled(false);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HTTPS enforcement disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * Enables HTTP to HTTPS redirect.
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/redirect/enable")
    public ResponseEntity<Map<String, String>> enableHttpRedirect() {
        httpsConfiguration.setRedirectHttp(true);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HTTP to HTTPS redirect enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * Disables HTTP to HTTPS redirect.
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/redirect/disable")
    public ResponseEntity<Map<String, String>> disableHttpRedirect() {
        httpsConfiguration.setRedirectHttp(false);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HTTP to HTTPS redirect disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * Enables HTTP Strict Transport Security (HSTS).
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/hsts/enable")
    public ResponseEntity<Map<String, String>> enableHsts() {
        httpsConfiguration.setHstsEnabled(true);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HSTS enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * Disables HTTP Strict Transport Security (HSTS).
     * @return ResponseEntity with status message
     */
    @PostMapping("/https/hsts/disable")
    public ResponseEntity<Map<String, String>> disableHsts() {
        httpsConfiguration.setHstsEnabled(false);
        final Map<String, String> response = new HashMap<>();
        response.put("message", "HSTS disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }
} 