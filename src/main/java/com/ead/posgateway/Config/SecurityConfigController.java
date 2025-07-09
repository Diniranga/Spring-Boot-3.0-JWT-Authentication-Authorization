package com.ead.posgateway.Config;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/config/security")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class SecurityConfigController {

    private final HttpsConfiguration httpsConfiguration;

    @GetMapping("/https-status")
    public ResponseEntity<Map<String, Object>> getHttpsStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("httpsEnabled", httpsConfiguration.isEnabled());
        response.put("redirectHttp", httpsConfiguration.isRedirectHttp());
        response.put("hstsEnabled", httpsConfiguration.isHstsEnabled());
        response.put("hstsMaxAge", httpsConfiguration.getHstsMaxAge());
        response.put("message", "HTTPS configuration status");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/enable")
    public ResponseEntity<Map<String, String>> enableHttps() {
        httpsConfiguration.setEnabled(true);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HTTPS enforcement enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/disable")
    public ResponseEntity<Map<String, String>> disableHttps() {
        httpsConfiguration.setEnabled(false);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HTTPS enforcement disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/redirect/enable")
    public ResponseEntity<Map<String, String>> enableHttpRedirect() {
        httpsConfiguration.setRedirectHttp(true);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HTTP to HTTPS redirect enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/redirect/disable")
    public ResponseEntity<Map<String, String>> disableHttpRedirect() {
        httpsConfiguration.setRedirectHttp(false);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HTTP to HTTPS redirect disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/hsts/enable")
    public ResponseEntity<Map<String, String>> enableHsts() {
        httpsConfiguration.setHstsEnabled(true);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HSTS enabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/https/hsts/disable")
    public ResponseEntity<Map<String, String>> disableHsts() {
        httpsConfiguration.setHstsEnabled(false);
        Map<String, String> response = new HashMap<>();
        response.put("message", "HSTS disabled");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }
} 