package com.ead.posgateway.Test;

import com.ead.posgateway.Config.SecurityContextUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
@Slf4j
public class TestController {

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("timestamp", System.currentTimeMillis());
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/authenticated")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> authenticatedEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires authentication");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("authenticated", SecurityContextUtils.isAuthenticated());
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user-only")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> userOnlyEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint is accessible only to users with USER role");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("authorities", SecurityContextUtils.getCurrentAuthentication().getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> adminOnlyEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint is accessible only to users with ADMIN role");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("authorities", SecurityContextUtils.getCurrentAuthentication().getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/user-create")
    @PreAuthorize("hasAuthority('USER:CREATE')")
    public ResponseEntity<Map<String, Object>> userCreateEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires USER:CREATE permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "CREATE");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user-read")
    @PreAuthorize("hasAuthority('USER:READ')")
    public ResponseEntity<Map<String, Object>> userReadEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires USER:READ permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "READ");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @PutMapping("/user-update")
    @PreAuthorize("hasAuthority('USER:UPDATE')")
    public ResponseEntity<Map<String, Object>> userUpdateEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires USER:UPDATE permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "UPDATE");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/user-delete")
    @PreAuthorize("hasAuthority('USER:DELETE')")
    public ResponseEntity<Map<String, Object>> userDeleteEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires USER:DELETE permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "DELETE");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin-read")
    @PreAuthorize("hasAuthority('ADMIN:READ')")
    public ResponseEntity<Map<String, Object>> adminReadEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires ADMIN:READ permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "ADMIN_READ");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/admin-create")
    @PreAuthorize("hasAuthority('ADMIN:CREATE')")
    public ResponseEntity<Map<String, Object>> adminCreateEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This endpoint requires ADMIN:CREATE permission");
        response.put("user", SecurityContextUtils.getCurrentUserEmail());
        response.put("action", "ADMIN_CREATE");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/current-user-info")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getCurrentUserInfo() {
        Authentication auth = SecurityContextUtils.getCurrentAuthentication();
        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", true);
        response.put("userEmail", SecurityContextUtils.getCurrentUserEmail());
        response.put("authorities", auth.getAuthorities());
        response.put("principal", auth.getPrincipal());
        response.put("details", auth.getDetails());
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/test-rate-limit")
    public ResponseEntity<Map<String, Object>> testRateLimit() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Rate limit test endpoint");
        response.put("timestamp", System.currentTimeMillis());
        response.put("note", "This endpoint is rate limited to 10 requests per minute");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/test-error")
    public ResponseEntity<Map<String, Object>> testErrorHandling() {
        throw new RuntimeException("This is a test error to verify error handling");
    }
} 