package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.Auth.LogoutService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.token.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;
    private final LogoutService logoutService;
    private final SessionManagementService sessionManagementService;
    private final SecurityMonitoringService securityMonitoringService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest
    ){
        return ResponseEntity.ok(service.register(request, httpRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request,
            HttpServletRequest httpRequest
    ){
        return ResponseEntity.ok(service.authenticate(request, httpRequest));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }

    @PostMapping("/validateToken")
    public boolean validateToken(
            @RequestBody TokenValidationRequest tokenValidationRequest,
            HttpServletRequest request
    ){
        return service.validateToken(tokenValidationRequest.getToken(), tokenValidationRequest.getEmail(), request);
    }

    @PostMapping("/security-context")
    public ResponseEntity<Map<String, Object>> getSecurityContext() {
        Authentication authentication = SecurityContextUtils.getCurrentAuthentication();
        Map<String, Object> contextInfo = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            contextInfo.put("authenticated", true);
            contextInfo.put("principal", authentication.getPrincipal());
            contextInfo.put("authorities", authentication.getAuthorities());
            contextInfo.put("details", authentication.getDetails());
        } else {
            contextInfo.put("authenticated", false);
        }
        
        return ResponseEntity.ok(contextInfo);
    }

    @PostMapping("/verify-authentication")
    public ResponseEntity<Map<String, Object>> verifyAuthentication() {
        Map<String, Object> response = new HashMap<>();
        
        if (SecurityContextUtils.isAuthenticated()) {
            response.put("authenticated", true);
            response.put("userEmail", SecurityContextUtils.getCurrentUserEmail());
            response.put("authorities", SecurityContextUtils.getCurrentAuthentication().getAuthorities());
            response.put("message", "User is authenticated");
        } else {
            response.put("authenticated", false);
            response.put("message", "User is not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        Map<String, String> response = new HashMap<>();
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            logoutService.logout(token);
            response.put("message", "Logout successful");
        } else {
            response.put("message", "No token provided");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, String>> logoutAllSessions() {
        Map<String, String> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            logoutService.logoutAllSessions(userEmail);
            response.put("message", "All sessions logged out successfully");
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/account-status")
    public ResponseEntity<Map<String, Object>> getAccountStatus(@RequestBody AuthenticationRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        var userOpt = service.getUserRepository().findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            response.put("exists", false);
            response.put("message", "Account not found");
        } else {
            var user = userOpt.get();
            response.put("exists", true);
            response.put("accountLocked", user.isAccountLocked());
            response.put("failedLoginAttempts", user.getFailedLoginAttempts());
            response.put("activeSessions", user.getActiveSessions());
            response.put("maxConcurrentSessions", user.getMaxConcurrentSessions());
            response.put("lastLoginTime", user.getLastLoginTime());
            response.put("lastLoginIp", user.getLastLoginIp());
            response.put("lastPasswordChange", user.getLastPasswordChange());
            
            if (user.isAccountLocked() && user.getLockTime() != null) {
                long minutesSinceLock = ChronoUnit.MINUTES.between(
                    user.getLockTime(), LocalDateTime.now());
                long remainingMinutes = Math.max(0, 15 - minutesSinceLock); // 15 is cooldown from config
                response.put("remainingLockMinutes", remainingMinutes);
                response.put("lockTime", user.getLockTime());
            }
            
            response.put("message", "Account status retrieved");
        }
        
        return ResponseEntity.ok(response);
    }

    // Session management endpoints

    @GetMapping("/sessions")
    public ResponseEntity<Map<String, Object>> getActiveSessions() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            var userOpt = service.getUserRepository().findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                var sessionStatistics = sessionManagementService.getSessionStatistics(user);
                var activeSessions = sessionManagementService.getActiveSessions(user);
                
                response.put("userEmail", userEmail);
                response.put("sessionStatistics", sessionStatistics);
                response.put("sessions", activeSessions.stream().map(session -> {
                    Map<String, Object> sessionInfo = new HashMap<>();
                    sessionInfo.put("sessionId", session.getSessionId());
                    sessionInfo.put("sessionType", session.getSessionType());
                    sessionInfo.put("loginMethod", session.getLoginMethod());
                    sessionInfo.put("ipAddress", session.getIpAddress());
                    sessionInfo.put("userAgent", session.getUserAgent());
                    sessionInfo.put("deviceFingerprint", session.getDeviceFingerprint());
                    sessionInfo.put("deviceInfo", session.getDeviceInfo());
                    sessionInfo.put("geographicLocation", session.getGeographicLocation());
                    sessionInfo.put("createdAt", session.getCreatedAt());
                    sessionInfo.put("lastUsedAt", session.getLastUsedAt());
                    sessionInfo.put("expiresAt", session.getExpiresAt());
                    sessionInfo.put("isValid", session.isValid());
                    sessionInfo.put("isExpired", session.isExpired());
                    sessionInfo.put("isRevoked", session.isRevoked());
                    sessionInfo.put("revokedReason", session.getRevokedReason());
                    sessionInfo.put("revokedAt", session.getRevokedAt());
                    sessionInfo.put("revokedBy", session.getRevokedBy());
                    return sessionInfo;
                }).toList());
                response.put("message", "Active sessions retrieved");
            } else {
                response.put("message", "User not found");
            }
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/sessions/all")
    public ResponseEntity<Map<String, Object>> getAllSessions() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            var userOpt = service.getUserRepository().findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                var allSessions = sessionManagementService.getAllSessions(user);
                
                response.put("userEmail", userEmail);
                response.put("totalSessions", allSessions.size());
                response.put("sessions", allSessions.stream().map(session -> {
                    Map<String, Object> sessionInfo = new HashMap<>();
                    sessionInfo.put("sessionId", session.getSessionId());
                    sessionInfo.put("sessionType", session.getSessionType());
                    sessionInfo.put("loginMethod", session.getLoginMethod());
                    sessionInfo.put("ipAddress", session.getIpAddress());
                    sessionInfo.put("userAgent", session.getUserAgent());
                    sessionInfo.put("deviceFingerprint", session.getDeviceFingerprint());
                    sessionInfo.put("deviceInfo", session.getDeviceInfo());
                    sessionInfo.put("geographicLocation", session.getGeographicLocation());
                    sessionInfo.put("createdAt", session.getCreatedAt());
                    sessionInfo.put("lastUsedAt", session.getLastUsedAt());
                    sessionInfo.put("expiresAt", session.getExpiresAt());
                    sessionInfo.put("isValid", session.isValid());
                    sessionInfo.put("isExpired", session.isExpired());
                    sessionInfo.put("isRevoked", session.isRevoked());
                    sessionInfo.put("revokedReason", session.getRevokedReason());
                    sessionInfo.put("revokedAt", session.getRevokedAt());
                    sessionInfo.put("revokedBy", session.getRevokedBy());
                    return sessionInfo;
                }).toList());
                response.put("message", "All sessions retrieved");
            } else {
                response.put("message", "User not found");
            }
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/sessions/{sessionId}/extend")
    public ResponseEntity<Map<String, String>> extendSession(
            @PathVariable String sessionId,
            @RequestBody Map<String, Integer> request
    ) {
        Map<String, String> response = new HashMap<>();
        
        Integer additionalMinutes = request.get("additionalMinutes");
        if (additionalMinutes != null && additionalMinutes > 0) {
            try {
                sessionManagementService.extendSession(sessionId, additionalMinutes);
                response.put("message", "Session extended by " + additionalMinutes + " minutes");
            } catch (Exception e) {
                response.put("message", "Failed to extend session: " + e.getMessage());
            }
        } else {
            response.put("message", "Invalid additional minutes value");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        String newPassword = request.get("newPassword");
        
        if (userEmail != null && newPassword != null) {
            try {
                service.changePassword(userEmail, newPassword);
                response.put("message", "Password changed successfully. All sessions have been invalidated for security.");
            } catch (Exception e) {
                response.put("message", "Failed to change password: " + e.getMessage());
            }
        } else {
            response.put("message", "Invalid request parameters");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/cleanup-sessions")
    public ResponseEntity<Map<String, String>> cleanupExpiredSessions() {
        Map<String, String> response = new HashMap<>();
        
        try {
            sessionManagementService.cleanupExpiredSessions();
            response.put("message", "Expired sessions cleaned up successfully");
        } catch (Exception e) {
            response.put("message", "Failed to cleanup sessions: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    // Security monitoring endpoints

    @GetMapping("/security/statistics")
    public ResponseEntity<Map<String, Object>> getSecurityStatistics() {
        Map<String, Object> response = new HashMap<>();
        
        // Check if user has admin role
        if (SecurityContextUtils.hasAuthority("ROLE_ADMIN")) {
            Map<String, Object> stats = securityMonitoringService.getSecurityStatistics();
            response.put("statistics", stats);
            response.put("message", "Security statistics retrieved");
        } else {
            response.put("message", "Access denied. Admin role required.");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/security/reset-counters")
    public ResponseEntity<Map<String, String>> resetSecurityCounters(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        
        // Check if user has admin role
        if (SecurityContextUtils.hasAuthority("ROLE_ADMIN")) {
            String userEmail = request.get("userEmail");
            if (userEmail != null) {
                securityMonitoringService.resetUserSecurityCounters(userEmail);
                response.put("message", "Security counters reset for user: " + userEmail);
            } else {
                response.put("message", "User email is required");
            }
        } else {
            response.put("message", "Access denied. Admin role required.");
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/security/events")
    public ResponseEntity<Map<String, Object>> getSecurityEvents() {
        Map<String, Object> response = new HashMap<>();
        
        // Check if user has admin role
        if (SecurityContextUtils.hasAuthority("ROLE_ADMIN")) {
            Map<String, Object> stats = securityMonitoringService.getSecurityStatistics();
            response.put("securityEvents", stats);
            response.put("message", "Security events retrieved");
        } else {
            response.put("message", "Access denied. Admin role required.");
        }
        
        return ResponseEntity.ok(response);
    }
}
