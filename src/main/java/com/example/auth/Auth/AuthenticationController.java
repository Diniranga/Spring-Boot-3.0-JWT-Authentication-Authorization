/*
 * AuthenticationController.java
 *
 * REST controller for authentication, registration, password reset, session management, and security endpoints.
 * Handles user login, registration, token validation, password reset, session operations, and security statistics.
 */
package com.example.auth.Auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.example.auth.Config.SecurityContextUtils;
import com.example.auth.dto.SessionDto;
import com.example.auth.dto.UserDto;
import com.example.auth.session.SessionService;
import com.example.auth.service.UserService;

/**
 * REST controller for authentication, registration, password reset, session management, and security endpoints.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {
    private final AuthenticationService service;
    private final LogoutService logoutService;
    private final SessionService sessionService;
    private final UserService userService;

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Registration request received for email: {}", request.getEmail());
        return ResponseEntity.ok(service.register(request, httpRequest));
    }

    /**
     * Login endpoint.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @Valid @RequestBody AuthenticationRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Login request received for email: {}", request.getEmail());
        return ResponseEntity.ok(service.authenticate(request, httpRequest));
    }

    /**
     * Refresh JWT tokens.
     */
    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }

    /**
     * Validate a JWT token.
     */
    @PostMapping("/validateToken")
    public ResponseEntity<Map<String, Object>> validateToken(
            @Valid @RequestBody TokenValidationRequest tokenValidationRequest,
            HttpServletRequest request
    ) {
        boolean isValid = service.validateToken(tokenValidationRequest.getToken(), tokenValidationRequest.getEmail(), request);
        Map<String, Object> response = new HashMap<>();
        response.put("valid", isValid);
        response.put("message", isValid ? "Token is valid" : "Token is invalid");
        return ResponseEntity.ok(response);
    }

    /**
     * Get the current security context.
     */
    @PostMapping("/security-context")
    public ResponseEntity<Map<String, Object>> getSecurityContext() {
        Authentication authentication = SecurityContextUtils.getCurrentAuthentication();
        Map<String, Object> contextInfo = new HashMap<>();
        if (authentication != null && authentication.isAuthenticated()) {
            contextInfo.put("authenticated", true);
            Object principal = authentication.getPrincipal();
            if (principal instanceof com.example.auth.User.User user) {
                // Map User entity to UserDto
                UserDto userDto = UserDto.builder()
                        .id(user.getId())
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .lastLoginTime(user.getLastLoginTime())
                        .lastLoginIp(user.getLastLoginIp())
                        .accountLocked(user.isAccountLocked())
                        .activeSessions(user.getActiveSessions())
                        .maxConcurrentSessions(user.getMaxConcurrentSessions())
                        .build();
                contextInfo.put("principal", userDto);
            } else {
                contextInfo.put("principal", principal);
            }
            contextInfo.put("authorities", authentication.getAuthorities());
            contextInfo.put("details", authentication.getDetails());
        } else {
            contextInfo.put("authenticated", false);
        }
        return ResponseEntity.ok(contextInfo);
    }

    /**
     * Logout from the current session.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        Map<String, String> response = new HashMap<>();
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            logoutService.logout(token);
            response.put("message", "Logout successful");
            log.info("User logged out successfully");
        } else {
            response.put("message", "No token provided");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Logout from all sessions.
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, String>> logoutAllSessions() {
        Map<String, String> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            logoutService.logoutAllSessions(userEmail);
            response.put("message", "All sessions logged out successfully");
            log.info("All sessions logged out for user: {}", userEmail);
        } else {
            response.put("message", "User not authenticated");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Get account status for a user.
     */
    @PostMapping("/account-status")
    public ResponseEntity<UserDto> getAccountStatus(@Valid @RequestBody AuthenticationRequest request) {
        UserDto userDto = service.getAccountStatus(request.getEmail());
        return ResponseEntity.ok(userDto);
    }

    /**
     * Request a password reset (forgot password).
     */
    @PostMapping("/forgot-password-reset")
    public ResponseEntity<Map<String, String>> forgotPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        service.requestPasswordReset(request.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("message", "If the email exists, a password reset link has been sent.");
        return ResponseEntity.ok(response);
    }

    /**
     * Reset password using a reset token.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody PasswordResetSubmitRequest request) {
        service.resetPassword(request.getToken(), request.getNewPassword());
        Map<String, String> response = new HashMap<>();
        response.put("message", "Password has been reset successfully.");
        return ResponseEntity.ok(response);
    }

    /**
     * Get active sessions for the current user.
     */
    @GetMapping("/sessions")
    public ResponseEntity<Map<String, Object>> getActiveSessions() {
        Map<String, Object> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            userService.findByEmail(userEmail).ifPresentOrElse(user -> {
                var activeSessions = sessionService.getActiveSessions(user);
                response.put("userEmail", userEmail);
                response.put("activeSessions", activeSessions.size());
                response.put("maxConcurrentSessions", user.getMaxConcurrentSessions());
                response.put("sessions", activeSessions.stream().map(SessionDto::fromUserSession).collect(Collectors.toList()));
                response.put("message", "Active sessions retrieved");
            }, () -> response.put("message", "User not found"));
        } else {
            response.put("message", "User not authenticated");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Get all sessions for the current user.
     */
    @GetMapping("/sessions/all")
    public ResponseEntity<Map<String, Object>> getAllSessions() {
        Map<String, Object> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            userService.findByEmail(userEmail).ifPresentOrElse(user -> {
                var allSessions = sessionService.getAllSessions(user);
                response.put("userEmail", userEmail);
                response.put("totalSessions", allSessions.size());
                response.put("sessions", allSessions.stream().map(SessionDto::fromUserSession).collect(Collectors.toList()));
                response.put("message", "All sessions retrieved");
            }, () -> response.put("message", "User not found"));
        } else {
            response.put("message", "User not authenticated");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Extend a session by session ID.
     */
    @PostMapping("/sessions/{sessionId}/extend")
    public ResponseEntity<Map<String, String>> extendSession(
            @PathVariable String sessionId,
            @RequestBody Map<String, Integer> request
    ) {
        Map<String, String> response = new HashMap<>();
        Integer additionalMinutes = request.get("additionalMinutes");
        if (additionalMinutes == null || additionalMinutes <= 0) {
            response.put("message", "Invalid additional minutes value");
            return ResponseEntity.badRequest().body(response);
        }
        sessionService.extendSession(sessionId, additionalMinutes);
        response.put("message", "Session extended successfully");
        return ResponseEntity.ok(response);
    }

    /**
     * Change password for the current user.
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        Map<String, String> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail == null) {
            response.put("message", "User not authenticated");
            return ResponseEntity.status(401).body(response);
        }
        boolean changed = service.changePassword(userEmail, request.getOldPassword(), request.getNewPassword());
        if (changed) {
            response.put("message", "Password changed successfully. All sessions have been invalidated for security.");
            return ResponseEntity.ok(response);
        } else {
            response.put("message", "Old password is incorrect");
            return ResponseEntity.status(400).body(response);
        }
    }

    /**
     * Cleanup expired sessions for the current user.
     */
    @PostMapping("/cleanup-sessions")
    public ResponseEntity<Map<String, String>> cleanupExpiredSessions() {
        Map<String, String> response = new HashMap<>();
        sessionService.cleanupExpiredSessions();
        response.put("message", "Expired sessions cleaned up successfully");
        return ResponseEntity.ok(response);
    }

    /**
     * Get security statistics for the current user.
     */
    @GetMapping("/security/statistics")
    public ResponseEntity<Map<String, Object>> getSecurityStatistics() {
        Map<String, Object> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            userService.findByEmail(userEmail).ifPresentOrElse(user -> {
                UserDto userDto = userService.getUserDto(user);
                response.put("userEmail", userEmail);
                response.put("accountStatus", userDto);
                response.put("activeSessions", sessionService.getActiveSessions(user).size());
                response.put("totalSessions", sessionService.getAllSessions(user).size());
                response.put("message", "Security statistics retrieved");
            }, () -> response.put("message", "User not found"));
        } else {
            response.put("message", "User not authenticated");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * Reset security counters for the current user.
     */
    @PostMapping("/security/reset-counters")
    public ResponseEntity<Map<String, String>> resetSecurityCounters(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            userService.findByEmail(userEmail).ifPresentOrElse(user -> {
                userService.resetFailedAttempts(user);
                response.put("message", "Security counters reset successfully");
            }, () -> response.put("message", "User not found"));
        } else {
            response.put("message", "User not authenticated");
        }
        return ResponseEntity.ok(response);
    }
}
