package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.Auth.LogoutService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.dto.SessionDto;
import com.ead.posgateway.dto.UserDto;
import com.ead.posgateway.session.SessionService;
import com.ead.posgateway.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationService service;
    private final LogoutService logoutService;
    private final SessionService sessionService;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Registration request received for email: {}", request.getEmail());
        return ResponseEntity.ok(service.register(request, httpRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @Valid @RequestBody AuthenticationRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Login request received for email: {}", request.getEmail());
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
            log.info("User logged out successfully");
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
            log.info("All sessions logged out for user: {}", userEmail);
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/account-status")
    public ResponseEntity<UserDto> getAccountStatus(@Valid @RequestBody AuthenticationRequest request) {
        UserDto userDto = service.getAccountStatus(request.getEmail());
        return ResponseEntity.ok(userDto);
    }

    // Session management endpoints

    @GetMapping("/sessions")
    public ResponseEntity<Map<String, Object>> getActiveSessions() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            var userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                var activeSessions = sessionService.getActiveSessions(user);
                
                response.put("userEmail", userEmail);
                response.put("activeSessions", activeSessions.size());
                response.put("maxConcurrentSessions", user.getMaxConcurrentSessions());
                response.put("sessions", activeSessions.stream()
                        .map(SessionDto::fromUserSession)
                        .collect(Collectors.toList()));
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
            var userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                var allSessions = sessionService.getAllSessions(user);
                
                response.put("userEmail", userEmail);
                response.put("totalSessions", allSessions.size());
                response.put("sessions", allSessions.stream()
                        .map(SessionDto::fromUserSession)
                        .collect(Collectors.toList()));
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
        if (additionalMinutes == null || additionalMinutes <= 0) {
            response.put("message", "Invalid additional minutes value");
            return ResponseEntity.badRequest().body(response);
        }
        
        sessionService.extendSession(sessionId, additionalMinutes);
        response.put("message", "Session extended successfully");
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        
        String newPassword = request.get("newPassword");
        if (newPassword == null || newPassword.trim().isEmpty()) {
            response.put("message", "New password is required");
            return ResponseEntity.badRequest().body(response);
        }
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            service.changePassword(userEmail, newPassword);
            response.put("message", "Password changed successfully. All sessions have been invalidated for security.");
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/cleanup-sessions")
    public ResponseEntity<Map<String, String>> cleanupExpiredSessions() {
        Map<String, String> response = new HashMap<>();
        
        sessionService.cleanupExpiredSessions();
        response.put("message", "Expired sessions cleaned up successfully");
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/security/statistics")
    public ResponseEntity<Map<String, Object>> getSecurityStatistics() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            var userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                UserDto userDto = userService.getUserDto(user);
                
                response.put("userEmail", userEmail);
                response.put("accountStatus", userDto);
                response.put("activeSessions", sessionService.getActiveSessions(user).size());
                response.put("totalSessions", sessionService.getAllSessions(user).size());
                response.put("message", "Security statistics retrieved");
            } else {
                response.put("message", "User not found");
            }
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/security/reset-counters")
    public ResponseEntity<Map<String, String>> resetSecurityCounters(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            var userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                userService.resetFailedAttempts(user);
                response.put("message", "Security counters reset successfully");
            } else {
                response.put("message", "User not found");
            }
        } else {
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }
}
