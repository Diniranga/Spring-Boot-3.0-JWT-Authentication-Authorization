package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.Auth.LogoutService;
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
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;
    private final LogoutService logoutService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }

    @PostMapping("/validateToken")
    public boolean validateToken(@RequestBody TokenValidationRequest tokenValidationRequest){
        return service.validateToken(tokenValidationRequest.getToken(), tokenValidationRequest.getEmail());
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
}
