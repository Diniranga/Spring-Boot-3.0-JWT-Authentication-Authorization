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

    @PostMapping("/verify-2fa")
    public ResponseEntity<AuthenticationResponse> verify2fa(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String code = body.get("code");
        return ResponseEntity.ok(service.verify2faCode(email, code));
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

    @PostMapping("/enable-2fa")
    public ResponseEntity<Map<String, Object>> enable2fa() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            try {
                service.enable2faForUser(userEmail);
                response.put("success", true);
                response.put("message", "2FA enabled successfully");
                response.put("userEmail", userEmail);
            } catch (Exception e) {
                response.put("success", false);
                response.put("message", "Failed to enable 2FA: " + e.getMessage());
            }
        } else {
            response.put("success", false);
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<Map<String, Object>> disable2fa() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            try {
                service.disable2faForUser(userEmail);
                response.put("success", true);
                response.put("message", "2FA disabled successfully");
                response.put("userEmail", userEmail);
            } catch (Exception e) {
                response.put("success", false);
                response.put("message", "Failed to disable 2FA: " + e.getMessage());
            }
        } else {
            response.put("success", false);
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/2fa-status")
    public ResponseEntity<Map<String, Object>> get2faStatus() {
        Map<String, Object> response = new HashMap<>();
        
        String userEmail = SecurityContextUtils.getCurrentUserEmail();
        if (userEmail != null) {
            try {
                boolean user2faEnabled = service.is2faEnabledForUser(userEmail);
                response.put("success", true);
                response.put("userEmail", userEmail);
                response.put("user2faEnabled", user2faEnabled);
                response.put("global2faEnabled", service.isGlobal2faEnabled());
                response.put("message", "2FA status retrieved successfully");
            } catch (Exception e) {
                response.put("success", false);
                response.put("message", "Failed to get 2FA status: " + e.getMessage());
            }
        } else {
            response.put("success", false);
            response.put("message", "User not authenticated");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-2fa")
    public ResponseEntity<Map<String, Object>> resend2faCode(@RequestBody Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        
        String email = body.get("email");
        if (email != null) {
            try {
                service.resend2faCode(email);
                response.put("success", true);
                response.put("message", "2FA code resent successfully");
                response.put("userEmail", email);
            } catch (Exception e) {
                response.put("success", false);
                response.put("message", "Failed to resend 2FA code: " + e.getMessage());
            }
        } else {
            response.put("success", false);
            response.put("message", "Email is required");
        }
        
        return ResponseEntity.ok(response);
    }
}
