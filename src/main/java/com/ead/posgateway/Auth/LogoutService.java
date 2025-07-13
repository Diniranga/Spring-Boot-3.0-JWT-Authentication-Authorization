package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutService {

    private final SessionManagementService sessionManagementService;
    private final UserRepository userRepository;

    public void logout(String token) {
        try {
            // Invalidate the specific session
            sessionManagementService.invalidateSession(token);

            // Clear security context
            SecurityContextUtils.clearSecurityContext();
            
            log.info("User logged out successfully");
            
        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new RuntimeException("Logout failed", e);
        }
    }

    public void logoutAllSessions(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Invalidate all sessions for the user
            sessionManagementService.invalidateAllSessions(user);

            log.info("All sessions logged out for user: {}", userEmail);
            
        } catch (Exception e) {
            log.error("Error during logout all sessions: {}", e.getMessage());
            throw new RuntimeException("Logout all sessions failed", e);
        }
    }
} 