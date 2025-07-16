/*
 * LogoutService.java
 *
 * Service for handling user logout operations.
 * Provides methods to logout from a single session or all sessions for a user.
 */
package com.example.auth.Auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.auth.Config.SecurityContextUtils;
import com.example.auth.User.User;
import com.example.auth.User.UserRepository;

/**
 * Service for handling user logout operations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class LogoutService {
    private final SessionManagementService sessionManagementService;
    private final UserRepository userRepository;

    /**
     * Logout from the current session using the provided token.
     * @param token JWT token
     */
    public void logout(String token) {
        try {
            sessionManagementService.invalidateSession(token);
            SecurityContextUtils.clearSecurityContext();
            log.info("User logged out successfully");
        } catch (RuntimeException e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new RuntimeException("Logout failed", e);
        }
    }

    /**
     * Logout from all sessions for the given user email.
     * @param userEmail user email
     */
    public void logoutAllSessions(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            sessionManagementService.invalidateAllSessions(user);
            log.info("All sessions logged out for user: {}", userEmail);
        } catch (RuntimeException e) {
            log.error("Error during logout all sessions: {}", e.getMessage());
            throw new RuntimeException("Logout all sessions failed", e);
        }
    }
} 