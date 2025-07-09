package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.token.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutService {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    public void logout(String token) {
        try {
            // Revoke the specific token
            tokenRepository.findByToken(token)
                    .ifPresent(tokenEntity -> {
                        tokenEntity.setExpired(true);
                        tokenEntity.setRevoked(true);
                        tokenRepository.save(tokenEntity);
                        log.info("Token revoked for user: {}", tokenEntity.getUser().getEmail());
                    });

            // Clear security context
            SecurityContextUtils.clearSecurityContext();
            
        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new RuntimeException("Logout failed", e);
        }
    }

    public void logoutAllSessions(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Revoke all tokens for the user
            var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
            validTokens.forEach(token -> {
                token.setExpired(true);
                token.setRevoked(true);
            });
            tokenRepository.saveAll(validTokens);

            log.info("All sessions revoked for user: {}", userEmail);
            
        } catch (Exception e) {
            log.error("Error during logout all sessions: {}", e.getMessage());
            throw new RuntimeException("Logout all sessions failed", e);
        }
    }
} 