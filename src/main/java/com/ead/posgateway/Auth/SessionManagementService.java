package com.ead.posgateway.Auth;

import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.session.SessionService;
import com.ead.posgateway.session.UserSession;
import com.ead.posgateway.token.Token;
import com.ead.posgateway.token.TokenRepository;
import com.ead.posgateway.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionManagementService {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final SecurityMonitoringService securityMonitoringService;
    private final SessionService sessionService;

    @Value("${spring.application.security.session.max-concurrent-sessions:3}")
    private int maxConcurrentSessions;

    @Value("${spring.application.security.session.session-timeout-minutes:30}")
    private int sessionTimeoutMinutes;

    /**
     * Create a new session with both access and refresh tokens in a single record
     */
    public Token createSession(User user, String accessToken, String refreshToken, HttpServletRequest request) {
        // Create user session first
        SessionService.SessionCreationResult result = sessionService.createSession(user, request, UserSession.SessionType.WEB);
        UserSession userSession = result.getSession();
        
        // Create token record linked to the session
        Token token = Token.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .sessionId(userSession.getSessionId())
                .createdAt(LocalDateTime.now())
                .build();

        Token savedToken = tokenRepository.save(token);

        log.info("Session and token created for user: {} with session ID: {} (reused: {})", 
                user.getEmail(), userSession.getSessionId(), result.isWasReused());

        return savedToken;
    }

    /**
     * Validate session and update last used time
     */
    public boolean validateSession(String tokenValue, HttpServletRequest request) {
        // First find the token
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isEmpty()) {
            return false;
        }

        Token token = tokenOpt.get();
        if (token.isExpired() || token.isRevoked()) {
            return false;
        }

        // Validate the associated session
        if (token.getSessionId() != null) {
            return sessionService.validateSession(token.getSessionId(), request);
        }

        return true;
    }

    /**
     * Invalidate session
     */
    public void invalidateSession(String tokenValue) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isPresent()) {
            Token token = tokenOpt.get();
            token.setRevoked(true);
            tokenRepository.save(token);

            // Invalidate the associated session
            if (token.getSessionId() != null) {
                sessionService.invalidateSession(token.getSessionId(), "Token invalidation");
            }

            log.info("Session and token invalidated for user: {}", token.getUser().getEmail());
        }
    }

    /**
     * Invalidate all sessions for a user
     */
    public void invalidateAllSessions(User user) {
        // Invalidate all user sessions
        sessionService.invalidateAllSessions(user, "All sessions logout");
        
        // Invalidate all tokens for the user
        List<Token> userTokens = tokenRepository.findByUser(user);
        userTokens.forEach(token -> {
            token.setRevoked(true);
        });
        tokenRepository.saveAll(userTokens);

        log.info("All sessions and tokens invalidated for user: {}", user.getEmail());
    }

    /**
     * Invalidate sessions older than specified time
     */
    public void cleanupExpiredSessions() {
        // Cleanup expired sessions
        sessionService.cleanupExpiredSessions();
        
        // Cleanup expired tokens (optional - tokens are managed by JWT expiration)
        log.info("Expired sessions and tokens cleaned up");
    }

    /**
     * Get active sessions for a user
     */
    public List<UserSession> getActiveSessions(User user) {
        return sessionService.getActiveSessions(user);
    }

    /**
     * Get session statistics
     */
    public SessionService.SessionStatistics getSessionStatistics(User user) {
        return sessionService.getSessionStatistics(user);
    }

    /**
     * Extend session
     */
    public void extendSession(String sessionId, int additionalMinutes) {
        sessionService.extendSession(sessionId, additionalMinutes);
    }

    /**
     * Get all sessions for a user
     */
    public List<UserSession> getAllSessions(User user) {
        return sessionService.getAllSessions(user);
    }
} 