/*
 * SessionManagementService.java
 *
 * Service for managing user sessions and associated tokens.
 * Handles session creation, validation, invalidation, and cleanup for authentication flows.
 */
package com.ead.posgateway.Auth;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.session.SessionService;
import com.ead.posgateway.session.UserSession;
import com.ead.posgateway.token.Token;
import com.ead.posgateway.token.TokenRepository;
import com.ead.posgateway.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Service for managing user sessions and associated tokens.
 */
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
     * Create a new session and associated token for a user.
     * @param user the user
     * @param accessToken access token
     * @param refreshToken refresh token
     * @param request HTTP request
     * @return created Token
     */
    public Token createSession(User user, String accessToken, String refreshToken, HttpServletRequest request) {
        SessionService.SessionCreationResult result = sessionService.createSession(user, request, UserSession.SessionType.WEB);
        UserSession userSession = result.getSession();
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
        log.info("Session and token created for user: {} with session ID: {} (reused: {})", user.getEmail(), userSession.getSessionId(), result.isWasReused());
        return savedToken;
    }

    /**
     * Validate a session and update last used time.
     * @param tokenValue token value
     * @param request HTTP request
     * @return true if valid, false otherwise
     */
    public boolean validateSession(String tokenValue, HttpServletRequest request) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isEmpty()) {
            return false;
        }
        Token token = tokenOpt.get();
        if (token.isExpired() || token.isRevoked()) {
            return false;
        }
        if (token.getSessionId() != null) {
            return sessionService.validateSession(token.getSessionId(), request);
        }
        return true;
    }

    /**
     * Invalidate a specific session by token.
     * @param tokenValue token value
     */
    public void invalidateSession(String tokenValue) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isPresent()) {
            Token token = tokenOpt.get();
            token.setRevoked(true);
            tokenRepository.save(token);
            if (token.getSessionId() != null) {
                sessionService.invalidateSession(token.getSessionId(), "Token invalidation");
            }
            log.info("Session and token invalidated for user: {}", token.getUser().getEmail());
        }
    }

    /**
     * Invalidate all sessions for a user.
     * @param user the user
     */
    public void invalidateAllSessions(User user) {
        sessionService.invalidateAllSessions(user, "All sessions logout");
        List<Token> userTokens = tokenRepository.findByUser(user);
        userTokens.forEach(token -> token.setRevoked(true));
        tokenRepository.saveAll(userTokens);
        log.info("All sessions and tokens invalidated for user: {}", user.getEmail());
    }

    /**
     * Cleanup expired sessions and tokens.
     */
    public void cleanupExpiredSessions() {
        sessionService.cleanupExpiredSessions();
        log.info("Expired sessions and tokens cleaned up");
    }

    /**
     * Get active sessions for a user.
     * @param user the user
     * @return list of active sessions
     */
    public List<UserSession> getActiveSessions(User user) {
        return sessionService.getActiveSessions(user);
    }

    /**
     * Get session statistics for a user.
     * @param user the user
     * @return session statistics
     */
    public SessionService.SessionStatistics getSessionStatistics(User user) {
        return sessionService.getSessionStatistics(user);
    }

    /**
     * Extend a session by session ID.
     * @param sessionId session ID
     * @param additionalMinutes minutes to extend
     */
    public void extendSession(String sessionId, int additionalMinutes) {
        sessionService.extendSession(sessionId, additionalMinutes);
    }

    /**
     * Get all sessions for a user.
     * @param user the user
     * @return list of all sessions
     */
    public List<UserSession> getAllSessions(User user) {
        return sessionService.getAllSessions(user);
    }
} 