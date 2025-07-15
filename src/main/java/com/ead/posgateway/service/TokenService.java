/*
 * TokenService.java
 * Service for managing JWT and refresh tokens, including creation, revocation, and validation.
 */
package com.ead.posgateway.service;

import com.ead.posgateway.Config.JwtService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.token.Token;
import com.ead.posgateway.token.TokenRepository;
import com.ead.posgateway.token.TokenType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Service for managing JWT and refresh tokens, including creation, revocation, and validation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class TokenService {

    /** Repository for token persistence. */
    private final TokenRepository tokenRepository;
    /** Service for JWT operations. */
    private final JwtService jwtService;

    /**
     * Creates and saves a new token for the user.
     * @param user User entity
     * @param accessToken JWT access token
     * @param refreshToken JWT refresh token
     * @param sessionId Session identifier
     * @return Saved Token entity
     */
    public Token createToken(final User user, final String accessToken, final String refreshToken, final String sessionId) {
        Token token = Token.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .sessionId(sessionId)
                .createdAt(LocalDateTime.now())
                .isActive(true)
                .build();

        Token savedToken = tokenRepository.save(token);
        log.debug("Token created for user: {} with session ID: {}", user.getEmail(), sessionId);
        return savedToken;
    }

    /**
     * Finds a token by its value.
     * @param tokenValue Token string
     * @return Optional containing the Token if found
     */
    public Optional<Token> findByToken(final String tokenValue) {
        return tokenRepository.findByToken(tokenValue);
    }

    /**
     * Finds all tokens for a user.
     * @param user User entity
     * @return List of Token entities
     */
    public List<Token> findByUser(final User user) {
        return tokenRepository.findByUser(user);
    }

    /**
     * Revokes a token by its value.
     * @param tokenValue Token string
     */
    public void revokeToken(final String tokenValue) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isPresent()) {
            Token token = tokenOpt.get();
            token.setRevoked(true);
            token.setIsActive(false);
            tokenRepository.save(token);
            log.info("Token revoked for user: {}", token.getUser().getEmail());
        }
    }

    /**
     * Revokes all tokens for a user.
     * @param user User entity
     */
    public void revokeAllUserTokens(final User user) {
        List<Token> userTokens = tokenRepository.findByUser(user);
        userTokens.forEach(token -> {
            token.setRevoked(true);
            token.setIsActive(false);
        });
        tokenRepository.saveAll(userTokens);
        log.info("All tokens revoked for user: {}", user.getEmail());
    }

    /**
     * Revokes all tokens associated with a session ID.
     * @param sessionId Session identifier
     */
    public void revokeTokensBySessionId(final String sessionId) {
        List<Token> sessionTokens = tokenRepository.findBySessionIdAndRevokedFalse(sessionId);
        sessionTokens.forEach(token -> {
            token.setRevoked(true);
            token.setIsActive(false);
        });
        tokenRepository.saveAll(sessionTokens);
        log.info("Revoked {} tokens for session: {}", sessionTokens.size(), sessionId);
    }

    /**
     * Generates a JWT access token for the given user details.
     * @param userDetails UserDetails
     * @return JWT access token string
     */
    public String generateAccessToken(final UserDetails userDetails) {
        return jwtService.generateToken(userDetails);
    }

    /**
     * Generates a JWT refresh token for the given user details.
     * @param userDetails UserDetails
     * @return JWT refresh token string
     */
    public String generateRefreshToken(final UserDetails userDetails) {
        return jwtService.generateRefreshToken(userDetails);
    }

    /**
     * Validates a JWT token for the given user details.
     * @param token JWT token string
     * @param userDetails UserDetails
     * @return true if valid, false otherwise
     */
    public boolean isTokenValid(final String token, final UserDetails userDetails) {
        return jwtService.isTokenValid(token, userDetails);
    }

    /**
     * Extracts the user email from a JWT token.
     * @param token JWT token string
     * @return user email (subject)
     */
    public String extractUserEmail(final String token) {
        return jwtService.extractUserEmail(token);
    }
} 