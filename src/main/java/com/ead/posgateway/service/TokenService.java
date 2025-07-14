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

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class TokenService {

    private final TokenRepository tokenRepository;
    private final JwtService jwtService;

    public Token createToken(User user, String accessToken, String refreshToken, String sessionId) {
        Token token = Token.builder()
                .user(user)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .sessionId(sessionId)
                .createdAt(LocalDateTime.now())
                .build();

        Token savedToken = tokenRepository.save(token);
        log.debug("Token created for user: {} with session ID: {}", user.getEmail(), sessionId);
        return savedToken;
    }

    public Optional<Token> findByToken(String tokenValue) {
        return tokenRepository.findByToken(tokenValue);
    }

    public List<Token> findByUser(User user) {
        return tokenRepository.findByUser(user);
    }

    public void revokeToken(String tokenValue) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isPresent()) {
            Token token = tokenOpt.get();
            token.setExpired(true);
            token.setRevoked(true);
            tokenRepository.save(token);
            log.info("Token revoked for user: {}", token.getUser().getEmail());
        }
    }

    public void revokeAllUserTokens(User user) {
        List<Token> userTokens = tokenRepository.findByUser(user);
        userTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(userTokens);
        log.info("All tokens revoked for user: {}", user.getEmail());
    }

    public void revokeTokensBySessionId(String sessionId) {
        List<Token> sessionTokens = tokenRepository.findBySessionIdAndExpiredFalseAndRevokedFalse(sessionId);
        sessionTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(sessionTokens);
        log.info("Revoked {} tokens for session: {}", sessionTokens.size(), sessionId);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return jwtService.generateToken(userDetails);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return jwtService.generateRefreshToken(userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return jwtService.isTokenValid(token, userDetails);
    }

    public String extractUserEmail(String token) {
        return jwtService.extractUserEmail(token);
    }
} 