/*
 * LogOutService.java
 *
 * Service for handling logout by revoking JWT tokens.
 */
package com.ead.posgateway.Config;

import com.ead.posgateway.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

/**
 * Service for handling logout by revoking JWT tokens.
 */
@Service
@RequiredArgsConstructor
public class LogOutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    /**
     * Handles logout by revoking the JWT token if present in the Authorization header.
     * @param request HTTP request
     * @param response HTTP response
     * @param authentication authentication object
     */
    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwtToken = authHeader.substring(7);
        var storedToken = tokenRepository.findByToken(jwtToken)
                .orElse(null);
        if (storedToken != null) {
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }
    }
}
