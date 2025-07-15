/*
 * JwtAuthenticationFilter.java
 *
 * Servlet filter for JWT authentication and security context management.
 */
package com.ead.posgateway.Config;

import com.ead.posgateway.Auth.SessionManagementService;
import com.ead.posgateway.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet filter for JWT authentication and security context management.
 */
@Component
@RequiredArgsConstructor
@Order(2)
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final SessionManagementService sessionManagementService;

    /**
     * Filters requests and sets security context if JWT is valid.
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            final String authHeader = request.getHeader("Authorization");
            final String jwtToken;
            final String userEmail;
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }
            jwtToken = authHeader.substring(7);
            userEmail = jwtService.extractUserEmail(jwtToken);
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                boolean isSessionValid = sessionManagementService.validateSession(jwtToken, request);
                boolean isTokenValid = jwtService.isTokenValid(jwtToken, userDetails);
                if (isTokenValid && isSessionValid) {
                    SecurityContextUtils.setSecurityContext(userDetails, jwtToken, request);
                    log.debug("Security context set for user: {}", userEmail);
                } else {
                    log.warn("Invalid session detected for user: {} - Token valid: {} - Session valid: {}", 
                            userEmail, isTokenValid, isSessionValid);
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            SecurityContextUtils.clearSecurityContext();
            log.error("Error in JWT filter for request: {}", request.getRequestURI(), e);
            filterChain.doFilter(request, response);
        }
    }
}
