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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Order(2)
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final SessionManagementService sessionManagementService;

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
                
                // Enhanced session validation with device fingerprinting
                boolean isSessionValid = sessionManagementService.validateSession(jwtToken, request);
                boolean isTokenValid = jwtService.isTokenValid(jwtToken, userDetails);
                        
                if (isTokenValid && isSessionValid) {
                    // Best Practice: Use utility class for setting security context
                    SecurityContextUtils.setSecurityContext(userDetails, jwtToken, request);
                    log.debug("Security context set for user: {}", userEmail);
                } else {
                    // Log security event for invalid session
                    log.warn("Invalid session detected for user: {} - Token valid: {} - Session valid: {}", 
                            userEmail, isTokenValid, isSessionValid);
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            // Best Practice: Clear security context on error
            SecurityContextUtils.clearSecurityContext();
            log.error("Error in JWT filter for request: {}", request.getRequestURI(), e);
            filterChain.doFilter(request, response);
        }
    }
}
