package com.ead.posgateway.Config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
@Order(0) // Execute before other filters
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final HttpsConfiguration httpsConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        if (httpsConfiguration.isEnabled()) {
            // Add security headers
            addSecurityHeaders(response);
            
            // Redirect HTTP to HTTPS if enabled
            if (httpsConfiguration.isRedirectHttp() && !isSecure(request)) {
                redirectToHttps(request, response);
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }

    private void addSecurityHeaders(HttpServletResponse response) {
        // HTTP Strict Transport Security (HSTS)
        if (httpsConfiguration.isHstsEnabled()) {
            response.setHeader("Strict-Transport-Security", 
                "max-age=" + httpsConfiguration.getHstsMaxAge() + "; includeSubDomains");
        }
        
        // Prevent clickjacking
        response.setHeader("X-Frame-Options", "DENY");
        
        // Prevent MIME type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        // Content Security Policy
        response.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';");
        
        // Referrer Policy
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // XSS Protection
        response.setHeader("X-XSS-Protection", "1; mode=block");
        
        // Permissions Policy
        response.setHeader("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()");
        
        // Remove server information
        response.setHeader("Server", "");
    }

    private boolean isSecure(HttpServletRequest request) {
        return request.isSecure() || 
               "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")) ||
               "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Scheme"));
    }

    private void redirectToHttps(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestURL = request.getRequestURL().toString();
        String httpsURL = requestURL.replace("http://", "https://");
        
        log.info("Redirecting HTTP request to HTTPS: {} -> {}", requestURL, httpsURL);
        response.sendRedirect(httpsURL);
    }
} 