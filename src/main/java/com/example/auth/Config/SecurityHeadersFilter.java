/*
 * SecurityHeadersFilter.java
 *
 * Servlet filter for adding security headers and enforcing HTTPS policies.
 */
package com.example.auth.Config;

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

/**
 * Servlet filter for adding security headers and enforcing HTTPS policies.
 */
@Component
@RequiredArgsConstructor
@Slf4j
@Order(0) // Execute before other filters
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final HttpsConfiguration httpsConfiguration;

    /**
     * Adds security headers and enforces HTTPS if enabled.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        if (httpsConfiguration.isEnabled()) {
            addSecurityHeaders(response);
            if (httpsConfiguration.isRedirectHttp() && !isSecure(request)) {
                redirectToHttps(request, response);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Adds standard security headers to the response.
     */
    private void addSecurityHeaders(HttpServletResponse response) {
        if (httpsConfiguration.isHstsEnabled()) {
            response.setHeader("Strict-Transport-Security", 
                "max-age=" + httpsConfiguration.getHstsMaxAge() + "; includeSubDomains");
        }
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()");
        response.setHeader("Server", "");
    }

    /**
     * Checks if the request is secure (HTTPS).
     */
    private boolean isSecure(HttpServletRequest request) {
        return request.isSecure() || 
               "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")) ||
               "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Scheme"));
    }

    /**
     * Redirects HTTP requests to HTTPS.
     */
    private void redirectToHttps(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestURL = request.getRequestURL().toString();
        String httpsURL = requestURL.replace("http://", "https://");
        log.info("Redirecting HTTP request to HTTPS: {} -> {}", requestURL, httpsURL);
        response.sendRedirect(httpsURL);
    }
} 