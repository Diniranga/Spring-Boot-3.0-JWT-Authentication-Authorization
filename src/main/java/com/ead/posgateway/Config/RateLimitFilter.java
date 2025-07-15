/*
 * RateLimitFilter.java
 *
 * Servlet filter for rate limiting requests to authentication endpoints.
 */
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Servlet filter for rate limiting requests to authentication endpoints.
 */
@Component
@Slf4j
@Order(1)
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastResetTime = new ConcurrentHashMap<>();
    private final RateLimitConfiguration rateLimitConfiguration;

    /**
     * Filters requests and applies rate limiting if enabled.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        String clientIp = getClientIpAddress(request);
        String requestURI = request.getRequestURI();
        if (rateLimitConfiguration.isEnabled() && requestURI.startsWith("/auth/")) {
            boolean isExcluded = false;
            for (String excludedPath : rateLimitConfiguration.getExcludedPaths()) {
                if (requestURI.equals(excludedPath)) {
                    isExcluded = true;
                    break;
                }
            }
            if (!isExcluded && isRateLimited(clientIp)) {
                log.warn("Rate limit exceeded for IP: {} on endpoint: {}", clientIp, requestURI);
                response.setStatus(429); // Too Many Requests
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Rate limit exceeded. Please try again later.\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Checks if the client IP is rate limited.
     */
    private boolean isRateLimited(String clientIp) {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastResetTime.getOrDefault(clientIp, 0L) > rateLimitConfiguration.getResetIntervalMs()) {
            requestCounts.put(clientIp, new AtomicInteger(0));
            lastResetTime.put(clientIp, currentTime);
        }
        AtomicInteger count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
        return count.incrementAndGet() > rateLimitConfiguration.getMaxRequestsPerMinute();
    }

    /**
     * Gets the client IP address from the request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
} 