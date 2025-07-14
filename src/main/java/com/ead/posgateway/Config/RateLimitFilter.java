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

@Component
@Slf4j
@Order(1)
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastResetTime = new ConcurrentHashMap<>();
    
    private final RateLimitConfiguration rateLimitConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientIp = getClientIpAddress(request);
        String requestURI = request.getRequestURI();
        
        // Only apply rate limiting to authentication endpoints if enabled
        if (rateLimitConfiguration.isEnabled() && requestURI.startsWith("/auth/")) {
            // Check if path is excluded
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

    private boolean isRateLimited(String clientIp) {
        long currentTime = System.currentTimeMillis();
        
        // Reset counter if interval has passed
        if (currentTime - lastResetTime.getOrDefault(clientIp, 0L) > rateLimitConfiguration.getResetIntervalMs()) {
            requestCounts.put(clientIp, new AtomicInteger(0));
            lastResetTime.put(clientIp, currentTime);
        }
        
        AtomicInteger count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
        return count.incrementAndGet() > rateLimitConfiguration.getMaxRequestsPerMinute();
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
} 