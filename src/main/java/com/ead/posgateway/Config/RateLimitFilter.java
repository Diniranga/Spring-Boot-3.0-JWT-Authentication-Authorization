package com.ead.posgateway.Config;

import com.ead.posgateway.Config.SecurityMonitoringService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastResetTime = new ConcurrentHashMap<>();
    private final SecurityMonitoringService securityMonitoringService;
    
    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long RESET_INTERVAL = 60000; // 1 minute

    public RateLimitFilter(SecurityMonitoringService securityMonitoringService) {
        this.securityMonitoringService = securityMonitoringService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientIp = getClientIpAddress(request);
        String requestURI = request.getRequestURI();
        
        // Only apply rate limiting to authentication endpoints
        if (requestURI.startsWith("/auth/") && !requestURI.equals("/auth/refresh-token")) {
            if (isRateLimited(clientIp)) {
                log.warn("Rate limit exceeded for IP: {} on endpoint: {}", clientIp, requestURI);
                securityMonitoringService.logRateLimitViolation(clientIp, requestURI);
                response.setStatus(429); // Too Many Requests
                response.getWriter().write("Rate limit exceeded. Please try again later.");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }

    private boolean isRateLimited(String clientIp) {
        long currentTime = System.currentTimeMillis();
        
        // Reset counter if interval has passed
        if (currentTime - lastResetTime.getOrDefault(clientIp, 0L) > RESET_INTERVAL) {
            requestCounts.put(clientIp, new AtomicInteger(0));
            lastResetTime.put(clientIp, currentTime);
        }
        
        AtomicInteger count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
        return count.incrementAndGet() > MAX_REQUESTS_PER_MINUTE;
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
} 