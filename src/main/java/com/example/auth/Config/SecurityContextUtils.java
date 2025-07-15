/*
 * SecurityContextUtils.java
 *
 * Utility class for managing Spring Security context and authentication details.
 */
package com.example.auth.Config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility class for managing Spring Security context and authentication details.
 */
@Component
public class SecurityContextUtils {

    /**
     * Sets the security context for the current thread.
     * @param userDetails user details
     * @param credentials credentials (e.g., JWT)
     * @param request HTTP request
     */
    public static void setSecurityContext(UserDetails userDetails, String credentials, HttpServletRequest request) {
        try {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    credentials,
                    userDetails.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            throw new RuntimeException("Failed to set security context", e);
        }
    }

    /**
     * Clears the security context for the current thread.
     */
    public static void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Gets the current authentication object.
     * @return the current Authentication, or null if not authenticated
     */
    public static Authentication getCurrentAuthentication() {
        SecurityContext context = SecurityContextHolder.getContext();
        return context != null ? context.getAuthentication() : null;
    }

    /**
     * Checks if the current user is authenticated.
     * @return true if authenticated, false otherwise
     */
    public static boolean isAuthenticated() {
        Authentication authentication = getCurrentAuthentication();
        return authentication != null && 
               authentication.isAuthenticated() && 
               !"anonymousUser".equals(authentication.getPrincipal());
    }

    /**
     * Gets the current user's email (username).
     * @return the user's email, or null if not authenticated
     */
    public static String getCurrentUserEmail() {
        Authentication authentication = getCurrentAuthentication();
        return authentication != null ? authentication.getName() : null;
    }

    /**
     * Checks if the current user has a specific authority.
     * @param authority the authority to check
     * @return true if the user has the authority, false otherwise
     */
    public static boolean hasAuthority(String authority) {
        Authentication authentication = getCurrentAuthentication();
        if (authentication != null && authentication.getAuthorities() != null) {
            return authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(auth -> auth.equals(authority));
        }
        return false;
    }
} 