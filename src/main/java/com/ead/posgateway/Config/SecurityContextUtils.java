package com.ead.posgateway.Config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class SecurityContextUtils {

    /**
     * Best Practice: Set security context with proper error handling
     */
    public static void setSecurityContext(UserDetails userDetails, String credentials, HttpServletRequest request) {
        try {
            // Create authentication token
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    credentials,
                    userDetails.getAuthorities()
            );
            
            // Set authentication details for audit
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            
            // Set security context
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
            
        } catch (Exception e) {
            // Clear context on error
            SecurityContextHolder.clearContext();
            throw new RuntimeException("Failed to set security context", e);
        }
    }

    /**
     * Best Practice: Clear security context
     */
    public static void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Best Practice: Get current authentication safely
     */
    public static Authentication getCurrentAuthentication() {
        SecurityContext context = SecurityContextHolder.getContext();
        return context != null ? context.getAuthentication() : null;
    }

    /**
     * Best Practice: Check if user is authenticated
     */
    public static boolean isAuthenticated() {
        Authentication authentication = getCurrentAuthentication();
        return authentication != null && 
               authentication.isAuthenticated() && 
               !"anonymousUser".equals(authentication.getPrincipal());
    }

    /**
     * Best Practice: Get current user email safely
     */
    public static String getCurrentUserEmail() {
        Authentication authentication = getCurrentAuthentication();
        return authentication != null ? authentication.getName() : null;
    }

    /**
     * Best Practice: Check if current user has specific authority
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