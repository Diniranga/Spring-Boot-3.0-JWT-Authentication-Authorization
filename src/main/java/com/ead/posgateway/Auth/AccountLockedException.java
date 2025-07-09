package com.ead.posgateway.Auth;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for account lockout scenarios
 */
public class AccountLockedException extends AuthenticationException {
    
    private final long remainingMinutes;
    private final boolean isPermanentlyLocked;
    
    public AccountLockedException(String message) {
        super(message);
        this.remainingMinutes = 0;
        this.isPermanentlyLocked = true;
    }
    
    public AccountLockedException(String message, long remainingMinutes) {
        super(message);
        this.remainingMinutes = remainingMinutes;
        this.isPermanentlyLocked = false;
    }
    
    public long getRemainingMinutes() {
        return remainingMinutes;
    }
    
    public boolean isPermanentlyLocked() {
        return isPermanentlyLocked;
    }
} 