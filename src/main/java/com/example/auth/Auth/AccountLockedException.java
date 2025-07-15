/*
 * AccountLockedException.java
 *
 * Custom exception for account lockout scenarios in authentication flows.
 * Used to indicate temporary or permanent account lock status.
 */
package com.example.auth.Auth;

import org.springframework.security.core.AuthenticationException;

/**
 * Exception thrown when a user account is locked due to failed login attempts or admin action.
 */
public class AccountLockedException extends AuthenticationException {
    private final long remainingMinutes;
    private final boolean permanentlyLocked;

    /**
     * Constructor for permanent lock.
     * @param message exception message
     */
    public AccountLockedException(String message) {
        super(message);
        this.remainingMinutes = 0;
        this.permanentlyLocked = true;
    }

    /**
     * Constructor for temporary lock.
     * @param message exception message
     * @param remainingMinutes minutes until unlock
     */
    public AccountLockedException(String message, long remainingMinutes) {
        super(message);
        this.remainingMinutes = remainingMinutes;
        this.permanentlyLocked = false;
    }

    /**
     * @return minutes remaining until unlock (0 if permanent)
     */
    public long getRemainingMinutes() {
        return remainingMinutes;
    }

    /**
     * @return true if account is permanently locked
     */
    public boolean isPermanentlyLocked() {
        return permanentlyLocked;
    }
} 