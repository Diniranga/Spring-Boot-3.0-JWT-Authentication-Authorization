/*
 * PasswordValidator.java
 *
 * Component for validating password strength and complexity requirements.
 */
package com.ead.posgateway.Auth;

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import org.springframework.stereotype.Component;

/**
 * Validates password strength and returns validation results.
 */
@Component
public class PasswordValidator {
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;

    /**
     * Validate password strength and return result.
     * @param password password to validate
     * @return validation result
     */
    public PasswordValidationResult validatePassword(String password) {
        List<String> errors = new ArrayList<>();
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            errors.add("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }
        if (password != null) {
            if (!password.matches(".*[A-Z].*")) {
                errors.add("Password must contain at least one uppercase letter");
            }
            if (!password.matches(".*[a-z].*")) {
                errors.add("Password must contain at least one lowercase letter");
            }
            if (!password.matches(".*\\d.*")) {
                errors.add("Password must contain at least one digit");
            }
            if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) {
                errors.add("Password must contain at least one special character");
            }
            if (password.length() > MAX_PASSWORD_LENGTH) {
                errors.add("Password must not exceed " + MAX_PASSWORD_LENGTH + " characters");
            }
        }
        return new PasswordValidationResult(errors.isEmpty(), errors);
    }

    /**
     * Result of password validation.
     */
    @Getter
    public static class PasswordValidationResult {
        private final boolean valid;
        private final List<String> errors;
        public PasswordValidationResult(boolean valid, List<String> errors) {
            this.valid = valid;
            this.errors = List.copyOf(errors);
        }
    }
} 