/*
 * PasswordResetSubmitRequest.java
 *
 * DTO for submitting a new password using a reset token.
 */
package com.example.auth.Auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for submitting a new password with a reset token.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetSubmitRequest {
    /** Password reset token. */
    @NotBlank(message = "Token is required")
    private String token;

    /** New password. */
    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String newPassword;
} 