/*
 * PasswordResetRequest.java
 *
 * DTO for password reset (forgot password) requests. Contains the user's email.
 */
package com.ead.posgateway.Auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for initiating a password reset (forgot password).
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetRequest {
    /** User's email address. */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    private String email;
} 