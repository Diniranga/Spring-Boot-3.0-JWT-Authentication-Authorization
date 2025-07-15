/*
 * ChangePasswordRequest.java
 *
 * DTO for change password requests. Contains old and new password fields.
 */
package com.example.auth.Auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for changing the user's password.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ChangePasswordRequest {
    /** User's old password. */
    @NotBlank(message = "Old password is required")
    private String oldPassword;

    /** User's new password. */
    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String newPassword;
} 