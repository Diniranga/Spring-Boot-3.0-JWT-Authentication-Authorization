/*
 * AuthenticationRequest.java
 *
 * DTO for user login requests. Contains email and password fields.
 */
package com.example.auth.Auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for user authentication (login).
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
    /** User's email address. */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    private String email;

    /** User's password. */
    @NotBlank(message = "Password is required")
    @Size(min = 1, max = 128, message = "Password must not be empty and not exceed 128 characters")
    private String password;
}
