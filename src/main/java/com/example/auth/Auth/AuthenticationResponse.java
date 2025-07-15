/*
 * AuthenticationResponse.java
 *
 * DTO for authentication responses. Contains tokens, user info, and optional metadata.
 */
package com.example.auth.Auth;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response body for authentication endpoints (login, register, refresh).
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationResponse {
    /** Access token (JWT). */
    private String accessToken;
    /** Refresh token (JWT). */
    private String refreshToken;
    /** User's email address. */
    private String userEmail;
    /** User's role. */
    private String userRole;
    /** Optional message. */
    private String message;
    /** Token issued at time. */
    private LocalDateTime issuedAt;
    /** Token expiration time. */
    private LocalDateTime expiresAt;
    /** Token type (e.g., Bearer). */
    private String tokenType;

    public AuthenticationResponse(String accessToken, String refreshToken, String userEmail, String userRole, String message) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
        this.userRole = userRole;
        this.message = message;
        this.issuedAt = LocalDateTime.now();
        this.tokenType = "Bearer";
    }
}
