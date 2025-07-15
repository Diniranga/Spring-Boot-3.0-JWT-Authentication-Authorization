/*
 * TokenValidationRequest.java
 *
 * DTO for token validation requests. Contains email and token fields.
 */
package com.ead.posgateway.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request body for validating a JWT or password reset token.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenValidationRequest {
    /** User's email address. */
    private String email;
    /** Token to validate. */
    private String token;
}
