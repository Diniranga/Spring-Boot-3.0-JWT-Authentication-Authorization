package com.ead.posgateway.Auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationResponse {

    private String accessToken;
    private String refreshToken;
    private String userEmail;
    private String userRole;
    private String message;
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;
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
