package com.ead.posgateway.token;

import com.ead.posgateway.User.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

    @Id
    @GeneratedValue
    private Integer id;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String accessToken;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String refreshToken;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType = TokenType.BEARER;
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    // Token fingerprinting and session tracking
    private LocalDateTime createdAt;
    private String sessionId;
    private boolean isActive;

    private static com.ead.posgateway.Config.JwtService jwtService;

    public static void setJwtService(com.ead.posgateway.Config.JwtService service) {
        jwtService = service;
    }

    @Transient
    public boolean isExpired() {
        if (accessToken == null || jwtService == null) return false;
        try {
            java.util.Date exp = jwtService.extractClaim(accessToken, io.jsonwebtoken.Claims::getExpiration);
            return exp != null && exp.before(new java.util.Date());
        } catch (Exception e) {
            return false;
        }
    }

    // Helper methods for backward compatibility
    public String getToken() {
        return accessToken;
    }

    public void setToken(String token) {
        this.accessToken = token;
    }

    public boolean isAccessTokenValid() {
        return accessToken != null && !isExpired() && !revoked && isActive;
    }

    public boolean isRefreshTokenValid() {
        return refreshToken != null && !isExpired() && !revoked && isActive;
    }

    public void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }
}
