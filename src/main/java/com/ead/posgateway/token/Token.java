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
    private boolean expired;
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    // Token fingerprinting and session tracking
    private String deviceFingerprint;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
    private String sessionId;
    private boolean isActive;

    // Helper methods for backward compatibility
    public String getToken() {
        return accessToken;
    }

    public void setToken(String token) {
        this.accessToken = token;
    }

    public boolean isAccessTokenValid() {
        return accessToken != null && !expired && !revoked && isActive;
    }

    public boolean isRefreshTokenValid() {
        return refreshToken != null && !expired && !revoked && isActive;
    }
}
