/*
 * Token.java
 * Entity representing an authentication token (access/refresh) for a user session.
 */
package com.ead.posgateway.token;

import com.ead.posgateway.User.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Entity representing an authentication token (access/refresh) for a user session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

    /** Primary key. */
    @Id
    @GeneratedValue
    private Integer id;

    /** JWT access token string. */
    @Lob
    @Column(columnDefinition = "TEXT")
    private String accessToken;

    /** JWT refresh token string. */
    @Lob
    @Column(columnDefinition = "TEXT")
    private String refreshToken;

    /** Type of token (BEARER or REFRESH). */
    @Enumerated(EnumType.STRING)
    private TokenType tokenType = TokenType.BEARER;

    /** Whether the token is revoked. */
    private boolean revoked;

    /** Associated user. */
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    /** Token creation timestamp. */
    private LocalDateTime createdAt;
    /** Associated session ID. */
    private String sessionId;
    /** Whether the token is active. */
    private boolean isActive;

    /** Static reference to JwtService for token validation.
     * -- SETTER --
     *  Sets the JwtService for static token validation.
     */
    @Setter
    private static com.ead.posgateway.Config.JwtService jwtService;

    /**
     * Checks if the access token is expired.
     * @return true if expired, false otherwise
     */
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

    /**
     * Returns the access token (for backward compatibility).
     * @return access token string
     */
    public String getToken() {
        return accessToken;
    }

    /**
     * Sets the access token (for backward compatibility).
     * @param token access token string
     */
    public void setToken(String token) {
        this.accessToken = token;
    }

    /**
     * Checks if the access token is valid (not expired, not revoked, active).
     * @return true if valid, false otherwise
     */
    public boolean isAccessTokenValid() {
        return accessToken != null && !isExpired() && !revoked && isActive;
    }

    /**
     * Checks if the refresh token is valid (not expired, not revoked, active).
     * @return true if valid, false otherwise
     */
    public boolean isRefreshTokenValid() {
        return refreshToken != null && !isExpired() && !revoked && isActive;
    }

    /**
     * Sets the active status of the token.
     * @param isActive true if active, false otherwise
     */
    public void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }
}
