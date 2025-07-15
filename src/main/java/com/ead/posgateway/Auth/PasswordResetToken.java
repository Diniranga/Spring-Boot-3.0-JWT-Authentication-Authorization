/*
 * PasswordResetToken.java
 *
 * Entity representing a password reset token for a user.
 * Used for password reset flows and token validation.
 */
package com.ead.posgateway.Auth;

import java.time.LocalDateTime;

import com.ead.posgateway.User.User;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * JPA entity for storing password reset tokens and their status.
 */
@Entity
@Data
@NoArgsConstructor
public class PasswordResetToken {
    /** Token ID. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Unique token string. */
    @Column(nullable = false, unique = true)
    private String token;

    /** Associated user. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** Expiry date/time. */
    @Column(nullable = false)
    private LocalDateTime expiryDate;

    /** Whether the token has been used. */
    @Column(nullable = false)
    private boolean used = false;

    /** Whether the token has been revoked. */
    @Column(nullable = false)
    private boolean isRevoked = false;

    /** Token creation date/time. */
    @Column(nullable = false)
    private LocalDateTime createdAt;

    public PasswordResetToken(String token, User user, LocalDateTime expiryDate) {
        this.token = token;
        this.user = user;
        this.expiryDate = expiryDate;
        this.createdAt = LocalDateTime.now();
        this.used = false;
    }
} 