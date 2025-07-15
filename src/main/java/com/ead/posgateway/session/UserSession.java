/*
 * UserSession.java
 * Entity representing a user session, including device, IP, and session status.
 */
package com.ead.posgateway.session;

import com.ead.posgateway.User.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity representing a user session, including device, IP, and session status.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_sessions")
public class UserSession {

    /** Primary key. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Associated user. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** Unique session identifier. */
    @Column(unique = true, nullable = false)
    private String sessionId;

    /** Device fingerprint for the session. */
    @Column(nullable = false)
    private String deviceFingerprint;

    /** IP address for the session. */
    @Column(nullable = false)
    private String ipAddress;

    /** User agent string. */
    @Column(name = "user_agent")
    private String userAgent;

    /** Session creation timestamp. */
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /** Last used timestamp. */
    @Column(name = "last_used_at", nullable = false)
    private LocalDateTime lastUsedAt;

    /** Session expiration timestamp. */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /** Whether the session is active. */
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    /** Whether the session is revoked. */
    @Column(name = "is_revoked", nullable = false)
    private boolean isRevoked = false;

    /** Session type (e.g., WEB, MOBILE). */
    @Column(name = "session_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SessionType sessionType = SessionType.WEB;

    /** Login method used for the session. */
    @Column(name = "login_method")
    @Enumerated(EnumType.STRING)
    private LoginMethod loginMethod = LoginMethod.PASSWORD;

    /** Device information. */
    @Column(name = "device_info")
    private String deviceInfo;

    /** Reason for session revocation, if any. */
    @Column(name = "revoked_reason")
    private String revokedReason;

    /** Timestamp when the session was revoked. */
    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    /** User or system that revoked the session. */
    @Column(name = "revoked_by")
    private String revokedBy;

    /**
     * Checks if the session is valid (active, not expired, not revoked).
     * @return true if valid, false otherwise
     */
    public boolean isValid() {
        return isActive && !isExpired() && !isRevoked && 
               LocalDateTime.now().isBefore(expiresAt);
    }

    /**
     * Checks if the session is expired.
     * @return true if expired, false otherwise
     */
    @Transient
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }

    /**
     * Revokes the session with a reason and revokedBy.
     * @param reason Reason for revocation
     * @param revokedBy User or system that revoked
     */
    public void revoke(String reason, String revokedBy) {
        this.isRevoked = true;
        this.isActive = false;
        this.revokedReason = reason;
        this.revokedBy = revokedBy;
        this.revokedAt = LocalDateTime.now();
    }

    /**
     * Updates the last used timestamp to now.
     */
    public void updateLastUsed() {
        this.lastUsedAt = LocalDateTime.now();
    }

    /**
     * Extends the session expiration by the given number of minutes.
     * @param additionalMinutes Minutes to add
     */
    public void extendSession(int additionalMinutes) {
        this.expiresAt = this.expiresAt.plusMinutes(additionalMinutes);
    }

    /**
     * Sets the active status of the session.
     * @param isActive true if active, false otherwise
     */
    public void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }

    /**
     * Enum for session type.
     */
    public enum SessionType {
        WEB, MOBILE, API, DESKTOP
    }

    /**
     * Enum for login method.
     */
    public enum LoginMethod {
        PASSWORD, OAUTH, SSO, API_KEY
    }
} 