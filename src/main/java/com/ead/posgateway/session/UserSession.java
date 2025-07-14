package com.ead.posgateway.session;

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
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(unique = true, nullable = false)
    private String sessionId;

    @Column(nullable = false)
    private String deviceFingerprint;

    @Column(nullable = false)
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at", nullable = false)
    private LocalDateTime lastUsedAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    @Column(name = "is_revoked", nullable = false)
    private boolean isRevoked = false;

    @Column(name = "session_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SessionType sessionType = SessionType.WEB;

    @Column(name = "login_method")
    @Enumerated(EnumType.STRING)
    private LoginMethod loginMethod = LoginMethod.PASSWORD;

    @Column(name = "geographic_location")
    private String geographicLocation;

    @Column(name = "device_info")
    private String deviceInfo;

    @Column(name = "revoked_reason")
    private String revokedReason;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "revoked_by")
    private String revokedBy;

    // Helper methods
    public boolean isValid() {
        return isActive && !isExpired() && !isRevoked && 
               LocalDateTime.now().isBefore(expiresAt);
    }

    @Transient
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }

    public void revoke(String reason, String revokedBy) {
        this.isRevoked = true;
        this.isActive = false;
        this.revokedReason = reason;
        this.revokedBy = revokedBy;
        this.revokedAt = LocalDateTime.now();
    }

    public void updateLastUsed() {
        this.lastUsedAt = LocalDateTime.now();
    }

    public void extendSession(int additionalMinutes) {
        this.expiresAt = this.expiresAt.plusMinutes(additionalMinutes);
    }

    public void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }

    public enum SessionType {
        WEB, MOBILE, API, DESKTOP
    }

    public enum LoginMethod {
        PASSWORD, OAUTH, SSO, API_KEY
    }
} 