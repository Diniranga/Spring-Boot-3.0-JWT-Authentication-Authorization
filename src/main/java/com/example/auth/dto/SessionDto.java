/*
 * SessionDto.java
 * Data Transfer Object for user session information.
 */
package com.example.auth.dto;

import com.example.auth.session.UserSession;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO representing user session information for API responses.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SessionDto {

    /** Session unique identifier. */
    private String sessionId;
    /** Type of session (e.g., WEB, MOBILE). */
    private String sessionType;
    /** Login method used for the session. */
    private String loginMethod;
    /** IP address from which the session was created. */
    private String ipAddress;
    /** User agent string of the client. */
    private String userAgent;
    /** Device fingerprint for the session. */
    private String deviceFingerprint;
    /** Device information. */
    private String deviceInfo;
    /** Session creation timestamp. */
    private LocalDateTime createdAt;
    /** Last used timestamp. */
    private LocalDateTime lastUsedAt;
    /** Session expiration timestamp. */
    private LocalDateTime expiresAt;
    /** Whether the session is currently valid. */
    private boolean isValid;
    /** Whether the session is expired. */
    private boolean isExpired;
    /** Whether the session is revoked. */
    private boolean isRevoked;
    /** Reason for session revocation, if any. */
    private String revokedReason;
    /** Timestamp when the session was revoked. */
    private LocalDateTime revokedAt;
    /** User or system that revoked the session. */
    private String revokedBy;

    /**
     * Creates a SessionDto from a UserSession entity.
     * @param session UserSession entity
     * @return SessionDto instance
     */
    public static SessionDto fromUserSession(final UserSession session) {
        return SessionDto.builder()
                .sessionId(session.getSessionId())
                .sessionType(session.getSessionType().name())
                .loginMethod(session.getLoginMethod().name())
                .ipAddress(session.getIpAddress())
                .userAgent(session.getUserAgent())
                .deviceFingerprint(session.getDeviceFingerprint())
                .deviceInfo(session.getDeviceInfo())
                .createdAt(session.getCreatedAt())
                .lastUsedAt(session.getLastUsedAt())
                .expiresAt(session.getExpiresAt())
                .isValid(session.isValid())
                .isExpired(session.isExpired())
                .isRevoked(session.isRevoked())
                .revokedReason(session.getRevokedReason())
                .revokedAt(session.getRevokedAt())
                .revokedBy(session.getRevokedBy())
                .build();
    }
} 