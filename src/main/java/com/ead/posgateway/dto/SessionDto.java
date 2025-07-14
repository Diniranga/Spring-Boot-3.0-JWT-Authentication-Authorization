package com.ead.posgateway.dto;

import com.ead.posgateway.session.UserSession;
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
public class SessionDto {

    private String sessionId;
    private String sessionType;
    private String loginMethod;
    private String ipAddress;
    private String userAgent;
    private String deviceFingerprint;
    private String deviceInfo;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
    private LocalDateTime expiresAt;
    private boolean isValid;
    private boolean isExpired;
    private boolean isRevoked;
    private String revokedReason;
    private LocalDateTime revokedAt;
    private String revokedBy;

    public static SessionDto fromUserSession(UserSession session) {
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