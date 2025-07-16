package com.example.auth.Auth;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType; // e.g., FAILED_LOGIN, SUSPICIOUS_ACTIVITY, SESSION_ANOMALY, etc.

    @Column(nullable = false)
    private String email; // user email (if available)

    @Column(nullable = true)
    private String ipAddress;

    @Column(nullable = true)
    private String details; // JSON or string with extra info

    @Column(nullable = false)
    private LocalDateTime eventTime;
} 