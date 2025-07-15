/*
 * UserDto.java
 * Data Transfer Object for user information (excluding sensitive fields).
 */
package com.ead.posgateway.dto;

import com.ead.posgateway.User.Role;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO representing user information for API responses.
 * Excludes security-sensitive fields (e.g., password).
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {

    /** User's unique identifier. */
    private Integer id;
    /** User's first name. */
    private String firstName;
    /** User's last name. */
    private String lastName;
    /** User's email address. */
    private String email;
    /** User's role. */
    private Role role;
    /** Account creation timestamp. */
    private LocalDateTime createdAt;
    /** Last login timestamp. */
    private LocalDateTime lastLoginTime;
    /** Last login IP address. */
    private String lastLoginIp;
    /** Whether the account is locked. */
    private boolean accountLocked;
    /** Number of active sessions. */
    private int activeSessions;
    /** Maximum allowed concurrent sessions. */
    private int maxConcurrentSessions;
    // Security-sensitive fields are intentionally excluded.
} 