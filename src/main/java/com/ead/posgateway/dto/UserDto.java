package com.ead.posgateway.dto;

import com.ead.posgateway.User.Role;
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
public class UserDto {

    private Integer id;
    private String firstName;
    private String lastName;
    private String email;
    private Role role;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginTime;
    private String lastLoginIp;
    private boolean accountLocked;
    private int activeSessions;
    private int maxConcurrentSessions;
    
    // Security-sensitive fields are excluded
    // password, failedLoginAttempts, lockTime, etc.
} 