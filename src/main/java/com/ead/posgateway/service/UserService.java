package com.ead.posgateway.service;

import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.dto.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        User savedUser = userRepository.save(user);
        log.info("User created: {}", savedUser.getEmail());
        return savedUser;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public UserDto getUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(user.getRole())
                .lastLoginTime(user.getLastLoginTime())
                .lastLoginIp(user.getLastLoginIp())
                .accountLocked(user.isAccountLocked())
                .activeSessions(user.getActiveSessions())
                .maxConcurrentSessions(user.getMaxConcurrentSessions())
                .build();
    }

    public void updateLastLogin(User user, String ipAddress) {
        user.setLastLoginTime(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);
    }

    public void changePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);
        log.info("Password changed for user: {}", user.getEmail());
    }

    public void resetFailedAttempts(User user) {
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setLockTime(null);
        userRepository.save(user);
    }

    public void incrementFailedAttempts(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        userRepository.save(user);
    }

    public void lockAccount(User user) {
        user.setAccountLocked(true);
        user.setLockTime(LocalDateTime.now());
        userRepository.save(user);
        log.warn("Account locked for user: {}", user.getEmail());
    }
} 