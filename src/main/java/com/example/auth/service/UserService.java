/*
 * UserService.java
 * Service for managing user entities, password operations, and account status.
 */
package com.example.auth.service;

import com.example.auth.User.User;
import com.example.auth.User.UserRepository;
import com.example.auth.dto.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for managing user entities, password operations, and account status.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    /** Repository for user persistence. */
    private final UserRepository userRepository;
    /** Password encoder for hashing passwords. */
    private final PasswordEncoder passwordEncoder;

    /**
     * Creates and saves a new user with encoded password.
     * @param user User entity
     * @return Saved User entity
     */
    public User createUser(final User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        User savedUser = userRepository.save(user);
        log.info("User created: {}", savedUser.getEmail());
        return savedUser;
    }

    /**
     * Finds a user by email address.
     * @param email User email
     * @return Optional containing the User if found
     */
    public Optional<User> findByEmail(final String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Converts a User entity to a UserDto for API responses.
     * @param user User entity
     * @return UserDto instance
     */
    public UserDto getUserDto(final User user) {
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

    /**
     * Updates the last login time and IP address for a user.
     * @param user User entity
     * @param ipAddress IP address string
     */
    public void updateLastLogin(final User user, final String ipAddress) {
        user.setLastLoginTime(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);
    }

    /**
     * Changes the user's password and updates the last password change timestamp.
     * @param user User entity
     * @param newPassword New password string
     */
    public void changePassword(final User user, final String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);
        log.info("Password changed for user: {}", user.getEmail());
    }

    /**
     * Checks if the provided raw password matches the user's encoded password.
     * @param user User entity
     * @param rawPassword Raw password string
     * @return true if matches, false otherwise
     */
    public boolean matchesPassword(final User user, final String rawPassword) {
        return passwordEncoder.matches(rawPassword, user.getPassword());
    }

    /**
     * Resets failed login attempts and unlocks the user's account.
     * @param user User entity
     */
    public void resetFailedAttempts(final User user) {
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setLockTime(null);
        userRepository.save(user);
    }

    /**
     * Increments the failed login attempts counter for a user.
     * @param user User entity
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void incrementFailedAttempts(final User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        userRepository.save(user);
    }

    /**
     * Locks the user's account and sets the lock time.
     * @param user User entity
     */
    public void lockAccount(final User user) {
        user.setAccountLocked(true);
        user.setLockTime(LocalDateTime.now());
        userRepository.save(user);
        log.warn("Account locked for user: {}", user.getEmail());
    }
} 