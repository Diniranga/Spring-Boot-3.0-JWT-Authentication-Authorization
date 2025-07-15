/*
 * PasswordResetTokenRepository.java
 *
 * Repository interface for managing PasswordResetToken entities.
 */
package com.ead.posgateway.Auth;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

/**
 * Spring Data JPA repository for PasswordResetToken entities.
 */
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    /**
     * Find a token by its string value.
     * @param token the token string
     * @return the PasswordResetToken entity
     */
    PasswordResetToken findByToken(String token);
    /**
     * Find all tokens for a user by user ID.
     * @param userId the user ID
     * @return list of PasswordResetToken entities
     */
    List<PasswordResetToken> findByUserId(Long userId);
} 