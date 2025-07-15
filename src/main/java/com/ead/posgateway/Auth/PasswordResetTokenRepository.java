package com.ead.posgateway.Auth;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    List<PasswordResetToken> findByUserId(Long userId);
    PasswordResetToken findByToken(String token);
} 