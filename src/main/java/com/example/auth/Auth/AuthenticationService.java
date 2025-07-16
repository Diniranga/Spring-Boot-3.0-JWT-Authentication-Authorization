/*
 * AuthenticationService.java
 *
 * Service for handling user authentication, registration, password reset, and related security logic.
 * Includes logic for login, registration, token validation, password reset, and session management.
 */
package com.example.auth.Auth;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.auth.User.User;
import com.example.auth.dto.UserDto;
import com.example.auth.session.SessionService;
import com.example.auth.session.UserSession;
import com.example.auth.service.TokenService;
import com.example.auth.service.UserService;
import com.example.auth.Auth.SecurityMonitoringService;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service for authentication, registration, password reset, and session management.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthenticationService {
    private static final int DEFAULT_MAX_CONCURRENT_SESSIONS = 3;

    private final UserService userService;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecurityMonitoringService securityMonitoringService;

    @Value("${spring.application.security.lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;
    @Value("${spring.application.security.lockout.cooldown-minutes:15}")
    private int cooldownMinutes;
    @Value("${spring.application.security.jwt.password-reset.token-expiration-minutes:30}")
    private int passwordResetTokenExpirationMinutes;
    @Value("${spring.application.frontend-base-url}")
    private String frontendBaseUrl;
    @Value("${spring.application.security.jwt.password-reset.rate-limit-minutes}")
    private int passwordResetRateLimitMinutes;

    /**
     * Register a new user and create an initial session and tokens.
     * @param request registration request
     * @param httpRequest HTTP request
     * @return authentication response
     */
    public AuthenticationResponse register(@Valid RegisterRequest request, HttpServletRequest httpRequest) {
        if (userService.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("User with email " + request.getEmail() + " already exists");
        }
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(request.getPassword())
                .role(request.getRole())
                .failedLoginAttempts(0)
                .accountLocked(false)
                .lockTime(null)
                .activeSessions(0)
                .maxConcurrentSessions(DEFAULT_MAX_CONCURRENT_SESSIONS)
                .lastPasswordChange(LocalDateTime.now())
                .build();
        User savedUser = userService.createUser(user);
        SessionService.SessionCreationResult sessionResult = sessionService.createSession(savedUser, httpRequest, UserSession.SessionType.WEB);
        UserSession userSession = sessionResult.getSession();
        if (sessionResult.isWasReused()) {
            tokenService.revokeTokensBySessionId(userSession.getSessionId());
            log.info("Revoked old tokens for reused session during registration: {}", userSession.getSessionId());
        }
        String jwtToken = tokenService.generateAccessToken(savedUser);
        String refreshToken = tokenService.generateRefreshToken(savedUser);
        tokenService.createToken(savedUser, jwtToken, refreshToken, userSession.getSessionId());
        log.info("User registered successfully: {} with {} session", savedUser.getEmail(), sessionResult.isWasReused() ? "reused" : "new");
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(savedUser.getEmail())
                .userRole(savedUser.getRole().name())
                .message("Registration successful")
                .build();
    }

    /**
     * Authenticate a user and create a session and tokens.
     * @param request authentication request
     * @param httpRequest HTTP request
     * @return authentication response
     */
    public AuthenticationResponse authenticate(@Valid AuthenticationRequest request, HttpServletRequest httpRequest) {
        Optional<User> userOpt = userService.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            throw new BadCredentialsException("Invalid email or password");
        }
        User user = userOpt.get();

        // CHECK LOCK FIRST!
        if (user.isAccountLocked()) {
            if (user.getLockTime() != null) {
                long minutesSinceLock = java.time.temporal.ChronoUnit.MINUTES.between(user.getLockTime(), LocalDateTime.now());
                if (minutesSinceLock >= cooldownMinutes) {
                    userService.resetFailedAttempts(user);
                    securityMonitoringService.trackAccountUnlocked(user.getEmail(), getClientIpAddress(httpRequest), "Cooldown expired");
                } else {
                    long remainingMinutes = cooldownMinutes - minutesSinceLock;
                    throw new AccountLockedException("Account is locked due to too many failed login attempts. Try again in " + remainingMinutes + " minutes.", remainingMinutes);
                }
            } else {
                throw new AccountLockedException("Account is locked. Contact administrator for assistance.");
            }
        }

        // Only now authenticate
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            log.info("User authenticated successfully: {}", request.getEmail());
            userService.resetFailedAttempts(user);
            userService.updateLastLogin(user, getClientIpAddress(httpRequest));
        } catch (BadCredentialsException ex) {
            userService.incrementFailedAttempts(user);
            int attempts = user.getFailedLoginAttempts();
            boolean willLock = attempts >= maxFailedAttempts;
            boolean isLocked = user.isAccountLocked() || willLock;
            securityMonitoringService.trackFailedLoginWithLockCheck(
                user.getEmail(),
                getClientIpAddress(httpRequest),
                attempts,
                maxFailedAttempts,
                willLock
            );
            if (willLock) {
                userService.lockAccount(user);
                throw new AccountLockedException("Account is locked due to too many failed login attempts. Try again in " + cooldownMinutes + " minutes.", cooldownMinutes);
            } else {
                int remainingAttempts = maxFailedAttempts - attempts;
                throw new BadCredentialsException("Invalid email or password. Attempts left: " + remainingAttempts);
            }
        }
        SessionService.SessionCreationResult sessionResult = sessionService.createSession(user, httpRequest, UserSession.SessionType.WEB);
        UserSession userSession = sessionResult.getSession();
        if (sessionResult.isWasReused()) {
            tokenService.revokeTokensBySessionId(userSession.getSessionId());
            log.info("Revoked old tokens for reused session: {}", userSession.getSessionId());
        }
        String jwtToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        tokenService.createToken(user, jwtToken, refreshToken, userSession.getSessionId());
        log.info("User logged in successfully: {} with {} session", user.getEmail(), sessionResult.isWasReused() ? "reused" : "new");
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("Login successful")
                .build();
    }

    /**
     * Validate a JWT token and session for a user.
     * @param token JWT token
     * @param userEmail user email
     * @param request HTTP request
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token, String userEmail, HttpServletRequest request) {
        if (!sessionService.validateSessionByToken(token, request)) {
            return false;
        }
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        return tokenService.isTokenValid(token, userDetails);
    }

    /**
     * Refresh JWT tokens using a valid refresh token.
     * @param request HTTP request
     * @param response HTTP response
     * @throws IOException if writing to response fails
     */
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String oldRefreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(401);
            response.getWriter().write("{\"error\":\"No refresh token provided\"}");
            return;
        }
        oldRefreshToken = authHeader.substring(7);
        userEmail = tokenService.extractUserEmail(oldRefreshToken);
        if (userEmail != null) {
            Optional<User> userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                if (tokenService.isTokenValid(oldRefreshToken, user) && sessionService.validateSession(oldRefreshToken, request)) {
                    sessionService.invalidateSessionByToken(oldRefreshToken, "Token refresh");
                    String accessToken = tokenService.generateAccessToken(user);
                    String newRefreshToken = tokenService.generateRefreshToken(user);
                    SessionService.SessionCreationResult sessionResult = sessionService.createSession(user, request, UserSession.SessionType.WEB);
                    UserSession userSession = sessionResult.getSession();
                    tokenService.createToken(user, accessToken, newRefreshToken, userSession.getSessionId());
                    AuthenticationResponse authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                    log.info("Token refreshed for user: {}", userEmail);
                } else {
                    response.setStatus(401);
                    response.getWriter().write("{\"error\":\"Invalid refresh token\"}");
                }
            } else {
                response.setStatus(401);
                response.getWriter().write("{\"error\":\"User not found\"}");
            }
        } else {
            response.setStatus(401);
            response.getWriter().write("{\"error\":\"Invalid refresh token\"}");
        }
    }

    /**
     * Change the password for an authenticated user.
     * @param userEmail user email
     * @param oldPassword old password
     * @param newPassword new password
     * @return true if changed, false if old password is incorrect
     */
    public boolean changePassword(String userEmail, String oldPassword, String newPassword) {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!userService.matchesPassword(user, oldPassword)) {
            return false;
        }
        userService.changePassword(user, newPassword);
        sessionService.invalidateAllSessions(user, "Password change");
        tokenService.revokeAllUserTokens(user);
        log.info("Password changed for user: {}. All sessions invalidated.", userEmail);
        return true;
    }

    /**
     * Get account status for a user by email.
     * @param email user email
     * @return user DTO
     */
    public UserDto getAccountStatus(String email) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("Account not found");
        }
        return userService.getUserDto(userOpt.get());
    }

    /**
     * Request a password reset (generates and logs a reset link).
     * @param email user email
     */
    public void requestPasswordReset(String email) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            log.info("Password reset requested for non-existent email: {}", email);
            return;
        }
        User user = userOpt.get();
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(passwordResetRateLimitMinutes);
        List<PasswordResetToken> tokens = passwordResetTokenRepository.findByUserId(Long.valueOf(user.getId()));
        long recentRequests = tokens.stream()
            .filter(t -> t.getCreatedAt() != null && t.getCreatedAt().isAfter(windowStart))
            .count();
        if (recentRequests >= 3) {
            throw new IllegalStateException("Too many password reset requests. Please wait " + passwordResetRateLimitMinutes + " minutes before trying again.");
        }
        for (PasswordResetToken token : tokens) {
            if (!token.isRevoked() && (!token.isUsed() || token.getExpiryDate().isBefore(LocalDateTime.now()))) {
                token.setRevoked(true);
            }
        }
        passwordResetTokenRepository.saveAll(tokens);
        String token = UUID.randomUUID().toString();
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(passwordResetTokenExpirationMinutes);
        PasswordResetToken resetToken = new PasswordResetToken(token, user, expiry);
        passwordResetTokenRepository.save(resetToken);
        String resetLink = String.format("%s/auth/reset-password?token=%s", frontendBaseUrl, token);
        log.info("Password reset link for {}: {} (expires in {} minutes)", email, resetLink, passwordResetTokenExpirationMinutes);
    }

    /**
     * Reset the user's password using a valid reset token.
     * @param token reset token
     * @param newPassword new password
     */
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token);
        if (resetToken == null || resetToken.isUsed() || resetToken.isRevoked() || resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            if (resetToken != null) resetToken.setRevoked(true);
            throw new IllegalArgumentException("Invalid or expired password reset token");
        }
        User user = resetToken.getUser();
        userService.changePassword(user, newPassword);
        resetToken.setUsed(true);
        resetToken.setRevoked(true);
        passwordResetTokenRepository.save(resetToken);
        sessionService.invalidateAllSessions(user, "Password reset");
        tokenService.revokeAllUserTokens(user);
        log.info("Password reset for user: {}. All sessions invalidated.", user.getEmail());
    }

    /**
     * Extract client IP address from request headers.
     * @param request HTTP request
     * @return client IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
