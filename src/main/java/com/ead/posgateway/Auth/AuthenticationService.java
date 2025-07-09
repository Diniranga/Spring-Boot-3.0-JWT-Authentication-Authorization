package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.JwtService;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.token.Token;
import com.ead.posgateway.token.TokenRepository;
import com.ead.posgateway.token.TokenType;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Value("${security.enable-2fa:true}")
    private boolean enable2fa;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    private static final long TWO_FA_CODE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
    private static final SecureRandom random = new SecureRandom();

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(savedUser.getEmail())
                .userRole(savedUser.getRole().name())
                .message("Registration successful")
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var userOpt = userRepository.findByEmailIgnoreCase(request.getEmail());
        if (userOpt.isEmpty()) {
            // Simulate authentication failure for non-existent user
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid credentials");
        }
        var user = userOpt.get();
        // Check if account is locked
        if (user.getAccountLockedUntil() != null && user.getAccountLockedUntil() > System.currentTimeMillis()) {
            long minutesLeft = (user.getAccountLockedUntil() - System.currentTimeMillis()) / 60000 + 1;
            throw new org.springframework.security.authentication.LockedException(
                "Account is locked. Try again in " + minutesLeft + " minutes.");
        }
        try {
            // Authenticate the user
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            // Reset failed attempts on success
            user.setFailedLoginAttempts(0);
            user.setAccountLockedUntil(null);
            userRepository.save(user);

            // 2FA logic
            if (enable2fa && user.isTwoFactorEnabled()) {
                String code = generate2faCode();
                user.setTwoFactorCode(code);
                user.setTwoFactorCodeExpiry(System.currentTimeMillis() + TWO_FA_CODE_EXPIRY_MS);
                userRepository.save(user);
                send2faCode(user.getEmail(), code);
                return AuthenticationResponse.builder()
                        .userEmail(user.getEmail())
                        .userRole(user.getRole().name())
                        .message("2FA code sent to your email. Please verify to complete login.")
                        .twoFactorRequired(true)
                        .build();
            }

            log.info("User authenticated successfully: {} with authorities: {}", 
                    request.getEmail(), 
                    authentication.getAuthorities());
            var jwtToken = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            saveUserToken(user,jwtToken);
            saveRefreshToken(user, refreshToken);
            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken)
                    .userEmail(user.getEmail())
                    .userRole(user.getRole().name())
                    .message("Login successful")
                    .twoFactorRequired(false)
                    .build();
        } catch (org.springframework.security.core.AuthenticationException ex) {
            // Increment failed attempts
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                user.setAccountLockedUntil(System.currentTimeMillis() + LOCKOUT_DURATION_MS);
            }
            userRepository.save(user);
            throw ex;
        }
    }

    public AuthenticationResponse verify2faCode(String email, String code) {
        var user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Invalid email or code"));
        if (!enable2fa || !user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is not enabled for this user");
        }
        if (user.getTwoFactorCode() == null || user.getTwoFactorCodeExpiry() == null
                || user.getTwoFactorCodeExpiry() < System.currentTimeMillis()) {
            throw new org.springframework.security.authentication.BadCredentialsException("2FA code expired or not set");
        }
        if (!user.getTwoFactorCode().equals(code)) {
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid 2FA code");
        }
        // Clear 2FA code after successful verification
        user.setTwoFactorCode(null);
        user.setTwoFactorCodeExpiry(null);
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(user, jwtToken);
        saveRefreshToken(user, refreshToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("2FA verification successful. Login complete.")
                .twoFactorRequired(false)
                .build();
    }

    private String generate2faCode() {
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }

    private void send2faCode(String email, String code) {
        // Dummy email sender: log the code
        log.info("2FA code for {}: {}", email, code);
        // In production, integrate with an email service provider
    }

    private void saveUserToken(User user, String jwtToken) {
        revokeAllUserTokens(user);
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if(validTokens.isEmpty())
            return;
        validTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validTokens);
    }

    private void saveRefreshToken(User user, String refreshToken) {
        revokeAllUserRefreshTokens(user);
        var token = Token.builder()
                .user(user)
                .token(refreshToken)
                .tokenType(TokenType.REFRESH)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserRefreshTokens(User user) {
        var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        validTokens.stream()
            .filter(t -> t.getTokenType() == TokenType.REFRESH && !t.isExpired() && !t.isRevoked())
            .forEach(t -> {
                t.setExpired(true);
                t.setRevoked(true);
            });
        tokenRepository.saveAll(validTokens);
    }

    public boolean validateToken(String token, String userEmail) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        return jwtService.isTokenValid(token,userDetails);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        } else {
            refreshToken = authHeader.substring(7);
            userEmail = jwtService.extractUserEmail(refreshToken);
            if (userEmail != null) {
                var user = this.userRepository.findByEmail(userEmail).orElseThrow();
                if (jwtService.isTokenValid(refreshToken, user)) {
                    // Check if refresh token is valid and not revoked
                    var storedToken = tokenRepository.findByToken(refreshToken)
                        .filter(t -> t.getTokenType() == TokenType.REFRESH && !t.isExpired() && !t.isRevoked());
                    if (storedToken.isEmpty()) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Refresh token is invalid or revoked");
                        return;
                    }
                    // Issue new access and refresh tokens, revoke old refresh tokens
                    var accessToken = jwtService.generateToken(user);
                    var newRefreshToken = jwtService.generateRefreshToken(user);
                    revokeAllUserTokens(user);
                    saveUserToken(user, accessToken);
                    saveRefreshToken(user, newRefreshToken);
                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
        }
    }
}
