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
import java.time.LocalDateTime;
import java.time.ZoneOffset;

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

    @Value("${spring.application.security.enable-2fa}")
    private boolean enable2fa;

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
        // Check if account is locked
        var user = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (user != null && user.getAccountLockedUntil() != null && user.getAccountLockedUntil() > System.currentTimeMillis()) {
            long remainingTime = (user.getAccountLockedUntil() - System.currentTimeMillis()) / 1000;
            throw new org.springframework.security.authentication.LockedException(
                "Account is locked. Please try again in " + remainingTime + " seconds.");
        }

        try {
            // Authenticate the user
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            
            log.info("User authenticated successfully: {} with authorities: {}", 
                    request.getEmail(), 
                    authentication.getAuthorities());
            
            // Reset failed login attempts on successful authentication
            if (user != null) {
                user.setFailedLoginAttempts(0);
                user.setAccountLockedUntil(null);
                userRepository.save(user);
            }

            // Check if 2FA is globally enabled and user has 2FA enabled
            if (enable2fa && user.isTwoFactorEnabled()) {
                // Generate 2FA code and send it (in a real app, this would be sent via email/SMS)
                String twoFactorCode = generateTwoFactorCode();
                user.setTwoFactorCode(twoFactorCode);
                user.setTwoFactorCodeExpiry(System.currentTimeMillis() + (5 * 60 * 1000)); // 5 minutes
                userRepository.save(user);
                
                log.info("2FA code generated for user: {}", request.getEmail());
                
                return AuthenticationResponse.builder()
                        .userEmail(user.getEmail())
                        .userRole(user.getRole().name())
                        .message("2FA code sent. Please verify to complete login.")
                        .twoFactorRequired(true)
                        .build();
            } else {
                // 2FA not required - proceed with normal login
                var jwtToken = jwtService.generateToken(user);
                var refreshToken = jwtService.generateRefreshToken(user);
                saveUserToken(user, jwtToken);
                
                return AuthenticationResponse.builder()
                        .accessToken(jwtToken)
                        .refreshToken(refreshToken)
                        .userEmail(user.getEmail())
                        .userRole(user.getRole().name())
                        .message("Login successful")
                        .twoFactorRequired(false)
                        .build();
            }
        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            // Handle failed login attempt
            if (user != null) {
                handleFailedLoginAttempt(user);
            }
            throw e;
        }
    }

    public AuthenticationResponse verify2faCode(String email, String code) {
        // Check if 2FA is globally enabled
        if (!enable2fa) {
            throw new IllegalStateException("2FA is not enabled for this application");
        }
        
        var user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Invalid email or code"));
        
        // If 2FA is not enabled for this user, reject
        if (!user.isTwoFactorEnabled()) {
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
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("2FA verification successful. Login complete.")
                .twoFactorRequired(false)
                .build();
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
                    var accessToken = jwtService.generateToken(user);
                    revokeAllUserTokens(user);
                    saveUserToken(user, accessToken);
                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
        }
    }

    private String generateTwoFactorCode() {
        SecureRandom random = new SecureRandom();
        int code = 100000 + random.nextInt(900000); // 6-digit code
        return String.valueOf(code);
    }

    public void enable2faForUser(String userEmail) {
        var user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        if (!enable2fa) {
            throw new IllegalStateException("2FA is not enabled for this application");
        }
        
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        log.info("2FA enabled for user: {}", userEmail);
    }

    public void disable2faForUser(String userEmail) {
        var user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        user.setTwoFactorEnabled(false);
        user.setTwoFactorCode(null);
        user.setTwoFactorCodeExpiry(null);
        userRepository.save(user);
        log.info("2FA disabled for user: {}", userEmail);
    }

    public boolean is2faEnabledForUser(String userEmail) {
        var user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return user.isTwoFactorEnabled();
    }

    public boolean isGlobal2faEnabled() {
        return enable2fa;
    }

    public void resend2faCode(String email) {
        // Check if 2FA is globally enabled
        if (!enable2fa) {
            throw new IllegalStateException("2FA is not enabled for this application");
        }
        
        var user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Check if user has 2FA enabled
        if (!user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is not enabled for this user");
        }
        
        // Generate new 2FA code
        String twoFactorCode = generateTwoFactorCode();
        user.setTwoFactorCode(twoFactorCode);
        user.setTwoFactorCodeExpiry(System.currentTimeMillis() + (5 * 60 * 1000)); // 5 minutes
        userRepository.save(user);
        
        log.info("2FA code resent for user: {}", email);
    }

    private void handleFailedLoginAttempt(User user) {
        int maxAttempts = 5; // Configurable
        long lockoutDuration = 15 * 60 * 1000; // 15 minutes in milliseconds
        
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        
        if (user.getFailedLoginAttempts() >= maxAttempts) {
            user.setAccountLockedUntil(System.currentTimeMillis() + lockoutDuration);
            log.warn("Account locked for user: {} due to {} failed login attempts", 
                    user.getEmail(), user.getFailedLoginAttempts());
        }
        
        userRepository.save(user);
    }
}
