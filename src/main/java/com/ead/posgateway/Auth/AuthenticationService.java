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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

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
    private final SessionManagementService sessionManagementService;

    @Value("${spring.application.security.lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;
    @Value("${spring.application.security.lockout.cooldown-minutes:15}")
    private int cooldownMinutes;

    public AuthenticationResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .failedLoginAttempts(0)
                .accountLocked(false)
                .lockTime(null)
                .activeSessions(0)
                .maxConcurrentSessions(3)
                .lastPasswordChange(LocalDateTime.now())
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        // Create single session with both tokens
        sessionManagementService.createSession(savedUser, jwtToken, refreshToken, httpRequest);
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(savedUser.getEmail())
                .userRole(savedUser.getRole().name())
                .message("Registration successful")
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletRequest httpRequest) {
        var userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            throw new BadCredentialsException("Invalid email or password");
        }
        var user = userOpt.get();

        // Check if account is locked and if cooldown has expired
        if (user.isAccountLocked()) {
            if (user.getLockTime() != null) {
                long minutesSinceLock = ChronoUnit.MINUTES.between(user.getLockTime(), LocalDateTime.now());
                if (minutesSinceLock >= cooldownMinutes) {
                    // Unlock account
                    user.setAccountLocked(false);
                    user.setFailedLoginAttempts(0);
                    user.setLockTime(null);
                    userRepository.save(user);
                } else {
                    long remainingMinutes = cooldownMinutes - minutesSinceLock;
                    throw new AccountLockedException("Account is locked due to too many failed login attempts. Try again in " + remainingMinutes + " minutes.", remainingMinutes);
                }
            } else {
                throw new AccountLockedException("Account is locked. Contact administrator for assistance.");
            }
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
            // Reset failed attempts on success
            user.setFailedLoginAttempts(0);
            user.setAccountLocked(false);
            user.setLockTime(null);
            userRepository.save(user);
        } catch (BadCredentialsException ex) {
            // Increment failed attempts
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= maxFailedAttempts) {
                user.setAccountLocked(true);
                user.setLockTime(LocalDateTime.now());
            }
            userRepository.save(user);
            if (user.isAccountLocked()) {
                throw new AccountLockedException("Account is locked due to too many failed login attempts. Try again in " + cooldownMinutes + " minutes.", cooldownMinutes);
            } else {
                throw new BadCredentialsException("Invalid email or password. Attempts left: " + (maxFailedAttempts - attempts));
            }
        }

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        
        // Create single session with both tokens
        sessionManagementService.createSession(user, jwtToken, refreshToken, httpRequest);
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("Login successful")
                .build();
    }

    public boolean validateToken(String token, String userEmail, HttpServletRequest request) {
        // First validate session
        if (!sessionManagementService.validateSession(token, request)) {
            return false;
        }
        
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        return jwtService.isTokenValid(token, userDetails);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String oldRefreshToken;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        } else {
            oldRefreshToken = authHeader.substring(7);
            userEmail = jwtService.extractUserEmail(oldRefreshToken);
            if (userEmail != null) {
                var user = this.userRepository.findByEmail(userEmail).orElseThrow();
                // Validate old refresh token
                if (jwtService.isTokenValid(oldRefreshToken, user) && 
                    sessionManagementService.validateSession(oldRefreshToken, request)) {
                    // Revoke the old session
                    sessionManagementService.invalidateSession(oldRefreshToken);
                    // Issue new tokens
                    var accessToken = jwtService.generateToken(user);
                    var newRefreshToken = jwtService.generateRefreshToken(user);
                    
                    // Create new session with both tokens
                    sessionManagementService.createSession(user, accessToken, newRefreshToken, request);
                    
                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
        }
    }

    /**
     * Change user password and invalidate all sessions
     */
    public void changePassword(String userEmail, String newPassword) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);
        
        // Invalidate all sessions for security
        sessionManagementService.invalidateAllSessions(user);
        
        log.info("Password changed for user: {}. All sessions invalidated.", userEmail);
    }

    /**
     * Get user repository for account status checks
     */
    public UserRepository getUserRepository() {
        return userRepository;
    }
}
