package com.ead.posgateway.Auth;

import com.ead.posgateway.User.User;
import com.ead.posgateway.dto.UserDto;
import com.ead.posgateway.session.SessionService;
import com.ead.posgateway.session.UserSession;
import com.ead.posgateway.service.TokenService;
import com.ead.posgateway.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthenticationService {

    private final UserService userService;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    @Value("${spring.application.security.lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;
    
    @Value("${spring.application.security.lockout.cooldown-minutes:15}")
    private int cooldownMinutes;

    public AuthenticationResponse register(@Valid RegisterRequest request, HttpServletRequest httpRequest) {
        // Check if user already exists
        if (userService.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("User with email " + request.getEmail() + " already exists");
        }

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(request.getPassword()) // Will be encoded in UserService
                .role(request.getRole())
                .failedLoginAttempts(0)
                .accountLocked(false)
                .lockTime(null)
                .activeSessions(0)
                .maxConcurrentSessions(3)
                .lastPasswordChange(LocalDateTime.now())
                .build();

        var savedUser = userService.createUser(user);
        
        // Create session (this will reuse existing session if available)
        SessionService.SessionCreationResult sessionResult = sessionService.createSession(savedUser, httpRequest, UserSession.SessionType.WEB);
        UserSession userSession = sessionResult.getSession();
        
        if (sessionResult.isWasReused()) {
            // Revoke old tokens for this session
            tokenService.revokeTokensBySessionId(userSession.getSessionId());
            log.info("Revoked old tokens for reused session during registration: {}", userSession.getSessionId());
        }
        
        // Generate new tokens
        var jwtToken = tokenService.generateAccessToken(savedUser);
        var refreshToken = tokenService.generateRefreshToken(savedUser);
        
        // Create new token records
        tokenService.createToken(savedUser, jwtToken, refreshToken, userSession.getSessionId());
        
        log.info("User registered successfully: {} with {} session", 
                savedUser.getEmail(), sessionResult.isWasReused() ? "reused" : "new");
        
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(savedUser.getEmail())
                .userRole(savedUser.getRole().name())
                .message("Registration successful")
                .build();
    }

    public AuthenticationResponse authenticate(@Valid AuthenticationRequest request, HttpServletRequest httpRequest) {
        var userOpt = userService.findByEmail(request.getEmail());
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
                    userService.resetFailedAttempts(user);
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
            userService.resetFailedAttempts(user);
            userService.updateLastLogin(user, getClientIpAddress(httpRequest));
            
        } catch (BadCredentialsException ex) {
            // Increment failed attempts
            userService.incrementFailedAttempts(user);
            
            // Check if account should be locked
            if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
                userService.lockAccount(user);
                throw new AccountLockedException("Account is locked due to too many failed login attempts. Try again in " + cooldownMinutes + " minutes.", cooldownMinutes);
            } else {
                int remainingAttempts = maxFailedAttempts - user.getFailedLoginAttempts();
                throw new BadCredentialsException("Invalid email or password. Attempts left: " + remainingAttempts);
            }
        }

        // Create session (this will reuse existing session if available)
        SessionService.SessionCreationResult sessionResult = sessionService.createSession(user, httpRequest, UserSession.SessionType.WEB);
        UserSession userSession = sessionResult.getSession();
        
        if (sessionResult.isWasReused()) {
            // Revoke old tokens for this session
            tokenService.revokeTokensBySessionId(userSession.getSessionId());
            log.info("Revoked old tokens for reused session: {}", userSession.getSessionId());
        }
        
        // Generate new tokens
        var jwtToken = tokenService.generateAccessToken(user);
        var refreshToken = tokenService.generateRefreshToken(user);
        
        // Create new token records
        tokenService.createToken(user, jwtToken, refreshToken, userSession.getSessionId());
        
        log.info("User logged in successfully: {} with {} session", 
                user.getEmail(), sessionResult.isWasReused() ? "reused" : "new");
        
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
        if (!sessionService.validateSessionByToken(token, request)) {
            return false;
        }
        
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        return tokenService.isTokenValid(token, userDetails);
    }

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
            var userOpt = userService.findByEmail(userEmail);
            if (userOpt.isPresent()) {
                var user = userOpt.get();
                
                // Validate old refresh token
                if (tokenService.isTokenValid(oldRefreshToken, user) && 
                    sessionService.validateSession(oldRefreshToken, request)) {
                    
                    // Revoke the old session
                    sessionService.invalidateSessionByToken(oldRefreshToken, "Token refresh");
                    
                    // Issue new tokens
                    var accessToken = tokenService.generateAccessToken(user);
                    var newRefreshToken = tokenService.generateRefreshToken(user);
                    
                    // Create new session with both tokens
                    SessionService.SessionCreationResult sessionResult = sessionService.createSession(user, request, UserSession.SessionType.WEB);
                    UserSession userSession = sessionResult.getSession();
                    tokenService.createToken(user, accessToken, newRefreshToken, userSession.getSessionId());
                    
                    var authResponse = AuthenticationResponse.builder()
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

    public void changePassword(String userEmail, String newPassword) {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        userService.changePassword(user, newPassword);
        
        // Invalidate all sessions for security
        sessionService.invalidateAllSessions(user, "Password change");
        tokenService.revokeAllUserTokens(user);
        
        log.info("Password changed for user: {}. All sessions invalidated.", userEmail);
    }

    public UserDto getAccountStatus(String email) {
        var userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("Account not found");
        }
        return userService.getUserDto(userOpt.get());
    }

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
