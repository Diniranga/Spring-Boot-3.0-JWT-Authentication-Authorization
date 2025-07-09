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
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

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
        
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(user,jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("Login successful")
                .build();
    }

    public AuthenticationResponse verify2faCode(String email, String code) {
        var user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Invalid email or code"));
        // If 2FA is not enabled, reject
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
}
