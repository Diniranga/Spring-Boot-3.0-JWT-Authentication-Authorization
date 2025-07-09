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
        saveUserToken(savedUser, jwtToken, TokenType.BEARER);
        saveUserToken(savedUser, refreshToken, TokenType.REFRESH);
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
        saveUserToken(user, jwtToken, TokenType.BEARER);
        saveUserToken(user, refreshToken, TokenType.REFRESH);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .userEmail(user.getEmail())
                .userRole(user.getRole().name())
                .message("Login successful")
                .build();
    }

    private void saveUserToken(User user, String tokenValue, TokenType tokenType) {
        // Only revoke tokens of the same type
        revokeUserTokensByType(user, tokenType);
        var token = Token.builder()
                .user(user)
                .token(tokenValue)
                .tokenType(tokenType)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeUserTokensByType(User user, TokenType tokenType) {
        var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        validTokens.stream()
                .filter(t -> t.getTokenType() == tokenType && !t.isExpired() && !t.isRevoked())
                .forEach(t -> {
                    t.setExpired(true);
                    t.setRevoked(true);
                });
        tokenRepository.saveAll(validTokens);
    }

    private void revokeToken(String tokenValue) {
        Optional<Token> tokenOpt = tokenRepository.findByToken(tokenValue);
        tokenOpt.ifPresent(token -> {
            token.setExpired(true);
            token.setRevoked(true);
            tokenRepository.save(token);
        });
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
                if (jwtService.isTokenValid(oldRefreshToken, user)) {
                    // Revoke the old refresh token
                    revokeToken(oldRefreshToken);
                    // Issue new tokens
                    var accessToken = jwtService.generateToken(user);
                    var newRefreshToken = jwtService.generateRefreshToken(user);
                    saveUserToken(user, accessToken, TokenType.BEARER);
                    saveUserToken(user, newRefreshToken, TokenType.REFRESH);
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
