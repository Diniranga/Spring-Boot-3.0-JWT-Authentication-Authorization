package com.ead.posgateway;

import com.ead.posgateway.Auth.AuthenticationRequest;
import com.ead.posgateway.Auth.AuthenticationResponse;
import com.ead.posgateway.Auth.AuthenticationService;
import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import com.ead.posgateway.token.TokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationService2faTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private com.ead.posgateway.Config.JwtService jwtService;

    @Mock
    private TokenRepository tokenRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    private User testUser;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1)
                .firstName("John")
                .lastName("Doe")
                .email("john@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .twoFactorEnabled(false)
                .build();

        authRequest = new AuthenticationRequest();
        authRequest.setEmail("john@example.com");
        authRequest.setPassword("password");
    }

    @Test
    void when2faDisabled_shouldLoginNormally() {
        // Given
        ReflectionTestUtils.setField(authenticationService, "enable2fa", false);
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities()));
        when(userRepository.findByEmail("john@example.com"))
                .thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(any(User.class))).thenReturn("jwt-token");
        when(jwtService.generateRefreshToken(any(User.class))).thenReturn("refresh-token");
        when(tokenRepository.findAllValidTokenByUser(any(Integer.class))).thenReturn(new ArrayList<>());

        // When
        AuthenticationResponse response = authenticationService.authenticate(authRequest);

        // Then
        assertNotNull(response);
        assertFalse(response.isTwoFactorRequired());
        assertEquals("Login successful", response.getMessage());
        assertEquals("jwt-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        
        verify(userRepository, times(1)).save(any(User.class)); // Once for resetting failed attempts
    }

    @Test
    void when2faEnabledAndUserHas2fa_shouldRequire2faCode() {
        // Given
        ReflectionTestUtils.setField(authenticationService, "enable2fa", true);
        testUser.setTwoFactorEnabled(true);
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities()));
        when(userRepository.findByEmail("john@example.com"))
                .thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        AuthenticationResponse response = authenticationService.authenticate(authRequest);

        // Then
        assertNotNull(response);
        assertTrue(response.isTwoFactorRequired());
        assertEquals("2FA code sent. Please verify to complete login.", response.getMessage());
        assertNull(response.getAccessToken());
        assertNull(response.getRefreshToken());
        
        verify(userRepository, times(2)).save(any(User.class)); // Once for resetting failed attempts, once for 2FA code
    }

    @Test
    void when2faEnabledButUserDoesNotHave2fa_shouldLoginNormally() {
        // Given
        ReflectionTestUtils.setField(authenticationService, "enable2fa", true);
        testUser.setTwoFactorEnabled(false);
        
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities()));
        when(userRepository.findByEmail("john@example.com"))
                .thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(any(User.class))).thenReturn("jwt-token");
        when(jwtService.generateRefreshToken(any(User.class))).thenReturn("refresh-token");
        when(tokenRepository.findAllValidTokenByUser(any(Integer.class))).thenReturn(new ArrayList<>());

        // When
        AuthenticationResponse response = authenticationService.authenticate(authRequest);

        // Then
        assertNotNull(response);
        assertFalse(response.isTwoFactorRequired());
        assertEquals("Login successful", response.getMessage());
        assertEquals("jwt-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        
        verify(userRepository, times(1)).save(any(User.class)); // Once for resetting failed attempts
    }

    @Test
    void whenGlobal2faDisabled_shouldNotAllowEnablingUser2fa() {
        // Given
        ReflectionTestUtils.setField(authenticationService, "enable2fa", false);
        
        when(userRepository.findByEmail("john@example.com"))
                .thenReturn(Optional.of(testUser));

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            authenticationService.enable2faForUser("john@example.com");
        });
        
        assertEquals("2FA is not enabled for this application", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void whenGlobal2faEnabled_shouldAllowEnablingUser2fa() {
        // Given
        ReflectionTestUtils.setField(authenticationService, "enable2fa", true);
        
        when(userRepository.findByEmail("john@example.com"))
                .thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        assertDoesNotThrow(() -> {
            authenticationService.enable2faForUser("john@example.com");
        });

        // Then
        verify(userRepository).save(any(User.class));
    }
} 