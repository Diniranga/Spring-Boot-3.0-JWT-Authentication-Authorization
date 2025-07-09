package com.ead.posgateway.Auth;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {

    @Mock
    private AuthenticationService authenticationService;

    @Mock
    private LogoutService logoutService;

    @InjectMocks
    private AuthenticationController authenticationController;

    private User testUser;
    private AuthenticationRequest authRequest;
    private RegisterRequest registerRequest;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1)
                .firstName("John")
                .lastName("Doe")
                .email("john@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .build();

        authRequest = new AuthenticationRequest();
        authRequest.setEmail("john@example.com");
        authRequest.setPassword("password");

        registerRequest = new RegisterRequest();
        registerRequest.setFirstName("John");
        registerRequest.setLastName("Doe");
        registerRequest.setEmail("john@example.com");
        registerRequest.setPassword("password");
        registerRequest.setRole(Role.USER);

        objectMapper = new ObjectMapper();
    }

    @Test
    void register_shouldReturnAuthenticationResponse() {
        // Given
        AuthenticationResponse expectedResponse = AuthenticationResponse.builder()
                .accessToken("jwt-token")
                .refreshToken("refresh-token")
                .userEmail("john@example.com")
                .userRole("USER")
                .message("Registration successful")
                .build();

        when(authenticationService.register(any(RegisterRequest.class)))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<AuthenticationResponse> response = authenticationController.register(registerRequest);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals(expectedResponse, response.getBody());
        verify(authenticationService).register(registerRequest);
    }

    @Test
    void login_shouldReturnAuthenticationResponse() {
        // Given
        AuthenticationResponse expectedResponse = AuthenticationResponse.builder()
                .accessToken("jwt-token")
                .refreshToken("refresh-token")
                .userEmail("john@example.com")
                .userRole("USER")
                .message("Login successful")
                .build();

        when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<AuthenticationResponse> response = authenticationController.login(authRequest);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals(expectedResponse, response.getBody());
        verify(authenticationService).authenticate(authRequest);
    }

    @Test
    void validateToken_shouldReturnTrueForValidToken() {
        // Given
        TokenValidationRequest request = new TokenValidationRequest();
        request.setToken("valid-token");
        request.setEmail("john@example.com");

        when(authenticationService.validateToken(anyString(), anyString()))
                .thenReturn(true);

        // When
        boolean result = authenticationController.validateToken(request);

        // Then
        assertTrue(result);
        verify(authenticationService).validateToken("valid-token", "john@example.com");
    }

    @Test
    void validateToken_shouldReturnFalseForInvalidToken() {
        // Given
        TokenValidationRequest request = new TokenValidationRequest();
        request.setToken("invalid-token");
        request.setEmail("john@example.com");

        when(authenticationService.validateToken(anyString(), anyString()))
                .thenReturn(false);

        // When
        boolean result = authenticationController.validateToken(request);

        // Then
        assertFalse(result);
        verify(authenticationService).validateToken("invalid-token", "john@example.com");
    }

    @Test
    void getSecurityContext_shouldReturnContextInfo() {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                testUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentAuthentication)
                    .thenReturn(authentication);

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.getSecurityContext();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> contextInfo = response.getBody();
            assertNotNull(contextInfo);
            assertTrue((Boolean) contextInfo.get("authenticated"));
            assertEquals(testUser.getEmail(), contextInfo.get("principal"));
        }
    }

    @Test
    void getSecurityContext_whenNotAuthenticated_shouldReturnNotAuthenticated() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentAuthentication)
                    .thenReturn(null);

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.getSecurityContext();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> contextInfo = response.getBody();
            assertNotNull(contextInfo);
            assertFalse((Boolean) contextInfo.get("authenticated"));
        }
    }

    @Test
    void verifyAuthentication_shouldReturnAuthenticationInfo() {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                testUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::isAuthenticated)
                    .thenReturn(true);
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn(testUser.getEmail());
            mockedStatic.when(SecurityContextUtils::getCurrentAuthentication)
                    .thenReturn(authentication);

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.verifyAuthentication();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> authInfo = response.getBody();
            assertNotNull(authInfo);
            assertTrue((Boolean) authInfo.get("authenticated"));
            assertEquals(testUser.getEmail(), authInfo.get("userEmail"));
            assertEquals("User is authenticated", authInfo.get("message"));
        }
    }

    @Test
    void verifyAuthentication_whenNotAuthenticated_shouldReturnNotAuthenticated() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::isAuthenticated)
                    .thenReturn(false);

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.verifyAuthentication();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> authInfo = response.getBody();
            assertNotNull(authInfo);
            assertFalse((Boolean) authInfo.get("authenticated"));
            assertEquals("User is not authenticated", authInfo.get("message"));
        }
    }

    @Test
    void verify2fa_shouldReturnAuthenticationResponse() {
        // Given
        Map<String, String> body = new HashMap<>();
        body.put("email", "john@example.com");
        body.put("code", "123456");

        AuthenticationResponse expectedResponse = AuthenticationResponse.builder()
                .accessToken("jwt-token")
                .refreshToken("refresh-token")
                .userEmail("john@example.com")
                .userRole("USER")
                .message("2FA verification successful. Login complete.")
                .twoFactorRequired(false)
                .build();

        when(authenticationService.verify2faCode(anyString(), anyString()))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<AuthenticationResponse> response = authenticationController.verify2fa(body);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        assertEquals(expectedResponse, response.getBody());
        verify(authenticationService).verify2faCode("john@example.com", "123456");
    }

    @Test
    void logout_shouldReturnSuccessMessage() {
        // Given
        String authHeader = "Bearer valid-token";

        // When
        ResponseEntity<Map<String, String>> response = authenticationController.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, String> result = response.getBody();
        assertNotNull(result);
        assertEquals("Logout successful", result.get("message"));
        verify(logoutService).logout("valid-token");
    }

    @Test
    void logout_withoutToken_shouldReturnNoTokenMessage() {
        // Given
        String authHeader = null;

        // When
        ResponseEntity<Map<String, String>> response = authenticationController.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, String> result = response.getBody();
        assertNotNull(result);
        assertEquals("No token provided", result.get("message"));
        verify(logoutService, never()).logout(anyString());
    }

    @Test
    void logoutAllSessions_shouldReturnSuccessMessage() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn("john@example.com");

            // When
            ResponseEntity<Map<String, String>> response = authenticationController.logoutAllSessions();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, String> result = response.getBody();
            assertNotNull(result);
            assertEquals("All sessions logged out successfully", result.get("message"));
            verify(logoutService).logoutAllSessions("john@example.com");
        }
    }

    @Test
    void logoutAllSessions_whenNotAuthenticated_shouldReturnNotAuthenticatedMessage() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn(null);

            // When
            ResponseEntity<Map<String, String>> response = authenticationController.logoutAllSessions();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, String> result = response.getBody();
            assertNotNull(result);
            assertEquals("User not authenticated", result.get("message"));
            verify(logoutService, never()).logoutAllSessions(anyString());
        }
    }

    @Test
    void enable2fa_shouldReturnSuccessMessage() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn("john@example.com");

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.enable2fa();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> result = response.getBody();
            assertNotNull(result);
            assertTrue((Boolean) result.get("success"));
            assertEquals("2FA enabled successfully", result.get("message"));
            assertEquals("john@example.com", result.get("userEmail"));
            verify(authenticationService).enable2faForUser("john@example.com");
        }
    }

    @Test
    void enable2fa_whenExceptionOccurs_shouldReturnErrorMessage() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn("john@example.com");

            doThrow(new RuntimeException("2FA not available"))
                    .when(authenticationService).enable2faForUser(anyString());

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.enable2fa();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> result = response.getBody();
            assertNotNull(result);
            assertFalse((Boolean) result.get("success"));
            assertTrue(((String) result.get("message")).contains("Failed to enable 2FA"));
        }
    }

    @Test
    void disable2fa_shouldReturnSuccessMessage() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn("john@example.com");

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.disable2fa();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> result = response.getBody();
            assertNotNull(result);
            assertTrue((Boolean) result.get("success"));
            assertEquals("2FA disabled successfully", result.get("message"));
            assertEquals("john@example.com", result.get("userEmail"));
            verify(authenticationService).disable2faForUser("john@example.com");
        }
    }

    @Test
    void get2faStatus_shouldReturnStatusInfo() {
        // Given
        // Mock SecurityContextUtils
        try (var mockedStatic = mockStatic(SecurityContextUtils.class)) {
            mockedStatic.when(SecurityContextUtils::getCurrentUserEmail)
                    .thenReturn("john@example.com");

            when(authenticationService.is2faEnabledForUser(anyString())).thenReturn(true);
            when(authenticationService.isGlobal2faEnabled()).thenReturn(true);

            // When
            ResponseEntity<Map<String, Object>> response = authenticationController.get2faStatus();

            // Then
            assertNotNull(response);
            assertEquals(200, response.getStatusCodeValue());
            Map<String, Object> result = response.getBody();
            assertNotNull(result);
            assertTrue((Boolean) result.get("success"));
            assertEquals("john@example.com", result.get("userEmail"));
            assertTrue((Boolean) result.get("user2faEnabled"));
            assertTrue((Boolean) result.get("global2faEnabled"));
            assertEquals("2FA status retrieved successfully", result.get("message"));
        }
    }

    @Test
    void resend2faCode_shouldReturnSuccessMessage() {
        // Given
        Map<String, String> body = new HashMap<>();
        body.put("email", "john@example.com");

        // When
        ResponseEntity<Map<String, Object>> response = authenticationController.resend2faCode(body);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> result = response.getBody();
        assertNotNull(result);
        assertTrue((Boolean) result.get("success"));
        assertEquals("2FA code resent successfully", result.get("message"));
        assertEquals("john@example.com", result.get("userEmail"));
        verify(authenticationService).resend2faCode("john@example.com");
    }

    @Test
    void resend2faCode_withoutEmail_shouldReturnErrorMessage() {
        // Given
        Map<String, String> body = new HashMap<>();
        // No email provided

        // When
        ResponseEntity<Map<String, Object>> response = authenticationController.resend2faCode(body);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        Map<String, Object> result = response.getBody();
        assertNotNull(result);
        assertFalse((Boolean) result.get("success"));
        assertEquals("Email is required", result.get("message"));
        verify(authenticationService, never()).resend2faCode(anyString());
    }
} 