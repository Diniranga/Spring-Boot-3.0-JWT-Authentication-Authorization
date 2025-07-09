package com.ead.posgateway.Config;

import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import com.ead.posgateway.User.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private User testUser;
    private String validToken;
    private String authHeader;

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

        validToken = "valid.jwt.token";
        authHeader = "Bearer " + validToken;

        // Clear security context before each test
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_withValidToken_shouldSetAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenReturn(testUser.getEmail());
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(jwtService.isTokenValid(validToken, testUser)).thenReturn(true);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userRepository).findByEmail(testUser.getEmail());
        verify(jwtService).isTokenValid(validToken, testUser);
        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withInvalidToken_shouldNotSetAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenReturn(testUser.getEmail());
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(jwtService.isTokenValid(validToken, testUser)).thenReturn(false);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userRepository).findByEmail(testUser.getEmail());
        verify(jwtService).isTokenValid(validToken, testUser);
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withNoAuthHeader_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(null);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withEmptyAuthHeader_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("");
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withInvalidAuthHeaderFormat_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("InvalidFormat");
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withNullEmail_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenReturn(null);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withUserNotFound_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenReturn(testUser.getEmail());
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.empty());
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userRepository).findByEmail(testUser.getEmail());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withExistingAuthentication_shouldNotOverride() throws ServletException, IOException {
        // Given
        Authentication existingAuth = new UsernamePasswordAuthenticationToken(
                "existing@example.com",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(securityContext.getAuthentication()).thenReturn(existingAuth);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withException_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenThrow(new RuntimeException("JWT parsing error"));
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withValidTokenAndAdminUser_shouldSetAuthenticationWithAdminRole() throws ServletException, IOException {
        // Given
        User adminUser = User.builder()
                .id(2)
                .firstName("Admin")
                .lastName("User")
                .email("admin@example.com")
                .password("encodedPassword")
                .role(Role.ADMIN)
                .build();

        String adminToken = "admin.jwt.token";
        String adminAuthHeader = "Bearer " + adminToken;

        when(request.getHeader("Authorization")).thenReturn(adminAuthHeader);
        when(jwtService.extractUserEmail(adminToken)).thenReturn(adminUser.getEmail());
        when(userRepository.findByEmail(adminUser.getEmail())).thenReturn(Optional.of(adminUser));
        when(jwtService.isTokenValid(adminToken, adminUser)).thenReturn(true);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(adminToken);
        verify(userRepository).findByEmail(adminUser.getEmail());
        verify(jwtService).isTokenValid(adminToken, adminUser);
        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withValidTokenAndUserRole_shouldSetAuthenticationWithUserRole() throws ServletException, IOException {
        // Given
        User regularUser = User.builder()
                .id(3)
                .firstName("Regular")
                .lastName("User")
                .email("user@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .build();

        String userToken = "user.jwt.token";
        String userAuthHeader = "Bearer " + userToken;

        when(request.getHeader("Authorization")).thenReturn(userAuthHeader);
        when(jwtService.extractUserEmail(userToken)).thenReturn(regularUser.getEmail());
        when(userRepository.findByEmail(regularUser.getEmail())).thenReturn(Optional.of(regularUser));
        when(jwtService.isTokenValid(userToken, regularUser)).thenReturn(true);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(userToken);
        verify(userRepository).findByEmail(regularUser.getEmail());
        verify(jwtService).isTokenValid(userToken, regularUser);
        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withAuthHeaderWithoutBearer_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("TokenWithoutBearer");
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withAuthHeaderWithOnlyBearer_shouldContinueChain() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer ");
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).extractUserEmail(anyString());
        verify(userRepository, never()).findByEmail(anyString());
        verify(jwtService, never()).isTokenValid(anyString(), any());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withValidTokenAndUserDetailsService_shouldUseUserDetailsService() throws ServletException, IOException {
        // Given
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(testUser.getEmail())
                .password(testUser.getPassword())
                .authorities("ROLE_USER")
                .build();

        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(jwtService.extractUserEmail(validToken)).thenReturn(testUser.getEmail());
        when(userDetailsService.loadUserByUsername(testUser.getEmail())).thenReturn(userDetails);
        when(jwtService.isTokenValid(validToken, userDetails)).thenReturn(true);
        when(securityContext.getAuthentication()).thenReturn(null);
        SecurityContextHolder.setContext(securityContext);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).extractUserEmail(validToken);
        verify(userDetailsService).loadUserByUsername(testUser.getEmail());
        verify(jwtService).isTokenValid(validToken, userDetails);
        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(filterChain).doFilter(request, response);
    }
} 