package com.ead.posgateway.Config;

import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SecurityContextUtilsTest {

    private User testUser;
    private Authentication testAuthentication;
    private SecurityContext securityContext;
    private MockHttpServletRequest request;

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

        testAuthentication = new UsernamePasswordAuthenticationToken(
                testUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        securityContext = new SecurityContextImpl();
        request = new MockHttpServletRequest();
        SecurityContextHolder.clearContext();
    }

    @Test
    void setSecurityContext_shouldSetAuthenticationInContext() {
        // Given
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(testUser.getEmail())
                .password(testUser.getPassword())
                .authorities("ROLE_USER")
                .build();

        // When
        SecurityContextUtils.setSecurityContext(userDetails, "credentials", request);

        // Then
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(currentAuth);
        assertEquals(testUser.getEmail(), currentAuth.getName());
        assertTrue(currentAuth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void setSecurityContext_withException_shouldClearContext() {
        // Given
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(testUser.getEmail())
                .password(testUser.getPassword())
                .authorities("ROLE_USER")
                .build();

        // Set initial context
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);

        // When & Then
        assertThrows(RuntimeException.class, () -> {
            SecurityContextUtils.setSecurityContext(userDetails, null, null);
        });

        // Context should be cleared on exception
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNull(currentAuth);
    }

    @Test
    void clearSecurityContext_shouldClearAuthentication() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);

        // When
        SecurityContextUtils.clearSecurityContext();

        // Then
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNull(currentAuth);
    }

    @Test
    void getCurrentAuthentication_shouldReturnCurrentAuthentication() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);

        // When
        Authentication currentAuth = SecurityContextUtils.getCurrentAuthentication();

        // Then
        assertNotNull(currentAuth);
        assertEquals(testUser.getEmail(), currentAuth.getName());
    }

    @Test
    void getCurrentAuthentication_whenNoAuthentication_shouldReturnNull() {
        // When
        Authentication currentAuth = SecurityContextUtils.getCurrentAuthentication();

        // Then
        assertNull(currentAuth);
    }

    @Test
    void getCurrentUserEmail_shouldReturnUserEmail() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);

        // When
        String userEmail = SecurityContextUtils.getCurrentUserEmail();

        // Then
        assertEquals(testUser.getEmail(), userEmail);
    }

    @Test
    void getCurrentUserEmail_whenNoAuthentication_shouldReturnNull() {
        // When
        String userEmail = SecurityContextUtils.getCurrentUserEmail();

        // Then
        assertNull(userEmail);
    }

    @Test
    void getCurrentUserEmail_withNonStringPrincipal_shouldReturnNull() {
        // Given
        Authentication authWithNonStringPrincipal = new UsernamePasswordAuthenticationToken(
                123, // Non-string principal
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithNonStringPrincipal);

        // When
        String userEmail = SecurityContextUtils.getCurrentUserEmail();

        // Then
        assertNull(userEmail);
    }

    @Test
    void isAuthenticated_shouldReturnTrueWhenAuthenticated() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(testAuthentication);

        // When
        boolean isAuthenticated = SecurityContextUtils.isAuthenticated();

        // Then
        assertTrue(isAuthenticated);
    }

    @Test
    void isAuthenticated_whenNoAuthentication_shouldReturnFalse() {
        // When
        boolean isAuthenticated = SecurityContextUtils.isAuthenticated();

        // Then
        assertFalse(isAuthenticated);
    }

    @Test
    void isAuthenticated_withNullAuthentication_shouldReturnFalse() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(null);

        // When
        boolean isAuthenticated = SecurityContextUtils.isAuthenticated();

        // Then
        assertFalse(isAuthenticated);
    }

    @Test
    void isAuthenticated_withAnonymousUser_shouldReturnFalse() {
        // Given
        Authentication anonymousAuth = new UsernamePasswordAuthenticationToken(
                "anonymousUser",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
        );
        SecurityContextHolder.getContext().setAuthentication(anonymousAuth);

        // When
        boolean isAuthenticated = SecurityContextUtils.isAuthenticated();

        // Then
        assertFalse(isAuthenticated);
    }

    @Test
    void isAuthenticated_withNonAuthenticatedToken_shouldReturnFalse() {
        // Given
        Authentication nonAuthenticatedAuth = new UsernamePasswordAuthenticationToken(
                testUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        nonAuthenticatedAuth.setAuthenticated(false);
        SecurityContextHolder.getContext().setAuthentication(nonAuthenticatedAuth);

        // When
        boolean isAuthenticated = SecurityContextUtils.isAuthenticated();

        // Then
        assertFalse(isAuthenticated);
    }

    @Test
    void setSecurityContext_withAdminUser_shouldSetAdminAuthentication() {
        // Given
        UserDetails adminUserDetails = org.springframework.security.core.userdetails.User.builder()
                .username("admin@example.com")
                .password("encodedPassword")
                .authorities("ROLE_ADMIN")
                .build();

        // When
        SecurityContextUtils.setSecurityContext(adminUserDetails, "credentials", request);

        // Then
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(currentAuth);
        assertEquals("admin@example.com", currentAuth.getName());
        assertTrue(currentAuth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void setSecurityContext_withMultipleAuthorities_shouldSetAllAuthorities() {
        // Given
        UserDetails userWithMultipleAuthorities = org.springframework.security.core.userdetails.User.builder()
                .username("user@example.com")
                .password("encodedPassword")
                .authorities("ROLE_USER", "READ", "WRITE")
                .build();

        // When
        SecurityContextUtils.setSecurityContext(userWithMultipleAuthorities, "credentials", request);

        // Then
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(currentAuth);
        assertEquals("user@example.com", currentAuth.getName());
        assertTrue(currentAuth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertTrue(currentAuth.getAuthorities().contains(new SimpleGrantedAuthority("READ")));
        assertTrue(currentAuth.getAuthorities().contains(new SimpleGrantedAuthority("WRITE")));
    }

    @Test
    void getCurrentAuthentication_withNullContext_shouldReturnNull() {
        // Given
        SecurityContextHolder.clearContext();

        // When
        Authentication currentAuth = SecurityContextUtils.getCurrentAuthentication();

        // Then
        assertNull(currentAuth);
    }

    @Test
    void getCurrentUserEmail_withEmptyStringPrincipal_shouldReturnEmptyString() {
        // Given
        Authentication authWithEmptyPrincipal = new UsernamePasswordAuthenticationToken(
                "",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithEmptyPrincipal);

        // When
        String userEmail = SecurityContextUtils.getCurrentUserEmail();

        // Then
        assertEquals("", userEmail);
    }
} 