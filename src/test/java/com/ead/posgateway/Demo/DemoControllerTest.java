package com.ead.posgateway.Demo;

import com.ead.posgateway.Config.SecurityContextUtils;
import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class DemoControllerTest {

    @InjectMocks
    private DemoController demoController;

    private User testUser;
    private User adminUser;
    private Authentication userAuthentication;
    private Authentication adminAuthentication;
    private SecurityContext securityContext;

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

        adminUser = User.builder()
                .id(2)
                .firstName("Admin")
                .lastName("User")
                .email("admin@example.com")
                .password("encodedPassword")
                .role(Role.ADMIN)
                .build();

        userAuthentication = new UsernamePasswordAuthenticationToken(
                testUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        adminAuthentication = new UsernamePasswordAuthenticationToken(
                adminUser.getEmail(),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        securityContext = new SecurityContextImpl();
        SecurityContextHolder.clearContext();
    }

    @Test
    void sayHelloGet_shouldReturnHelloMessage() {
        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_shouldReturnHelloMessage() {
        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withUserAuthentication_shouldReturnHelloMessage() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(userAuthentication);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withAdminAuthentication_shouldReturnHelloMessage() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(adminAuthentication);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withAdminAuthentication_shouldReturnHelloMessage() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(adminAuthentication);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withNoAuthentication_shouldReturnHelloMessage() {
        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withNoAuthentication_shouldReturnHelloMessage() {
        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withNullAuthentication_shouldReturnHelloMessage() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(null);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withNullAuthentication_shouldReturnHelloMessage() {
        // Given
        SecurityContextHolder.getContext().setAuthentication(null);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withAnonymousUser_shouldReturnHelloMessage() {
        // Given
        Authentication anonymousAuth = new UsernamePasswordAuthenticationToken(
                "anonymousUser",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
        );
        SecurityContextHolder.getContext().setAuthentication(anonymousAuth);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withAnonymousUser_shouldReturnHelloMessage() {
        // Given
        Authentication anonymousAuth = new UsernamePasswordAuthenticationToken(
                "anonymousUser",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
        );
        SecurityContextHolder.getContext().setAuthentication(anonymousAuth);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withNonStringPrincipal_shouldReturnHelloMessage() {
        // Given
        Authentication authWithNonStringPrincipal = new UsernamePasswordAuthenticationToken(
                123, // Non-string principal
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithNonStringPrincipal);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withNonStringPrincipal_shouldReturnHelloMessage() {
        // Given
        Authentication authWithNonStringPrincipal = new UsernamePasswordAuthenticationToken(
                123, // Non-string principal
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithNonStringPrincipal);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withEmptyStringPrincipal_shouldReturnHelloMessage() {
        // Given
        Authentication authWithEmptyPrincipal = new UsernamePasswordAuthenticationToken(
                "",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithEmptyPrincipal);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withEmptyStringPrincipal_shouldReturnHelloMessage() {
        // Given
        Authentication authWithEmptyPrincipal = new UsernamePasswordAuthenticationToken(
                "",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithEmptyPrincipal);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloGet_withUserWithSpecialCharacters_shouldReturnHelloMessage() {
        // Given
        Authentication authWithSpecialChars = new UsernamePasswordAuthenticationToken(
                "user+test@example.com",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithSpecialChars);

        // When
        ResponseEntity<String> response = demoController.sayHelloGet();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("GET: Hello from secured endpoint", response.getBody());
    }

    @Test
    void sayHelloPost_withUserWithSpecialCharacters_shouldReturnHelloMessage() {
        // Given
        Authentication authWithSpecialChars = new UsernamePasswordAuthenticationToken(
                "admin+test@example.com",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(authWithSpecialChars);

        // When
        ResponseEntity<String> response = demoController.sayHelloPost();

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("POST: Hello from secured endpoint", response.getBody());
    }
} 