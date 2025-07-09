package com.ead.posgateway.Config;

import com.ead.posgateway.User.Role;
import com.ead.posgateway.User.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    private User testUser;
    private String testSecretKey;
    private long testExpiration;
    private Key signingKey;

    @BeforeEach
    void setUp() {
        testSecretKey = "JsNVm2juYWzy78yatVOCZUnttbBxKjIuZmAuO/PMnaY+VM2nT6F8Z6N3MGaULriP";
        testExpiration = 86400000L; // 24 hours
        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(testSecretKey));

        ReflectionTestUtils.setField(jwtService, "SECRET_KEY", testSecretKey);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", testExpiration);
        ReflectionTestUtils.setField(jwtService, "refreshExpiration", 604800000L); // 7 days
        ReflectionTestUtils.setField(jwtService, "issuer", "pos-gateway");
        ReflectionTestUtils.setField(jwtService, "audience", "pos-gateway-client");

        testUser = User.builder()
                .id(1)
                .firstName("John")
                .lastName("Doe")
                .email("john@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .build();
    }

    @Test
    void generateToken_shouldCreateValidJwtToken() {
        // When
        String token = jwtService.generateToken(testUser);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        
        // Verify token structure
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals(testUser.getEmail(), claims.getSubject());
        assertEquals(testUser.getEmail(), claims.get("email"));
        assertEquals(testUser.getRole().name(), claims.get("role"));
        assertEquals("pos-gateway", claims.getIssuer());
        assertEquals("pos-gateway-client", claims.getAudience());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertNotNull(claims.getId()); // JTI claim
    }

    @Test
    void generateRefreshToken_shouldCreateValidRefreshToken() {
        // When
        String refreshToken = jwtService.generateRefreshToken(testUser);

        // Then
        assertNotNull(refreshToken);
        assertFalse(refreshToken.isEmpty());

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();

        assertEquals(testUser.getEmail(), claims.getSubject());
        assertEquals("pos-gateway", claims.getIssuer());
        assertEquals("pos-gateway-client", claims.getAudience());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertNotNull(claims.getId()); // JTI claim
    }

    @Test
    void extractUserEmail_shouldExtractEmailFromToken() {
        // Given
        String token = jwtService.generateToken(testUser);

        // When
        String extractedEmail = jwtService.extractUserEmail(token);

        // Then
        assertEquals(testUser.getEmail(), extractedEmail);
    }

    @Test
    void extractUserEmail_withInvalidToken_shouldReturnNull() {
        // When
        String extractedEmail = jwtService.extractUserEmail("invalid.token.here");

        // Then
        assertNull(extractedEmail);
    }

    @Test
    void isTokenValid_withValidTokenAndUser_shouldReturnTrue() {
        // Given
        String token = jwtService.generateToken(testUser);

        // When
        boolean isValid = jwtService.isTokenValid(token, testUser);

        // Then
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_withExpiredToken_shouldReturnFalse() {
        // Given
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", -1000L); // Expired
        String expiredToken = jwtService.generateToken(testUser);

        // When
        boolean isValid = jwtService.isTokenValid(expiredToken, testUser);

        // Then
        assertFalse(isValid);
    }

    @Test
    void isTokenValid_withWrongUser_shouldReturnFalse() {
        // Given
        String token = jwtService.generateToken(testUser);
        User wrongUser = User.builder()
                .id(2)
                .email("wrong@example.com")
                .role(Role.USER)
                .build();

        // When
        boolean isValid = jwtService.isTokenValid(token, wrongUser);

        // Then
        assertFalse(isValid);
    }

    @Test
    void isTokenValid_withInvalidToken_shouldReturnFalse() {
        // When
        boolean isValid = jwtService.isTokenValid("invalid.token.here", testUser);

        // Then
        assertFalse(isValid);
    }

    @Test
    void generateToken_withExtraClaims_shouldIncludeClaims() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("customClaim", "customValue");
        extraClaims.put("userId", testUser.getId());

        // When
        String token = jwtService.generateToken(extraClaims, testUser);

        // Then
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals("customValue", claims.get("customClaim"));
        assertEquals(testUser.getId(), claims.get("userId"));
        assertEquals(testUser.getEmail(), claims.getSubject());
    }

    @Test
    void extractClaim_shouldExtractSpecificClaim() {
        // Given
        String token = jwtService.generateToken(testUser);

        // When
        String email = jwtService.extractClaim(token, Claims::getSubject);

        // Then
        assertEquals(testUser.getEmail(), email);
    }

    @Test
    void extractClaim_withInvalidToken_shouldReturnNull() {
        // When
        String email = jwtService.extractClaim("invalid.token.here", Claims::getSubject);

        // Then
        assertNull(email);
    }

    @Test
    void generateToken_withDifferentRoles_shouldIncludeRoleInToken() {
        // Given
        User adminUser = User.builder()
                .id(2)
                .email("admin@example.com")
                .role(Role.ADMIN)
                .build();

        // When
        String token = jwtService.generateToken(adminUser);

        // Then
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals("ADMIN", claims.get("role"));
        assertEquals(adminUser.getEmail(), claims.getSubject());
    }

    @Test
    void refreshTokenExpiration_shouldBeLongerThanAccessToken() {
        // Given
        String accessToken = jwtService.generateToken(testUser);
        String refreshToken = jwtService.generateRefreshToken(testUser);

        // When
        Claims accessClaims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(accessToken)
                .getBody();

        Claims refreshClaims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();

        // Then
        assertTrue(refreshClaims.getExpiration().after(accessClaims.getExpiration()));
    }

    @Test
    void tokenValidation_shouldCheckIssuerAndAudience() {
        // Given
        String token = jwtService.generateToken(testUser);

        // When
        boolean isValid = jwtService.isTokenValid(token, testUser);

        // Then
        assertTrue(isValid);
        
        // Verify claims are properly set
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        assertEquals("pos-gateway", claims.getIssuer());
        assertEquals("pos-gateway-client", claims.getAudience());
    }
} 