/*
 * JwtService.java
 * Service for JWT token generation, validation, and extraction using RSA keys.
 */
package com.example.auth.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * Service for handling JWT creation, validation, and extraction.
 * Uses RSA key pairs for signing and verification.
 */
@Service
@Slf4j
public class JwtService {

    @Value("${spring.application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${spring.application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    @Value("${spring.application.security.jwt.audience}")
    private String jwtAudience;

    @Value("${spring.application.security.jwt.issuer}")
    private String jwtIssuer;

    private static final int KEY_SIZE = 2048;

    private final KeyPair keyPair;

    /**
     * Initializes JwtService and generates RSA key pair.
     */
    public JwtService() {
        this.keyPair = generateKeyPair();
    }

    /**
     * Generates an RSA key pair for signing and verification.
     * @return KeyPair instance
     */
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            log.error("Failed to generate RSA key pair", e);
            throw new IllegalStateException("Failed to initialize JWT service", e);
        }
    }

    /**
     * Extracts the user email (subject) from a JWT token.
     * @param jwtToken JWT token string
     * @return user email (subject)
     */
    public String extractUserEmail(final String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    /**
     * Generates a JWT token for the given user details.
     * @param userDetails user details
     * @return JWT token string
     */
    public String generateToken(final UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with extra claims for the given user details.
     * @param extraClaims additional claims
     * @param userDetails user details
     * @return JWT token string
     */
    public String generateToken(final Map<String, Object> extraClaims, final UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Generates a refresh JWT token for the given user details.
     * @param userDetails user details
     * @return refresh JWT token string
     */
    public String generateRefreshToken(final UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    /**
     * Builds a JWT token with the specified claims and expiration.
     * @param extraClaims additional claims
     * @param userDetails user details
     * @param expiration expiration in ms
     * @return JWT token string
     */
    private String buildToken(final Map<String, Object> extraClaims, final UserDetails userDetails, final long expiration) {
        final long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setAudience(jwtAudience)
                .setIssuer(jwtIssuer)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expiration))
                .setId(UUID.randomUUID().toString())
                .signWith(getSigningKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Extracts a claim from the JWT token using the provided resolver.
     * @param jwtToken JWT token string
     * @param claimResolver function to extract claim
     * @return extracted claim or null if invalid
     */
    public <T> T extractClaim(final String jwtToken, final Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        if (claims == null) {
            return null;
        }
        return claimResolver.apply(claims);
    }

    /**
     * Validates the JWT token for the given user details.
     * @param jwtToken JWT token string
     * @param userDetails user details
     * @return true if valid, false otherwise
     */
    public boolean isTokenValid(final String jwtToken, final UserDetails userDetails) {
        try {
            final Claims claims = extractAllClaims(jwtToken);
            if (claims == null) return false;

            final String userName = claims.getSubject();
            if (userName == null || !userName.equals(userDetails.getUsername())) {
                log.warn("Token subject mismatch: expected {}, got {}", userDetails.getUsername(), userName);
                return false;
            }

            if (isTokenExpired(jwtToken)) {
                log.warn("Token expired for user: {}", userName);
                return false;
            }

            if (!jwtAudience.equals(claims.getAudience())) {
                log.warn("Token audience mismatch: expected {}, got {}", jwtAudience, claims.getAudience());
                return false;
            }

            if (!jwtIssuer.equals(claims.getIssuer())) {
                log.warn("Token issuer mismatch: expected {}, got {}", jwtIssuer, claims.getIssuer());
                return false;
            }

            if (claims.getIssuedAt() == null) {
                log.warn("Token issued at is null");
                return false;
            }

            if (claims.getId() == null || claims.getId().isEmpty()) {
                log.warn("Token ID is null or empty");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Error validating token for user: {}", userDetails.getUsername(), e);
            return false;
        }
    }

    /**
     * Checks if the JWT token is expired.
     * @param jwtToken JWT token string
     * @return true if expired, false otherwise
     */
    private boolean isTokenExpired(final String jwtToken) {
        final Date expiration = extractExpiration(jwtToken);
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Extracts the expiration date from the JWT token.
     * @param jwtToken JWT token string
     * @return expiration date
     */
    private Date extractExpiration(final String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    /**
     * Extracts all claims from the JWT token.
     * @param jwtToken JWT token string
     * @return Claims object or null if invalid
     */
    private Claims extractAllClaims(final String jwtToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getVerificationKey())
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
        } catch (Exception e) {
            log.warn("Failed to parse JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the private key for signing JWTs.
     * @return PrivateKey
     */
    private PrivateKey getSigningKey() {
        return keyPair.getPrivate();
    }

    /**
     * Gets the public key for verifying JWTs.
     * @return PublicKey
     */
    private PublicKey getVerificationKey() {
        return keyPair.getPublic();
    }

    /**
     * Returns the public key for external use.
     * @return PublicKey
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
