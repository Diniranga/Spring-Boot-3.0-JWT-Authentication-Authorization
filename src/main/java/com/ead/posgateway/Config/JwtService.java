package com.ead.posgateway.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
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

    private final KeyPair keyPair;

    public JwtService() {
        this.keyPair = generateKeyPair();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            log.error("Failed to generate RSA key pair", e);
            throw new RuntimeException("Failed to initialize JWT service", e);
        }
    }

    public String extractUserEmail(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        long now = System.currentTimeMillis();
        return Jwts
                .builder()
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

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        if (claims == null) {
            return null;
        }
        return claimResolver.apply(claims);
    }

    public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
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
            
            // Validate audience
            if (!jwtAudience.equals(claims.getAudience())) {
                log.warn("Token audience mismatch: expected {}, got {}", jwtAudience, claims.getAudience());
                return false;
            }
            
            // Validate issuer
            if (!jwtIssuer.equals(claims.getIssuer())) {
                log.warn("Token issuer mismatch: expected {}, got {}", jwtIssuer, claims.getIssuer());
                return false;
            }
            
            // Validate issued at
            if (claims.getIssuedAt() == null) {
                log.warn("Token issued at is null");
                return false;
            }
            
            // Validate JWT ID
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

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    private Claims extractAllClaims(String jwtToken) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getVerificationKey())
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
        } catch (Exception e) {
            log.warn("Failed to parse JWT token: {}", e.getMessage());
            return null;
        }
    }

    private PrivateKey getSigningKey() {
        return keyPair.getPrivate();
    }

    private PublicKey getVerificationKey() {
        return keyPair.getPublic();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
