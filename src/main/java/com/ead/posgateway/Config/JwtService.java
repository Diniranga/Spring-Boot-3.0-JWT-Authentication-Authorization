package com.ead.posgateway.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${spring.application.security.jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${spring.application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${spring.application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    @Value("${spring.application.security.jwt.audience}")
    private String jwtAudience;

    @Value("${spring.application.security.jwt.issuer}")
    private String jwtIssuer;

    public String extractUserEmail(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(
            UserDetails userDetails
    ){
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ){
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
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public <T>T extractClaim(String jwtToken, Function<Claims,T> claimResolver){
        final Claims claims = extractAllClaims(jwtToken);
        if(claims==null){
            return null;
        }
        return claimResolver.apply(claims);
    }

    public boolean isTokenValid(String jwtToken,UserDetails userDetails){
        final Claims claims = extractAllClaims(jwtToken);
        if (claims == null) return false;
        final String userName = claims.getSubject();
        if(userName == null || !userName.equals(userDetails.getUsername())){
            return false;
        }
        if (isTokenExpired(jwtToken)) {
            return false;
        }
        // Validate audience
        if (!jwtAudience.equals(claims.getAudience())) {
            return false;
        }
        // Validate issuer
        if (!jwtIssuer.equals(claims.getIssuer())) {
            return false;
        }
        // Validate issued at
        if (claims.getIssuedAt() == null) {
            return false;
        }
        // Validate JWT ID
        if (claims.getId() == null || claims.getId().isEmpty()) {
            return false;
        }
        return true;
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken,Claims::getExpiration);
    }

    private Claims extractAllClaims(String jwtToken) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
