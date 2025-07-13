package com.ead.posgateway.token;

import com.ead.posgateway.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query(value = """
      select t from Token t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
    List<Token> findAllValidTokenByUser(Integer id);

    // Find by access token
    Optional<Token> findByAccessToken(String accessToken);
    
    // Find by refresh token
    Optional<Token> findByRefreshToken(String refreshToken);
    
    // Backward compatibility - find by either access or refresh token
    @Query("SELECT t FROM Token t WHERE t.accessToken = :token OR t.refreshToken = :token")
    Optional<Token> findByToken(@Param("token") String token);

    // Find by session ID
    Optional<Token> findBySessionId(String sessionId);

    // Find all tokens for a user
    List<Token> findByUser(User user);

    // Find valid tokens for a user
    List<Token> findByUserAndExpiredFalseAndRevokedFalse(User user);

    // Find tokens by session ID
    List<Token> findBySessionIdAndExpiredFalseAndRevokedFalse(String sessionId);
}