/*
 * TokenRepository.java
 * Repository interface for managing Token entities and custom queries.
 */
package com.example.auth.token;

import com.example.auth.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing Token entities and custom queries.
 */
public interface TokenRepository extends JpaRepository<Token, Integer> {

    /**
     * Find all valid (not revoked) tokens for a user by user ID.
     * @param id User ID
     * @return List of valid Token entities
     */
    @Query(value = """
      select t from Token t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.revoked = false)\s
      """)
    List<Token> findAllValidTokenByUser(Integer id);

    /**
     * Find a token by its access token value.
     * @param accessToken Access token string
     * @return Optional containing the Token if found
     */
    Optional<Token> findByAccessToken(String accessToken);

    /**
     * Find a token by its refresh token value.
     * @param refreshToken Refresh token string
     * @return Optional containing the Token if found
     */
    Optional<Token> findByRefreshToken(String refreshToken);

    /**
     * Find a token by either access or refresh token value.
     * @param token Token string
     * @return Optional containing the Token if found
     */
    @Query("SELECT t FROM Token t WHERE t.accessToken = :token OR t.refreshToken = :token")
    Optional<Token> findByToken(@Param("token") String token);

    /**
     * Find a token by its associated session ID.
     * @param sessionId Session identifier
     * @return Optional containing the Token if found
     */
    Optional<Token> findBySessionId(String sessionId);

    /**
     * Find all tokens for a user.
     * @param user User entity
     * @return List of Token entities
     */
    List<Token> findByUser(User user);

    /**
     * Find all valid (not revoked) tokens for a user.
     * @param user User entity
     * @return List of valid Token entities
     */
    List<Token> findByUserAndRevokedFalse(User user);

    /**
     * Find all valid (not revoked) tokens by session ID.
     * @param sessionId Session identifier
     * @return List of valid Token entities
     */
    List<Token> findBySessionIdAndRevokedFalse(String sessionId);
}