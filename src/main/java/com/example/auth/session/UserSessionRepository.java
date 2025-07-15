/*
 * UserSessionRepository.java
 * Repository interface for managing UserSession entities and custom queries.
 */
package com.example.auth.session;

import com.example.auth.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing UserSession entities and custom queries.
 */
@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    /**
     * Find a session by its session ID, fetching the associated user.
     * @param sessionId Session identifier
     * @return Optional containing the UserSession if found
     */
    @Query("SELECT s FROM UserSession s JOIN FETCH s.user WHERE s.sessionId = :sessionId")
    Optional<UserSession> findBySessionId(@Param("sessionId") String sessionId);

    /**
     * Find a session by device fingerprint.
     * @param deviceFingerprint Device fingerprint string
     * @return Optional containing the UserSession if found
     */
    Optional<UserSession> findByDeviceFingerprint(String deviceFingerprint);

    /**
     * Find all active sessions for a user.
     * @param user User entity
     * @return List of active UserSession entities
     */
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.isActive = true AND s.isRevoked = false AND s.expiresAt > CURRENT_TIMESTAMP")
    List<UserSession> findActiveSessionsByUser(@Param("user") User user);

    /**
     * Find all sessions for a user.
     * @param user User entity
     * @return List of UserSession entities
     */
    List<UserSession> findByUser(User user);

    /**
     * Find sessions by user and session type.
     * @param user User entity
     * @param sessionType Session type
     * @return List of UserSession entities
     */
    List<UserSession> findByUserAndSessionType(User user, UserSession.SessionType sessionType);

    /**
     * Find expired sessions.
     * @param cutoffTime LocalDateTime cutoff
     * @return List of expired UserSession entities
     */
    List<UserSession> findByExpiresAtBeforeAndIsActiveTrue(LocalDateTime cutoffTime);

    /**
     * Find sessions by IP address.
     * @param ipAddress IP address string
     * @return List of UserSession entities
     */
    List<UserSession> findByIpAddress(String ipAddress);

    /**
     * Find sessions by user agent substring.
     * @param userAgent User agent substring
     * @return List of UserSession entities
     */
    List<UserSession> findByUserAgentContaining(String userAgent);

    /**
     * Find sessions created after a specific time.
     * @param after LocalDateTime after
     * @return List of UserSession entities
     */
    List<UserSession> findByCreatedAtAfter(LocalDateTime after);

    /**
     * Find sessions last used before a specific time.
     * @param before LocalDateTime before
     * @return List of UserSession entities
     */
    List<UserSession> findByLastUsedAtBeforeAndIsActiveTrue(LocalDateTime before);

    /**
     * Find sessions by login method.
     * @param loginMethod Login method enum
     * @return List of UserSession entities
     */
    List<UserSession> findByLoginMethod(UserSession.LoginMethod loginMethod);

    /**
     * Count active sessions for a user.
     * @param user User entity
     * @return Number of active sessions
     */
    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user = :user AND s.isActive = true AND s.isRevoked = false AND s.expiresAt > CURRENT_TIMESTAMP")
    long countActiveSessionsByUser(@Param("user") User user);

    /**
     * Find sessions that need to be expired.
     * @param now LocalDateTime now
     * @return List of UserSession entities to expire
     */
    @Query("SELECT s FROM UserSession s WHERE s.expiresAt <= :now AND s.isActive = true")
    List<UserSession> findSessionsToExpire(@Param("now") LocalDateTime now);

    /**
     * Find sessions by user ordered by creation date (descending).
     * @param user User entity
     * @return List of UserSession entities
     */
    List<UserSession> findByUserOrderByCreatedAtDesc(User user);

    /**
     * Find sessions by user ordered by last used date (descending).
     * @param user User entity
     * @return List of UserSession entities
     */
    List<UserSession> findByUserOrderByLastUsedAtDesc(User user);

    /**
     * Find sessions by user ordered by creation date (ascending).
     * @param user User entity
     * @return List of UserSession entities
     */
    List<UserSession> findByUserOrderByCreatedAtAsc(User user);

    /**
     * Find sessions by user, session type, and active status.
     * @param user User entity
     * @param sessionType Session type
     * @return List of UserSession entities
     */
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.sessionType = :sessionType AND s.isActive = true")
    List<UserSession> findByUserAndSessionTypeAndActive(@Param("user") User user, @Param("sessionType") UserSession.SessionType sessionType);

    /**
     * Find sessions by device fingerprint and user.
     * @param user User entity
     * @param deviceFingerprint Device fingerprint string
     * @return List of UserSession entities
     */
    List<UserSession> findByUserAndDeviceFingerprint(User user, String deviceFingerprint);

    /**
     * Find sessions by IP address and user.
     * @param user User entity
     * @param ipAddress IP address string
     * @return List of UserSession entities
     */
    List<UserSession> findByUserAndIpAddress(User user, String ipAddress);

    /**
     * Find sessions created in a date range for a user.
     * @param user User entity
     * @param startDate Start date
     * @param endDate End date
     * @return List of UserSession entities
     */
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.createdAt BETWEEN :startDate AND :endDate")
    List<UserSession> findByUserAndCreatedAtBetween(@Param("user") User user, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find sessions by revoked reason.
     * @param revokedReason Revoked reason string
     * @return List of UserSession entities
     */
    List<UserSession> findByRevokedReason(String revokedReason);

    /**
     * Find sessions revoked by a specific user or system.
     * @param revokedBy Revoked by string
     * @return List of UserSession entities
     */
    List<UserSession> findByRevokedBy(String revokedBy);

    /**
     * Find sessions revoked in a date range.
     * @param startDate Start date
     * @param endDate End date
     * @return List of UserSession entities
     */
    @Query("SELECT s FROM UserSession s WHERE s.revokedAt BETWEEN :startDate AND :endDate")
    List<UserSession> findByRevokedAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Find active sessions by device fingerprint.
     * @param deviceFingerprint Device fingerprint string
     * @return List of active UserSession entities
     */
    @Query("SELECT s FROM UserSession s WHERE s.deviceFingerprint = :deviceFingerprint AND s.isActive = true AND s.isRevoked = false AND s.expiresAt > CURRENT_TIMESTAMP")
    List<UserSession> findActiveSessionsByDeviceFingerprint(@Param("deviceFingerprint") String deviceFingerprint);
} 