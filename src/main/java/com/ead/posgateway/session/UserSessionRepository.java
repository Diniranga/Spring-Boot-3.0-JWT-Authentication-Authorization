package com.ead.posgateway.session;

import com.ead.posgateway.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    // Find by session ID
    @Query("SELECT s FROM UserSession s JOIN FETCH s.user WHERE s.sessionId = :sessionId")
    Optional<UserSession> findBySessionId(@Param("sessionId") String sessionId);

    // Find by device fingerprint
    Optional<UserSession> findByDeviceFingerprint(String deviceFingerprint);

    // Find active sessions for a user
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.isActive = true AND s.isRevoked = false AND s.expiresAt > CURRENT_TIMESTAMP")
    List<UserSession> findActiveSessionsByUser(@Param("user") User user);

    // Find all sessions for a user
    List<UserSession> findByUser(User user);

    // Find sessions by user and session type
    List<UserSession> findByUserAndSessionType(User user, UserSession.SessionType sessionType);

    // Find expired sessions
    List<UserSession> findByExpiresAtBeforeAndIsActiveTrue(LocalDateTime cutoffTime);

    // Find sessions by IP address
    List<UserSession> findByIpAddress(String ipAddress);

    // Find sessions by user agent
    List<UserSession> findByUserAgentContaining(String userAgent);

    // Find sessions created after a specific time
    List<UserSession> findByCreatedAtAfter(LocalDateTime after);

    // Find sessions last used before a specific time
    List<UserSession> findByLastUsedAtBeforeAndIsActiveTrue(LocalDateTime before);

    // Find sessions by login method
    List<UserSession> findByLoginMethod(UserSession.LoginMethod loginMethod);

    // Find active sessions count for a user
    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user = :user AND s.isActive = true AND s.isRevoked = false AND s.expiresAt > CURRENT_TIMESTAMP")
    long countActiveSessionsByUser(@Param("user") User user);

    // Find sessions that need to be expired
    @Query("SELECT s FROM UserSession s WHERE s.expiresAt <= :now AND s.isActive = true")
    List<UserSession> findSessionsToExpire(@Param("now") LocalDateTime now);

    // Find sessions by user ordered by creation date
    List<UserSession> findByUserOrderByCreatedAtDesc(User user);

    // Find sessions by user ordered by last used date
    List<UserSession> findByUserOrderByLastUsedAtDesc(User user);

    // Find sessions by user ordered by creation date (ascending)
    List<UserSession> findByUserOrderByCreatedAtAsc(User user);

    // Find sessions by multiple criteria
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.sessionType = :sessionType AND s.isActive = true")
    List<UserSession> findByUserAndSessionTypeAndActive(@Param("user") User user, @Param("sessionType") UserSession.SessionType sessionType);

    // Find sessions by device fingerprint and user
    List<UserSession> findByUserAndDeviceFingerprint(User user, String deviceFingerprint);

    // Find sessions by IP address and user
    List<UserSession> findByUserAndIpAddress(User user, String ipAddress);

    // Find sessions created in a date range
    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.createdAt BETWEEN :startDate AND :endDate")
    List<UserSession> findByUserAndCreatedAtBetween(@Param("user") User user, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    // Find sessions by revoked reason
    List<UserSession> findByRevokedReason(String revokedReason);

    // Find sessions revoked by a specific user
    List<UserSession> findByRevokedBy(String revokedBy);

    // Find sessions by revoked date range
    @Query("SELECT s FROM UserSession s WHERE s.revokedAt BETWEEN :startDate AND :endDate")
    List<UserSession> findByRevokedAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
} 