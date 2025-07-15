/*
 * User.java
 * Entity representing an application user with authentication and session details.
 */
package com.ead.posgateway.User;

import com.ead.posgateway.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

/**
 * Entity representing an application user with authentication and session details.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {

    /** Primary key. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    
    /** User's first name. */
    @Column(nullable = false)
    private String firstName;
    
    /** User's last name. */
    @Column(nullable = false)
    private String lastName;
    
    /** User's email address (unique). */
    @Column(unique = true, nullable = false)
    private String email;
    
    /** Encoded password. */
    @Column(nullable = false)
    private String password;

    /** User's role. */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    /** Tokens associated with the user. */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Token> tokens;

    // Account security fields
    /** Number of failed login attempts. */
    private int failedLoginAttempts;
    /** Whether the account is locked. */
    private boolean accountLocked;
    /** Timestamp when the account was locked. */
    private LocalDateTime lockTime;
    /** Timestamp of last password change. */
    private LocalDateTime lastPasswordChange;

    // Session management fields
    /** Number of active sessions. */
    private int activeSessions;
    /** Maximum allowed concurrent sessions. */
    private int maxConcurrentSessions;
    /** Timestamp of last login. */
    private LocalDateTime lastLoginTime;
    /** IP address of last login. */
    private String lastLoginIp;

    /**
     * Returns the authorities granted to the user.
     * @return collection of granted authorities
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return role.getUserAuthorities();
    }

    /**
     * Returns the encoded password.
     * @return password string
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Returns the username (email).
     * @return email string
     */
    @Override
    public String getUsername() {
        return email;
    }

    /**
     * Indicates whether the user's account has expired.
     * @return true if account is non-expired
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked.
     * @return true if account is non-locked
     */
    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    /**
     * Indicates whether the user's credentials (password) has expired.
     * @return true if credentials are non-expired
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is enabled or disabled.
     * @return true if enabled
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
