/*
 * Role.java
 * Enum representing user roles and their associated permissions.
 */
package com.example.auth.User;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.auth.User.Permission.*;

/**
 * Enum representing user roles and their associated permissions.
 */
@RequiredArgsConstructor
public enum Role {
    /** Admin role with full permissions. */
    ADMIN(Set.of(
            ADMIN_READ,
            ADMIN_CREATE,
            ADMIN_UPDATE,
            ADMIN_DELETE,
            USER_CREATE,
            USER_UPDATE,
            USER_READ,
            USER_DELETE
    )),
    /** Standard user role with user-level permissions. */
    USER(Set.of(
            USER_CREATE,
            USER_UPDATE,
            USER_READ,
            USER_DELETE
    ));

    @Getter
    private final Set<Permission> permissions;

    /**
     * Returns a list of granted authorities for the role, including permissions and role name.
     * @return list of SimpleGrantedAuthority
     */
    public List<SimpleGrantedAuthority> getUserAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
