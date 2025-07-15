/*
 * Permission.java
 * Enum representing user permissions for role-based access control.
 */
package com.ead.posgateway.User;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enum representing user permissions for role-based access control.
 */
@RequiredArgsConstructor
public enum Permission {

    /** Permission to read admin resources. */
    ADMIN_READ("ADMIN:READ"),
    /** Permission to update admin resources. */
    ADMIN_UPDATE("ADMIN:UPDATE"),
    /** Permission to create admin resources. */
    ADMIN_CREATE("ADMIN:CREATE"),
    /** Permission to delete admin resources. */
    ADMIN_DELETE("ADMIN:DELETE"),

    /** Permission to read user resources. */
    USER_READ("USER:READ"),
    /** Permission to update user resources. */
    USER_UPDATE("USER:UPDATE"),
    /** Permission to create user resources. */
    USER_CREATE("USER:CREATE"),
    /** Permission to delete user resources. */
    USER_DELETE("USER:DELETE");

    @Getter
    private final String permission;
}
