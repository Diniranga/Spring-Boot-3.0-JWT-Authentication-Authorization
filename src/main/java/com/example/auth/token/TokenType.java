/*
 * TokenType.java
 * Enum representing the type of authentication token.
 */
package com.example.auth.token;

/**
 * Enum representing the type of authentication token.
 */
public enum TokenType {
    /** Bearer token (access token). */
    BEARER,
    /** Refresh token. */
    REFRESH
}
