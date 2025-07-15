/*
 * UserRepository.java
 * Repository interface for managing User entities and custom queries.
 */
package com.ead.posgateway.User;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository interface for managing User entities and custom queries.
 */
public interface UserRepository extends JpaRepository<User, Integer> {

    /**
     * Find a user by email address.
     * @param email User email
     * @return Optional containing the User if found
     */
    Optional<User> findByEmail(String email);
}
