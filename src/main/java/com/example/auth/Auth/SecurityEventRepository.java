package com.example.auth.Auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
    // Custom queries can be added here if needed
} 