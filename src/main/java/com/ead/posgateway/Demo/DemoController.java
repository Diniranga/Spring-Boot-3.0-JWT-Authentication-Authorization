/*
 * DemoController.java
 * REST controller for demo endpoints with security annotations.
 */
package com.ead.posgateway.Demo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for demo endpoints to showcase secured access.
 */
@RestController
@RequestMapping("/demo")
@RequiredArgsConstructor
@Slf4j
public class DemoController {

    /**
     * Demo endpoint accessible to users with USER:READ authority.
     * @return ResponseEntity with demo message
     */
    @GetMapping("/get")
    @PreAuthorize("hasAuthority('USER:READ')")
    public ResponseEntity<Map<String, String>> demo() {
        final Map<String, String> response = new HashMap<>();
        response.put("message", "Hello from secured endpoint");
        log.info("Demo endpoint accessed");
        return ResponseEntity.ok(response);
    }

    /**
     * Demo endpoint accessible to users with ADMIN:READ authority.
     * @return ResponseEntity with admin demo message
     */
    @PostMapping("/post")
    @PreAuthorize("hasAuthority('ADMIN:READ')")
    public ResponseEntity<Map<String, String>> demoPost() {
        final Map<String, String> response = new HashMap<>();
        response.put("message", "Hello from admin secured endpoint");
        log.info("Admin demo endpoint accessed");
        return ResponseEntity.ok(response);
    }
}
