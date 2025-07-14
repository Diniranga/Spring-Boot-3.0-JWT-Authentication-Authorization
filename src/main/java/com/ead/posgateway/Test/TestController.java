package com.ead.posgateway.Test;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
@Slf4j
public class TestController {

    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> publicEndpoint() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello from public endpoint");
        log.info("Public test endpoint accessed");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/test-rate-limit")
    public ResponseEntity<Map<String, String>> testRateLimit() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Rate limit test endpoint");
        log.info("Rate limit test endpoint accessed");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/test-https")
    public ResponseEntity<Map<String, String>> testHttps() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "HTTPS test endpoint");
        log.info("HTTPS test endpoint accessed");
        return ResponseEntity.ok(response);
    }
} 