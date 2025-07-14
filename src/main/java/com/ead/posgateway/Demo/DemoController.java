package com.ead.posgateway.Demo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/demo")
@RequiredArgsConstructor
@Slf4j
public class DemoController {

    @GetMapping
    @PreAuthorize("hasAuthority('USER:READ')")
    public ResponseEntity<Map<String, String>> demo() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello from secured endpoint");
        log.info("Demo endpoint accessed");
        return ResponseEntity.ok(response);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ADMIN:READ')")
    public ResponseEntity<Map<String, String>> demoPost() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello from admin secured endpoint");
        log.info("Admin demo endpoint accessed");
        return ResponseEntity.ok(response);
    }
}
