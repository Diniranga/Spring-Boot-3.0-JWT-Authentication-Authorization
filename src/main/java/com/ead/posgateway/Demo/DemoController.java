package com.ead.posgateway.Demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
@PreAuthorize("hasAnyRole('ADMIN','USER')")
public class DemoController {

    @GetMapping("/get")
    @PreAuthorize("hasAnyAuthority('ADMIN:READ','USER:READ')")
    public ResponseEntity<String> sayHelloGet(){
        return ResponseEntity.ok("GET: Hello from secured endpoint");
    }

    @PostMapping("/post")
    @PreAuthorize("hasAnyAuthority('ADMIN:CREATE')")
    public ResponseEntity<String> sayHelloPost(){
        return ResponseEntity.ok("POST: Hello from secured endpoint");
    }
}
