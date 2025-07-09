package com.ead.posgateway.Config;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Aspect
@Component
@Slf4j
public class SecurityAuditAspect {

    @Around("@annotation(org.springframework.security.access.prepost.PreAuthorize)")
    public Object auditSecuredMethods(ProceedingJoinPoint joinPoint) throws Throwable {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        
        log.info("SECURITY_AUDIT: Method {} in {} accessed by user: {} at {}", 
                methodName, className, 
                auth != null ? auth.getName() : "anonymous", 
                LocalDateTime.now());
        
        try {
            Object result = joinPoint.proceed();
            log.info("SECURITY_AUDIT: Method {} in {} completed successfully for user: {}", 
                    methodName, className, 
                    auth != null ? auth.getName() : "anonymous");
            return result;
        } catch (Exception e) {
            log.error("SECURITY_AUDIT: Method {} in {} failed for user: {} with error: {}", 
                    methodName, className, 
                    auth != null ? auth.getName() : "anonymous", 
                    e.getMessage());
            throw e;
        }
    }
} 