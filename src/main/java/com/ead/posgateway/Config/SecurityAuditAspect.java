/*
 * SecurityAuditAspect.java
 *
 * Aspect for auditing security-related method invocations, especially those protected by @PreAuthorize.
 */
package com.ead.posgateway.Config;

import java.time.LocalDateTime;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Aspect for auditing security-related method invocations, especially those protected by @PreAuthorize.
 */
@Aspect
@Component
@Slf4j
public class SecurityAuditAspect {

    /**
     * Audits methods annotated with @PreAuthorize.
     * @param joinPoint the join point
     * @return the result of the method invocation
     * @throws Throwable if the method throws
     */
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