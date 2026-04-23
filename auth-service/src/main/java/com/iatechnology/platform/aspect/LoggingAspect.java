package com.iatechnology.platform.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    private String getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !authentication.getName().equals("anonymousUser")) {
            return authentication.getName();
        }
        return "System/Anonymous";
    }

    @AfterReturning(pointcut = "execution(* com.iatechnology.platform.service.*.create*(..)) || execution(* com.iatechnology.platform.service.*.save*(..))", returning = "result")
    public void logCreation(JoinPoint joinPoint, Object result) {
        log.info("Action [CREATE] exécutée dans {} par User '{}' - Succès", joinPoint.getSignature().getDeclaringType().getSimpleName(), getCurrentUser());
    }

    @AfterReturning(pointcut = "execution(* com.iatechnology.platform.service.*.update*(..))", returning = "result")
    public void logUpdate(JoinPoint joinPoint, Object result) {
        log.info("Action [UPDATE] exécutée dans {} par User '{}' - Succès", joinPoint.getSignature().getDeclaringType().getSimpleName(), getCurrentUser());
    }

    @AfterReturning("execution(* com.iatechnology.platform.service.*.delete*(..))")
    public void logDeletion(JoinPoint joinPoint) {
        log.info("Action [DELETE] exécutée dans {} par User '{}' - Succès", joinPoint.getSignature().getDeclaringType().getSimpleName(), getCurrentUser());
    }
    
    @AfterReturning(pointcut = "execution(* com.iatechnology.platform.controller.AuthController.authenticate*(..))")
    public void logLogin(JoinPoint joinPoint) {
        log.info("Action [LOGIN] exécutée. (User Authentication Requested)");
    }
}
