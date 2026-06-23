package com.pay.payment_system.components;

import com.pay.payment_system.configservice.IpService;
import com.pay.payment_system.configservice.UserSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Component
@RequiredArgsConstructor
public class AccountLockoutListener {

    private final IpService ipService;
    private final UserSecurityService userSecurityService;

    @EventListener
    @Transactional
    public void onSuccess(AuthenticationSuccessEvent event) {
        String email = event.getAuthentication().getName().trim().toLowerCase();
        userSecurityService.handleSuccessfulLogin(email);

        HttpServletRequest request = getCurrentHttpRequest();
        if (request != null) {
            ipService.registerAccessAttempt(email, "INITIAL_LOGIN", "Login: Correct credentials", request);
            log.info("AUDIT LOG: Initial login access registered for user: {}", email);
        }
    }

    @EventListener
    @Transactional
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String email = event.getAuthentication().getName().trim().toLowerCase();

        log.debug("AUTH FAILURE EVENT DETECTED: Propagating to CustomLoginFailureHandler for core processing: {}", email);
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return (attr != null) ? attr.getRequest() : null;
    }
}