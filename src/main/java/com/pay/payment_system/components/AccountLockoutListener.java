package com.pay.payment_system.components;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.configservice.IpService;
import com.pay.payment_system.configservice.UserSecurityService;
import com.pay.payment_system.entity.UserAccount;
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

    // LISTEN FOR SUCCESSFUL LOGINS

    @EventListener
    @Transactional
    public void onSuccess(AuthenticationSuccessEvent event) {

        String email = event.getAuthentication().getName().trim().toLowerCase();

        userSecurityService.handleSuccessfulLogin(email);

        UserAccount user = userSecurityService.handleSuccessfulLogin(email);

        HttpServletRequest request = getCurrentHttpRequest();
        if (request != null) {
            ipService.registerAccessAttempt(user, "INITIAL_LOGIN", "Login: Correct credentials", request);
            log.info("AUDIT LOG: Initial login access registered for user: {}", safe(user.getEmailCanonical()));
        }
    }

    // LISTEN FOR FAILED LOGINS

    @EventListener
    @Transactional
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String email = event.getAuthentication().getName().trim().toLowerCase();

        log.warn("FAILURE EVENT DETECTED: Propagating to CustomLoginFailureHandler for core processing: {}",safe (email));
    }

    // GETS THE CURRENT HTTP REQUEST TO EXTRACT THE IP AND BROWSER DATA

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return (attr != null) ? attr.getRequest() : null;
    }
}