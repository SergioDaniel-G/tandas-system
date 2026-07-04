package com.pay.payment_system.components;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import java.util.Optional;

@Component("auditorProvider")
public class SecurityAuditor implements AuditorAware<String> {

    // RESOLVES THE IDENTITY OF THE CURRENT LOGGED-IN OPERATOR OR PROCESS FOR DATA AUDITING PURPOSES

    @Override
    public Optional<String> getCurrentAuditor() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()
                || auth.getPrincipal().equals("anonymousUser")) {
            return Optional.of("SYSTEM");
        }
        return Optional.of(auth.getName());
    }
}
