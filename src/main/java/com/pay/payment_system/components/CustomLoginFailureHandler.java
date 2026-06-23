package com.pay.payment_system.components;

import com.pay.payment_system.configservice.LoginLockoutEvaluationService;
import com.pay.payment_system.configservice.LoginLockoutEvaluationService.LockoutResult;
import com.pay.payment_system.configservice.AuditLogService;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLoginFailureHandler implements AuthenticationFailureHandler {

    private final LoginLockoutEvaluationService lockoutEvaluationService;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String email = request.getParameter("email");
        String ip = request.getRemoteAddr();

        if (email == null) {
            email = (String) request.getAttribute("LOCKOUT_EMAIL");
        }

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        if (email == null || email.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().print("{\"status\":\"ERROR\",\"message\":\"Email parameter is required.\"}");
            return;
        }

        String cleanEmail = email.trim().toLowerCase();

        LockoutResult result = (LockoutResult) request.getAttribute("ALREADY_COUNTED_ATTEMPT");

        if (result == null) {
            result = lockoutEvaluationService.registerFailedAttempt(cleanEmail);
            request.setAttribute("ALREADY_COUNTED_ATTEMPT", result);
        } else {
            log.debug("DUPLICATE DETECTED: Skipping Redis increment.");
        }

        if (result != null && (result.dynamicLockTriggered() || result.currentAttempts() >= 5)) {
            sendLockedResponse(response, cleanEmail, ip, result);
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().print("{\"status\": \"ERROR\", \"message\": \"Password or email incorrect.\"}");
    }

    private void sendLockedResponse(HttpServletResponse response, String cleanEmail, String ip, LockoutResult result) throws IOException {
        long remainingSeconds = lockoutEvaluationService.getRemainingLockoutTimeInSeconds(cleanEmail);

        if (remainingSeconds <= 0 || (result != null && result.lockoutCount() > 4)) {
            remainingSeconds = 86400;
        }

        if (result != null && result.dynamicLockTriggered()) {
            String customDescription = null;

            if (result.lockoutCount() > 4) {
                int extraRequests = result.lockoutCount() - 4;
                if (extraRequests == 0 || extraRequests % 100 == 0) {
                    customDescription = String.format(
                            "Maximum login attempts exceeded. Account frozen permanently (24h jail). Total mitigated attack volume: %d requests.",
                            extraRequests
                    );
                }
            } else {
                customDescription = String.format(
                        "Maximum login attempts exceeded. Locked temporally for %dm (Lockout #%d)",
                        result.lockoutMinutes(),
                        result.lockoutCount()
                );
            }

            if (customDescription != null) {
                auditLogService.logCritical(cleanEmail, ip, "ACCOUNT_LOCKED", customDescription);
            }
        }

        response.setStatus(423);
        response.getWriter().print(String.format("""
    {
      "status": "LOCKED",
      "message": "Too many failed attempts. This account is temporarily disabled for security.",
      "retryAfterSeconds": %d
    }
    """, remainingSeconds));
    }
}