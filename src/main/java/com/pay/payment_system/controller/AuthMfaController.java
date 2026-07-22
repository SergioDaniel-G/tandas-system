package com.pay.payment_system.controller;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.configservice.MfaProcessingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.Map;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthMfaController {

    private final MfaProcessingService mfaProcessingService;

    @GetMapping("/verify-code")
    public String showMfaPage() {
        return "redirect:/mfa-page.html";
    }

    //JUST FOR INEXISTENT TOKEN

    /*@GetMapping("/test/remove-mfa-token")
    @ResponseBody
    public String removeMfaToken(HttpSession session) {

        if (session != null) {
            session.removeAttribute("MFA_CRYPTO_TOKEN");
            return "MFA token removed";
        }

        return "No session";
    }*/

    @PostMapping("/auth/validate-otp")
    @ResponseBody
    public ResponseEntity<?> validateMfa(@RequestParam String code,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        try {
            org.springframework.security.core.Authentication auth =
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();

            // DELETE FOR PRODUCTION
            // log.info("MFA DEBUG AUTH: {}", auth);
            // log.info("MFA DEBUG SESSION ID: {}", request.getSession(false) != null
            //        ? request.getSession(false).getId()
            //        : "NO SESSION");

            //log.info("MFA DEBUG CODE RECEIVED: {}", safe(code));

            log.info("MFA AUTH DEBUG USER: {}", auth != null ? auth.getName() : "NULL");
            log.info("MFA AUTH DEBUG AUTHORITIES: {}", auth != null ? auth.getAuthorities() : "NULL");

            String result = mfaProcessingService.processMfaValidation(code, auth, request, response);

            if (result == null) {
                log.error("MFA ERROR: Service returned a null status during validation.");
                return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "Authentication failed."));
            }

            if (result.equals("REDIRECT_INDEX")) {
                request.changeSessionId();
                return ResponseEntity.ok(Map.of("status", "SUCCESS", "redirectUrl", "index.html"));
            }

            if (result.equals("STATUS_EXPIRED")) {
                return ResponseEntity.ok(Map.of("status", "EXPIRED", "message", "The verification code has expired."));
            }

            if (result.equals("REDIRECT_LOGIN")) {
                return ResponseEntity.badRequest().body(Map.of("status", "EXPIRED", "redirectUrl", "login.html?expired=true"));
            }

            if (result.startsWith("REDIRECT_DELAYED_")) {
                String secondsStr = result.replace("REDIRECT_DELAYED_", "");
                long delaySeconds;
                try {
                    delaySeconds = Long.parseLong(secondsStr);
                } catch (NumberFormatException e) {
                    delaySeconds = 5;
                }

                String message;

                if (delaySeconds < 60) {
                    message = "Too many attempts. Please wait " + delaySeconds + " seconds.";
                } else {
                    long minutes = delaySeconds / 60;
                    message = "Too many attempts. Please wait " + minutes + " minutes.";
                }

                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
                        "status", "DELAYED",
                        "delaySeconds", delaySeconds,
                        "message", message
                ));
            }

            if (result.startsWith("REDIRECT_BLOCKED_")) {
                String secondsStr = result.replace("REDIRECT_BLOCKED_", "");
                long lockDurationSeconds;
                try {
                    lockDurationSeconds = Long.parseLong(secondsStr);
                } catch (NumberFormatException e) {
                    lockDurationSeconds = 900;
                }

                return ResponseEntity.status(HttpStatus.LOCKED).body(Map.of(
                        "status", "BLOCKED",
                        "lockDurationSeconds", lockDurationSeconds,
                        "message", "Locked due to consecutive failed OTP attempts."
                ));
            }

            if (result.startsWith("REDIRECT_REMAINING_")) {
                String remainingAttempts = result.replace("REDIRECT_REMAINING_", "");

                return ResponseEntity.ok(Map.of(
                        "status", "WRONG_CODE",
                        "remainingAttempts", remainingAttempts
                ));
            }

            log.warn("MFA WARNING: Unknown redirection token received: {}", safe(result));
            return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "Authentication failed."));

        } catch (Exception e) {
            log.error("CRITICAL EXCEPTION IN MFA CONTROLLER: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", "ERROR",
                    "message", "Internal server error: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/auth/mfa/resend")
    @ResponseBody
    public ResponseEntity<?> resendMfa(Authentication auth,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        try {
            String result = mfaProcessingService.processMfaResend(auth, request, response);

            if (result.equals("RESEND_SUCCESS")) {
                return ResponseEntity.ok(Map.of(
                        "status", "SUCCESS",
                        "message", "Fresh code dispatched.",
                        "nextCooldownSeconds", 60,
                        "otpExpiresInSeconds", 300
                ));
            }

            if (result.equals("RESEND_BLOCKED")) {
                return ResponseEntity.status(HttpStatus.LOCKED).body(Map.of(
                        "status", "BLOCKED",
                        "message", "Too many resend requests. Account locked for 15 minutes.",
                        "lockDurationSeconds", 900
                ));
            }

            if (result.equals("RESEND_DAILY_BLOCKED")) {
                return ResponseEntity.status(HttpStatus.LOCKED).body(Map.of(
                        "status", "BLOCKED",
                        "message", "Daily resend limit exceeded. Account locked for 24 hours.",
                        "lockDurationSeconds", 86400
                ));
            }

            // CAPTURES THE PROGRESSIVE DELAY CALCULATED BY REDIS IN THE SERVICE

            if (result.startsWith("RESEND_DELAYED_")) {
                String secondsStr = result.replace("RESEND_DELAYED_", "");
                long delaySeconds;
                try {
                    delaySeconds = Long.parseLong(secondsStr);
                } catch (NumberFormatException e) {
                    delaySeconds = 60;
                }
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
                        "status", "DELAYED",
                        "delaySeconds", delaySeconds,
                        "message", "Please wait before requesting a new code."
                ));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "UNAUTHORIZED", "message", "Expired session."));

        } catch (Exception e) {
            log.error("MFA ERROR: Internal error during resend process.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "ERROR", "message", "Internal error."));
        }
    }
}