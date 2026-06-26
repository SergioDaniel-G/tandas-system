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

    @PostMapping("/auth/validate-otp")
    @ResponseBody
    public ResponseEntity<?> validateMfa(@RequestParam String code,
                                         Authentication auth,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {

        String result = mfaProcessingService.processMfaValidation(code, auth, request, response);

        if (result == null) {
            log.error("MFA ERROR: Service returned a null status during validation.");
            return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "Authentication failed."));
        }

        if (result.equals("REDIRECT_INDEX")) {
            return ResponseEntity.ok(Map.of("status", "SUCCESS", "redirectUrl", "index.html"));
        }

        if (result.equals("STATUS_EXPIRED")) {
            return ResponseEntity.ok(Map.of("status", "EXPIRED", "message", "The verification code has expired."));
        }

        if (result.equals("REDIRECT_LOGIN")) {
            return ResponseEntity.badRequest().body(Map.of("status", "EXPIRED", "redirectUrl", "login.html?expired=true"));
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
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "WRONG_CODE",
                    "remainingAttempts", remainingAttempts
            ));
        }

        log.warn("MFA WARNING: Unknown redirection token received: {}", safe (result));
        return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "Authentication failed."));
    }

    @PostMapping("/auth/mfa/resend")
    @ResponseBody
    public ResponseEntity<?> resendMfa(Authentication auth,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        try {
            String result = mfaProcessingService.processMfaResend(auth, request, response);

            return switch (result) {
                case "RESEND_SUCCESS" ->
                        ResponseEntity.ok(Map.of("status", "SUCCESS", "message", "Fresh code dispatched."));

                case "RESEND_BLOCKED" ->
                        ResponseEntity.status(HttpStatus.LOCKED).body(Map.of("status", "BLOCKED", "message", "Locked."));

                default ->
                        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "UNAUTHORIZED", "message", "Expired session."));
            };
        } catch (Exception e) {
            log.error("MFA ERROR: Internal error during resend process.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "ERROR", "message", "Internal error."));
        }
    }
}
