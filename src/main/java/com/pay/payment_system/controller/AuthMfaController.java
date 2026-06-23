package com.pay.payment_system.controller;

import com.pay.payment_system.configservice.MfaProcessingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

        return switch (result) {

            case "REDIRECT_INDEX" ->
                    ResponseEntity.ok(Map.of("status", "SUCCESS", "redirectUrl", "index.html"));

            case "REDIRECT_LOGIN" ->
                    ResponseEntity.badRequest().body(Map.of("status", "EXPIRED", "redirectUrl", "login.html?expired=true"));

            case "REDIRECT_BLOCKED" ->
                    ResponseEntity.badRequest().body(Map.of("status", "BLOCKED", "redirectUrl", "login.html?error=locked"));

            default -> {
                if (result.startsWith("REDIRECT_REMAINING_")) {
                    String remainingAttempts = result.replace("REDIRECT_REMAINING_", "");
                    yield ResponseEntity.badRequest().body(Map.of(
                            "status", "WRONG_CODE",
                            "remainingAttempts", remainingAttempts
                    ));
                }

                log.warn("MFA WARNING: Unknown redirection token received: {}", result);
                yield ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "Authentication failed."));
            }
        };
    }
}