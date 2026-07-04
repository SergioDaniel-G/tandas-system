package com.pay.payment_system.controller;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.configservice.PasswordRecoveryService;
import com.pay.payment_system.repository.UserRepository;
import com.pay.payment_system.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RegistrationController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final MessageSource messageSource;
    private final PasswordRecoveryService passwordRecoveryService;

    // RETURNS UNAUTHORIZED STATUS CODE AS A BACKSTOP ENTRYPOINT FOR MANUALLY TRIGGERED LOGIN ROUTING

    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        return ResponseEntity.status(401).build();
    }

    // REDIRECTS CLIENTS TO THE FORGOT PASSWORD HTML INTERFACE INJECTING CONTEXTUAL NOTIFICATION MESSAGES IF PRESENT

    @GetMapping("/loadForgotPassword")
    public RedirectView loadForgotPassword(@RequestParam(required = false) String msg) {
        if (msg != null) {
            log.info("Loading forgot password screen with message context");
            return new RedirectView("/forgot_password.html?msg=" + safe(msg));
        }
        log.info("Loading forgot password screen");
        return new RedirectView("/forgot_password.html");
    }

    // REDIRECTS REQUESTS TO THE SECURE PASSWORD CREATION FORM APPENDING THE TRACKING TOKEN QUERY STRING PARAMETER

    @GetMapping("/loadResetPassword")
    public RedirectView loadResetPassword(@RequestParam String token) {
        log.info("Rendering reset password form for token");
        return new RedirectView("/reset_password.html?token=" + safe(token));
    }

    // DISPATCHES USER CREDENTIAL METADATA TO THE BACKING PIPELINE TO START RECOVERY LOGIC AND BLINDS CONSUMERS FROM USER DATA STATUS

    @PostMapping("/forgotPassword")
    public ResponseEntity<?> forgotPassword(@RequestParam String email,
                                            @RequestParam String mobileNum) {

        log.info("Password recovery requested for email: {}", safe(email));

        Map<String, Object> response = passwordRecoveryService.processForgotPassword(email, mobileNum);
        String status = (String) response.remove("status");

        if ("OK".equals(status)) {
            log.info("Password recovery token generated successfully for email: {}", safe(email));
            return ResponseEntity.ok(response);
        } else {
            log.warn("Password recovery failed for email: {}. Reason status: {}", safe(email), safe(status));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    // PROCESSES SECURE OVER THE AIR PASSWORD REPLACEMENT REQUISITIONS BY COMPARING MATCHES AGAINST THE TARGET TOKEN

    @PostMapping("/changePassword")
    public ResponseEntity<?> resetPassword(@RequestParam String password,
                                           @RequestParam String cpassword,
                                           @RequestParam String token) {

        log.info("Attempting password reset execution with token");

        Map<String, Object> response = passwordRecoveryService.processResetPassword(password, cpassword, token);
        String status = (String) response.remove("status");

        if ("OK".equals(status)) {
            log.info("Password updated successfully");
            return ResponseEntity.ok(response);
        } else if ("NOT_FOUND".equals(status)) {
            log.warn("Password reset failed. Token not found or expired");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } else {
            log.warn("Password reset validation failed. Status: {}", safe(status));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}