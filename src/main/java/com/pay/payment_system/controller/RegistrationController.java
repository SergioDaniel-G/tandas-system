package com.pay.payment_system.controller;

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

    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        return ResponseEntity.status(401).build();
    }

    /*
     * DISPLAYS THE INITIAL PASSWORD RECOVERY SCREEN
     */
    @GetMapping("/loadForgotPassword")
    public RedirectView loadForgotPassword(@RequestParam(required = false) String msg) {
        if (msg != null) {
            return new RedirectView("/forgot_password.html?msg=" + msg);
        }
        return new RedirectView("/forgot_password.html");
    }

    /* * RENDERS THE FORM TO DEFINE A NEW PASSWORD
     */
    @GetMapping("/loadResetPassword")
    public RedirectView loadResetPassword(@RequestParam String token) {
        return new RedirectView("/reset_password.html?token=" + token);
    }

    /**
     * VERIFIES USER CREDENTIALS TO AUTHORIZE A PASSWORD RESET.
     */
    @PostMapping("/forgotPassword")
    public ResponseEntity<?> forgotPassword(@RequestParam String email,
                                            @RequestParam String mobileNum) {

        Map<String, Object> response = passwordRecoveryService.processForgotPassword(email, mobileNum);
        String status = (String) response.remove("status");

        if ("OK".equals(status)) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    /* * ENCRYPTS AND UPDATES THE USER´S PASSWORD
     */
    @PostMapping("/changePassword")
    public ResponseEntity<?> resetPassword(@RequestParam String password,
                                           @RequestParam String cpassword,
                                           @RequestParam String token) {

        Map<String, Object> response = passwordRecoveryService.processResetPassword(password, cpassword, token);
        String status = (String) response.remove("status");

        if ("OK".equals(status)) {
            return ResponseEntity.ok(response);
        } else if ("NOT_FOUND".equals(status)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}