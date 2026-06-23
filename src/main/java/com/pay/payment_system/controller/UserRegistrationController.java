package com.pay.payment_system.controller;

import com.pay.payment_system.DTO.UserRegistrationDto;
import com.pay.payment_system.configservice.RecaptchaService;
import com.pay.payment_system.configservice.UserRegistrationProcessingService;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.context.i18n.LocaleContextHolder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Profile("dev")
public class UserRegistrationController {

    @Value("${google.recaptcha.site}")
    private String recaptchaSiteKey;

    private final UserService userService;
    private final RecaptchaService recaptchaService;
    private final MessageSource messageSource;
    private final UserRegistrationProcessingService userRegistrationProcessingService;

    @GetMapping("/recaptcha-key")
    public ResponseEntity<Map<String, String>> getRecaptchaKey() {
        Map<String, String> response = new HashMap<>();
        response.put("siteKey", recaptchaSiteKey);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/list", produces = org.springframework.http.MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {
        log.info("Fetching all registered users (DEV MODE)");

        List<UserAccount> users = userService.findAllUsers();

        List<Map<String, Object>> flatUsers = users.stream().map(user -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", user.getId());
            map.put("name", user.getName() != null ? user.getName() : "Signed-up user");
            map.put("email", user.getEmail());
            if (user.getSecurity() != null) {
                map.put("accountNonLocked", user.getSecurity().isAccountNonLocked());
                map.put("failedAttempts", user.getSecurity().getFailedAttempts());
            } else {
                map.put("accountNonLocked", true);
                map.put("failedAttempts", 0);
            }
            return map;
        }).toList();

        return ResponseEntity.ok(flatUsers);
    }

    @PostMapping("/register")
    public ResponseEntity<?> userAccountRegister(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                                 BindingResult result,
                                                 @RequestHeader(name = "g-recaptcha-response", required = false) String captchaResponse) {

        Map<String, Object> response = new HashMap<>();

        if (captchaResponse == null || !recaptchaService.validate(captchaResponse)) {
            log.warn("REGISTRATION: CAPTCHA validation failed for incoming request.");
            String msg = messageSource.getMessage("registration.captcha.failed", null, LocaleContextHolder.getLocale());
            response.put("status", "error");
            response.put("message", msg);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        Map<String, Object> businessResult = userRegistrationProcessingService.processUserRegistration(userRegistrationDto, result);
        String httpStatus = (String) businessResult.remove("httpStatus");

        if ("CREATED".equals(httpStatus)) {
            return ResponseEntity.status(HttpStatus.CREATED).body(businessResult);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(businessResult);
        }
    }

    public void sendAccountAlreadyExistsAlert(String email) {
        userRegistrationProcessingService.sendAccountAlreadyExistsAlert(email);
    }
}