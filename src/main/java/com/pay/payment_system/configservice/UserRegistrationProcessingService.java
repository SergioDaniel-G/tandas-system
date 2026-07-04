package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.DTO.UserRegistrationDto;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistrationProcessingService {

    private final UserService userService;
    private final JavaMailSender mailSender;
    private final MessageSource messageSource;
    private final PasswordEncoder passwordEncoder;

    @Qualifier("mailTaskExecutor")
    private final Executor mailTaskExecutor;

    // EVALUATES REGISTRATION DATA, NORMALIZES INPUTS, VALIDATES FIELD ERRORS, AND MASKS RESIDUAL DUPLICATIONS FOR ENHANCED PRIVACY

    public Map<String, Object> processUserRegistration(UserRegistrationDto userRegistrationDto, BindingResult result) {
        Map<String, Object> response = new HashMap<>();

        if (userRegistrationDto != null) {
            userRegistrationDto.normalizeData();
        }

        if (result.hasErrors()) {
            log.warn("REGISTRATION: the result contains validation errors.");

            StringBuilder compiledMessage = new StringBuilder("Please correct the following fields:\n");
            for (org.springframework.validation.FieldError err : result.getFieldErrors()) {
                compiledMessage.append("\n• ").append(err.getDefaultMessage());
            }

            response.put("status", "error");
            response.put("message", compiledMessage.toString());
            response.put("httpStatus", "BAD_REQUEST");
            return response;
        }

        if (userRegistrationDto.getEmail() == null || userRegistrationDto.getEmail().trim().isEmpty()) {
            response.put("status", "error");
            response.put("message", "Email address is required.");
            response.put("httpStatus", "BAD_REQUEST");
            return response;
        }

        String canonicalEmail = userRegistrationDto.getCanonicalEmailForUniqueness();

        UserAccount accountExist = userService.findByCanonicalEmail(canonicalEmail);

        if (accountExist != null) {
            log.info("REGISTRATION: Canonical Email '{}' already exists. Masking response for security.", safe(canonicalEmail));

            passwordEncoder.encode(userRegistrationDto.getPassword());

            sendAccountAlreadyExistsAlert(userRegistrationDto.getEmail());

            response.put("status", "success");
            response.put("message", "User registered successfully!");
            response.put("httpStatus", "CREATED");
            return response;
        }

        userService.save(userRegistrationDto, canonicalEmail);
        log.info("REGISTRATION SUCCESS: New user registered with email: {}", safe (userRegistrationDto.getEmail()));

        response.put("status", "success");
        response.put("message", "User registered successfully!");
        response.put("httpStatus", "CREATED");
        return response;
    }

    // DISPATCHES AN ASYNCHRONOUS OUTBOUND SECURITY ALERT NOTIFICATION WHEN A DUPLICATE ENTRY IS DETECTED ON SYSTEM CHANNELS

    public void sendAccountAlreadyExistsAlert(String email) {

        CompletableFuture.runAsync(() -> {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);

            String subject = messageSource.getMessage("registration.mail.subject", null, "Security Alert: Account Already Exists", LocaleContextHolder.getLocale());
            message.setSubject(subject);

            String content = "Hello,\n\n" +
                    "We are sending you this email because someone attempted to create a new account using your email address.\n\n" +
                    "Your account remains secure, and no changes have been made to your password or personal data.\n\n" +
                    "Sincerely.\n\n" +
                    "Litzia's Tanda,\n" +
                    "The Support Team.";

            message.setText(content);

            try {
                mailSender.send(message);
                log.info("REGISTRATION SECURITY: Alert email sent successfully to: {}", safe (email));
            } catch (Exception e) {
                log.error("REGISTRATION SECURITY ERROR: Failed to send alert email: {}", safe (e.getMessage()));
            }
        }, mailTaskExecutor);
    }
}