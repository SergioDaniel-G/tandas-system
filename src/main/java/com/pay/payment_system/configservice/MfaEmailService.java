package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaEmailService {

    private final JavaMailSender mailSender;

    /**
     * SENDS A SIX-DIGIT OTP CODE TO THE USER'S EMAIL ASYNCHRONOUSLY.
     */
    @Async("mailTaskExecutor")
    public void sendOtpEmailAsync(String email, String code) {

        if (log.isDebugEnabled()) {
            log.debug("---------- [DEBUG MFA CHALLENGE] ----------");
            log.debug("Target Email: {} | Generated Code: [REDACTED]", safe (email));
            log.debug("-------------------------------------------");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Security code - Litzia's Tanda");
            message.setText("Your access code is: " + code + "\n\nThis code is for one time use only.");

            mailSender.send(message);
            log.info("MFA EMAIL SUCCESS: Security token successfully dispatched to {}",safe (email));

        } catch (Exception e) {
            log.error("CRITICAL SECURITY ERROR: Failed to send MFA email to [{}]. Reason: {}", safe (email), safe (e.getMessage()));
        }
    }
}