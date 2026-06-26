package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@Slf4j
@Service
@RequiredArgsConstructor
public class SmsService {

    @Value("${twilio.account.sid}")
    private String accountSid;

    @Value("${twilio.auth.token}")
    private String authToken;

    @Value("${twilio.phone.number}")
    private String twilioPhoneNumber;

    @Value("${twilio.phone.destination}")
    private String destinationPhone;

    @Qualifier("mailTaskExecutor")
    private final Executor mailTaskExecutor;

    /**
     * VALIDATES CONFIGURATION ON STARTUP AND INITIALIZES THE TWILIO SDK.
     */
    @PostConstruct
    public void initTwilio() {
        if (accountSid == null || accountSid.isBlank() ||
                authToken == null || authToken.isBlank() ||
                twilioPhoneNumber == null || twilioPhoneNumber.isBlank() ||
                destinationPhone == null || destinationPhone.isBlank()) {

            throw new IllegalStateException("CRITICAL: Incomplete Twilio configuration in properties or environment variables.");
        }

        Twilio.init(accountSid, authToken);
        log.info("TWILIO SDK: Initialized successfully with Account SID.");
    }

    /**
     * SENDS AN OUTBOUND SMS ALERT.
     */
    public void sendSmsAlert(String textMessage) {

        CompletableFuture.runAsync(() -> {
            try {
                Message message = Message.creator(
                        new PhoneNumber(destinationPhone),
                        new PhoneNumber(twilioPhoneNumber),
                        textMessage
                ).create();

                log.info("TWILIO SMS SUCCESS: Alert dispatched to master phone. SID: {}", message.getSid());
            } catch (Exception e) {
                log.error("TWILIO SMS ERROR: Failed to deliver message. Reason: {}", safe (e.getMessage()));
            }
        }, mailTaskExecutor);
    }
}