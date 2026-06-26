package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.components.RequestDeviceParser;
import com.pay.payment_system.entity.UserTrustedIp;
import com.pay.payment_system.repository.UserTrustedIpRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class IpService {

    private final UserTrustedIpRepository userTrustedIpRepository;
    private final RequestDeviceParser requestDeviceParser;

    public boolean isIpKnown(String email, String ip) {
        return userTrustedIpRepository.existsByEmailAndIpAddress(email, ip);
    }

    @Transactional
    public void registerAccessAttempt(String email, String status, String reason, HttpServletRequest request) {

        String userAgent = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();

        boolean isBot = requestDeviceParser.detectBot(userAgent);
        String device = requestDeviceParser.determineDeviceType(userAgent);
        String risk = "LOW";
        if (isBot) {
            risk = "HIGH";
        } else if ("FAIL".equals(status) || "FAIL_PASS".equals(status)) {
            risk = "MEDIUM";
        }

        log.info("SECURITY_AUDIT | Email: {} | IP: {} | Status: {} | Risk: {} | Bot: {} | Device: {} | Reason: {} | UA: {}",
                safe (email), safe (ipAddress), status, risk, isBot, device, (reason != null ? safe (reason) : "NONE"), safe (userAgent));

        if ("SUCCESSFUL".equals(status) && !isBot) {
            saveOrUpdateTrustedIp(email, ipAddress);
        }
    }

    private void saveOrUpdateTrustedIp(String email, String ipAddress) {
        userTrustedIpRepository.findByEmailAndIpAddress(email, ipAddress)
                .ifPresentOrElse(
                        trustedIp -> {
                            trustedIp.setLastUsedAt(LocalDateTime.now());
                            userTrustedIpRepository.save(trustedIp);
                            log.debug("Trusted IP timestamp updated for user: {}", safe (email));
                        },
                        () -> {

                            UserTrustedIp newTrustedIp = UserTrustedIp.builder()
                                    .email(email)
                                    .ipAddress(ipAddress)
                                    .lastUsedAt(LocalDateTime.now())
                                    .build();
                            userTrustedIpRepository.save(newTrustedIp);
                            log.info("NEW TRUSTED IP REGISTERED | User: {} | IP: {}", safe (email), safe (ipAddress));
                        }
                );
    }
}