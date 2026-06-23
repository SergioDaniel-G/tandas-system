package com.pay.payment_system.service;

import com.pay.payment_system.entity.UserTrustedIp;
import com.pay.payment_system.repository.UserTrustedIpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserIpServiceImpl implements UserIpService {

    private final UserTrustedIpRepository userTrustedIpRepository;

    @Override
    @Transactional(readOnly = true)
    public List<UserTrustedIp> findAllUserIps() {
        log.info("SECURITY SERVICE: Fetching all active trusted IP records.");
        return userTrustedIpRepository.findAll();
    }

    @Override
    @Transactional
    public void addOrUpdateTrustedIp(String email, String ipAddress) {

        if (email == null || ipAddress == null || email.isBlank() || ipAddress.isBlank()) {
            log.error("SECURITY ERROR: Cannot register an empty email or IP address.");
            return;
        }

        String formattedEmail = email.trim().toLowerCase();
        String formattedIp = ipAddress.trim();

        log.info("SECURITY SERVICE: Registering or updating trusted IP [{}] for user [{}]", formattedIp, formattedEmail);

        userTrustedIpRepository.findByEmailAndIpAddress(formattedEmail, formattedIp)
                .ifPresentOrElse(
                        existingIp -> {
                            existingIp.setLastUsedAt(LocalDateTime.now());
                            userTrustedIpRepository.save(existingIp);
                            log.info("SECURITY AUDIT: Updated last used date for known IP.");
                        },
                        () -> {
                            UserTrustedIp newTrustedIp = UserTrustedIp.builder()
                                    .email(formattedEmail)
                                    .ipAddress(formattedIp)
                                    .lastUsedAt(LocalDateTime.now())
                                    .build();
                            userTrustedIpRepository.save(newTrustedIp);
                            log.info("SECURITY AUDIT: Successfully added new IP to trusted list.");
                        }
                );
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isIpTrusted(String email, String ipAddress) {
        if (email == null || ipAddress == null || email.isBlank() || ipAddress.isBlank()) {
            return false;
        }

        String formattedEmail = email.trim().toLowerCase();
        String formattedIp = ipAddress.trim();
        boolean trusted = userTrustedIpRepository.existsByEmailAndIpAddress(formattedEmail, formattedIp);

        log.info("SECURITY CHECK: Is IP [{}] trusted for user [{}]? -> {}", formattedIp, formattedEmail, trusted);
        return trusted;
    }
}