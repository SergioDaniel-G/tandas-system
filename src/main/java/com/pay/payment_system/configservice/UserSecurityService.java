package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserSecurityService {

    private final UserRepository userRepository;
    private final MfaEmailService mfaEmailService;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.security.mfa-secret}")
    private String secretKey;

    @Transactional
    public UserAccount handleSuccessfulLogin(String email) {
        UserAccount user = userRepository.findByEmail(email);
        if (user != null && user.getSecurity() != null) {
            UserSecurity security = user.getSecurity();
            if (security.getFailedAttempts() > 0) {
                security.resetFailedAttempts();
                log.info("LOGIN SUCCESSFUL: ATTEMPTS RESET FOR USER: {}", email);
            }
            security.updateLastLogin();
            log.info("USER METADATA UPDATED: LAST LOGIN DATE RECORDED FOR: {}", email);
        }
        return user;
    }

    @Transactional
    public UserSecurity handleFailedLoginAttempt(UserAccount user, String email) {
        UserSecurity security = user.getSecurity();
        if (security == null) {
            log.error("SECURITY ENTITY NOT FOUND FOR USER: {}", email);
            return null;
        }

        if (security.isBlocked()) {
            log.error("ACCOUNT LOCKED: {}", email);
            return null;
        }

        security.increaseFailedAttempts();
        return security;
    }

    public String generateAndSendOtp(Long userId, String email) {
        int codeInt = 100000 + secureRandom.nextInt(900000);
        String otp = String.valueOf(codeInt);

        long expiryTime = Instant.now().toEpochMilli() + (8 * 60 * 1000);

        mfaEmailService.sendOtpEmailAsync(email, otp);

        String hash = generateHash(userId, otp, expiryTime);
        return hash + "." + expiryTime;
    }

    /**
     * VALIDATES THE OTP MATHEMATICALLY AND PROTECTS AGAINST BRUTE FORCE
     */

    @Transactional
    public boolean validateOtp(UserAccount userAccount, String inputOtp, String cryptoToken) {
        try {
            String[] parts = cryptoToken.split("\\.");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid token format.");
            }

            String clientHash = parts[0];
            long expiryTime = Long.parseLong(parts[1]);

            if (Instant.now().toEpochMilli() > expiryTime) {
                throw new RuntimeException("MFA_EXPIRED: The OTP code has expired.");
            }

            UserSecurity security = userAccount.getSecurity();
            if (security.getOtpFailedAttempts() >= 3) {
                log.warn("MFA BRUTE FORCE BLOCK: Maximum OTP attempts exceeded for user: {}", userAccount.getEmail());
                throw new RuntimeException("MFA_BLOCKED: Maximum attempts exceeded. Please login again.");
            }

            String serverHash = generateHash(userAccount.getId(), inputOtp, expiryTime);

            boolean isHashValid = MessageDigest.isEqual(
                    serverHash.getBytes(StandardCharsets.UTF_8),
                    clientHash.getBytes(StandardCharsets.UTF_8)
            );

            if (isHashValid) {
                security.setOtpFailedAttempts(0);
                log.info("MFA SUCCESSFUL: OTP validated for user: {}", userAccount.getEmail());
                return true;
            } else {

                int attempts = security.getOtpFailedAttempts() + 1;
                security.setOtpFailedAttempts(attempts);
                log.warn("MFA FAILURE: Invalid OTP code entered. Attempt {}/3 for user: {}", attempts, userAccount.getEmail());
                return false;
            }

        } catch (RuntimeException e) {
            if (e.getMessage() != null && (e.getMessage().startsWith("MFA_EXPIRED") || e.getMessage().startsWith("MFA_BLOCKED"))) {
                throw e;
            }
            throw new RuntimeException("MFA_ERROR: Error in token structure.");
        } catch (Exception e) {
            throw new RuntimeException("MFA_ERROR: Token externally altered or invalid.");
        }
    }

    private String generateHash(Long userId, String otp, long expiryTime) {
        try {
            String rawData = userId + ":" + otp + ":" + expiryTime + ":" + secretKey;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawData.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error calculating security signature");
        }
    }
}