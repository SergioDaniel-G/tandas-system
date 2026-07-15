package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
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

    // RESETS FAILED LOGIN TRACKERS AND UPDATES USER METADATA TIMESTAMP UPON SUCCESSFUL SYSTEM AUTHENTICATION

    @Transactional
    public UserAccount handleSuccessfulLogin(String email) {
        UserAccount user = userRepository.findByEmailCanonical(email);
        if (user != null && user.getSecurity() != null) {
            UserSecurity security = user.getSecurity();
            if (security.getFailedAttempts() > 0) {
                security.resetFailedAttempts();
                log.info("LOGIN SUCCESSFUL: ATTEMPTS RESET FOR USER: {}", safe (email));
            }
            security.updateLastLogin();
            log.info("USER METADATA UPDATED: LAST LOGIN DATE RECORDED FOR: {}", safe (email));
        }
        return user;
    }

    // INCREMENTS ACCOUNT FAILURE METRICS INDEPENDENTLY WHILE ASSURING ACTIVE LOCKOUT SANITY CONTROLS ARE NOT VIOLATED

    @Transactional
    public UserSecurity handleFailedLoginAttempt(UserAccount user, String email) {
        UserSecurity security = user.getSecurity();
        if (security == null) {
            log.error("SECURITY ENTITY NOT FOUND FOR USER: {}", safe (email));
            return null;
        }

        if (security.isBlocked()) {
            log.error("ACCOUNT LOCKED: {}", safe (email));
            return null;
        }

        security.increaseFailedAttempts();
        return security;
    }

    // GENERATES A CRYPTOGRAPHICALLY SECURE MULTI-FACTOR TOKEN DISPATCHES REQUISITE EMAIL AND COMPUTES TIME WINDOW SIGNATURES

    public String generateAndSendOtp(Long userId, String email, HttpSession session) {
        int codeInt = 100000 + secureRandom.nextInt(900000);
        String otp = String.valueOf(codeInt);

        long expiryTime = Instant.now().toEpochMilli() + (5 * 60 * 1000);

        mfaEmailService.sendOtpEmailAsync(email, otp);

        String hash = generateHash(userId, otp, expiryTime);
        String tokenCompleto = hash + "." + expiryTime;

        session.setAttribute("MFA_CRYPTO_TOKEN", tokenCompleto);

        return tokenCompleto;
    }

    // EVALUATES CRYPTOGRAPHIC TIME BOUND SIGNATURES AND COMPARES USER OVER THE AIR INPUTS VIA CONSTANT TIME VERIFICATION

    @Transactional(propagation = Propagation.REQUIRES_NEW, noRollbackFor = {RuntimeException.class})
    public boolean validateOtp(UserAccount userAccount, String inputOtp, HttpSession session) {
        String cryptoToken = (String) session.getAttribute("MFA_CRYPTO_TOKEN");

        if (cryptoToken == null || !cryptoToken.contains(".")) {
            log.error("MFA CRITICAL: The cryptoToken was not sent by the frontend or is invalid.");
            return false;
        }

        try {
            String[] parts = cryptoToken.split("\\.");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid token format.");
            }

            String clientHash = parts[0];
            long expiryTime = Long.parseLong(parts[1]);

            if (Instant.now().toEpochMilli() > expiryTime) {
                session.removeAttribute("MFA_CRYPTO_TOKEN");
                throw new RuntimeException("MFA_EXPIRED: The OTP code has expired.");
            }

            String serverHash = generateHash(userAccount.getId(), inputOtp, expiryTime);

            boolean isHashValid = MessageDigest.isEqual(
                    serverHash.getBytes(StandardCharsets.UTF_8),
                    clientHash.getBytes(StandardCharsets.UTF_8)
            );

            if (isHashValid) {
                log.info("MFA SUCCESSFUL: OTP validated for user: {}", safe (userAccount.getEmailCanonical()));
                session.removeAttribute("MFA_CRYPTO_TOKEN");
                return true;
            } else {
                log.warn("MFA FAILURE: Invalid OTP code entered for user: {}", safe (userAccount.getEmailCanonical()));
                return false;
            }

        } catch (RuntimeException e) {
            if (e.getMessage() != null && e.getMessage().startsWith("MFA_EXPIRED")) {
                throw e;
            }
            throw new RuntimeException("MFA_ERROR: Error in token structure.");
        } catch (Exception e) {
            throw new RuntimeException("MFA_ERROR: Token externally altered or invalid.");
        }
    }

    // COMPUTES A ONE WAY SHA256 MESSAGE DIGEST INTEGRATING BOUND METADATA AND SHARED SYSTEM KEYS FOR HIGH ENTROPY SIGNING

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