package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaProcessingService {

    private final UserRepository userRepository;
    private final IpService ipService;
    private final MfaSecurityContextService mfaSecurityContextService;
    private final UserSecurityService userSecurityService;
    private final CacheManager cacheManager;
    private final StringRedisTemplate redisTemplate;

    // VALIDATES SUBMITTED OTP CODES AGAINST ACTIVE SESSION TOKENS AND EXECUTES SECURITY UPGRADES OR LOCKOUT ESCALATIONS

    @Transactional
    public String processMfaValidation(String code, Authentication auth, HttpServletRequest request, HttpServletResponse response) {
        if (auth == null) return "REDIRECT_LOGIN";

        String username = auth.getName();
        String cleanEmail = username.trim().toLowerCase();
        String lockKey = "login:lock:" + cleanEmail;
        String attemptsKey = "otp:attempts:" + cleanEmail;

        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            Long expireSeconds = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);
            long remaining = (expireSeconds != null && expireSeconds > 0) ? expireSeconds : 900;
            return "REDIRECT_BLOCKED_" + remaining;
        }

        UserAccount userAccount = userRepository.findByEmailCanonical(cleanEmail);
        if (userAccount == null || userAccount.getSecurity() == null) return "REDIRECT_LOGIN";

        if (userAccount.getSecurity().isBlocked()) {
            return "REDIRECT_BLOCKED_900";
        }

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("OTP_CRYPTO_TOKEN") == null) {
            log.warn("MFA SUSPICIOUS: Attempt with missing or expired session token for user: {}", safe (cleanEmail));
            return triggerLockoutIncrement(cleanEmail, session, "STATUS_EXPIRED");
        }

        String cryptoToken = (String) session.getAttribute("OTP_CRYPTO_TOKEN");
        String sanitizedCode = (code != null) ? code.trim() : "";

        boolean isOtpValid = false;
        try {
            isOtpValid = userSecurityService.validateOtp(userAccount, sanitizedCode, cryptoToken);
        } catch (RuntimeException e) {

            if (e.getMessage() != null && e.getMessage().contains("MFA_EXPIRED")) {
                log.warn("MFA EXPIRED ATTEMPT: User entered a structurally timed-out OTP code.");
                return triggerLockoutIncrement(cleanEmail, session, "STATUS_EXPIRED");
            }
            return "REDIRECT_LOGIN";
        }

        if (isOtpValid) {
            session.removeAttribute("OTP_CRYPTO_TOKEN");
            redisTemplate.delete(attemptsKey);
            if (cacheManager.getCache("users_security") != null) {
                cacheManager.getCache("users_security").evict(username);
            }
            ipService.registerAccessAttempt(userAccount, "SUCCESSFUL", null, request);
            mfaSecurityContextService.upgradeToFullAuthentication(auth, userAccount, request, response);
            return "REDIRECT_INDEX";
        }

        else {
            log.warn("MFA WRONG CODE: Input code does not match the generated token.");
            return triggerLockoutIncrement(cleanEmail, session, "REDIRECT_REMAINING_");
        }
    }

    // INCREMENTS MULTI-FACTOR ATTEMPTS IN CACHE AND ENFORCES PROGRESSIVE TEMPORARY LOCKOUTS ON VIOLATION THRESHOLDS

    private String triggerLockoutIncrement(String cleanEmail, HttpSession session, String baseStatus) {
        String attemptsKey = "otp:attempts:" + cleanEmail;
        String lockKey = "login:lock:" + cleanEmail;

        Long currentAttempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (currentAttempts != null && currentAttempts == 1) {
            redisTemplate.expire(attemptsKey, 60, TimeUnit.MINUTES);
        }

        if (currentAttempts != null && currentAttempts >= 3) {

            long lockDurationMinutes = (currentAttempts == 3) ? 15 : (currentAttempts == 4) ? 60 : 1440;
            long lockDurationSeconds = lockDurationMinutes * 60;

            redisTemplate.opsForValue().set(lockKey, "LOCKED", lockDurationMinutes, TimeUnit.MINUTES);

            if (cacheManager.getCache("users_security") != null) {
                cacheManager.getCache("users_security").evict(cleanEmail);
            }

            if (session != null) {
                session.removeAttribute("OTP_CRYPTO_TOKEN");
            }

            log.error("MFA SECURITY ESCALATION: Lockout level [{}] activated for {}. Blocked for {} minutes.",
                    currentAttempts, safe (cleanEmail), lockDurationMinutes);

            return "REDIRECT_BLOCKED_" + lockDurationSeconds;
        }

        if (baseStatus.equals("STATUS_EXPIRED")) {
            if (session != null) session.removeAttribute("OTP_CRYPTO_TOKEN");
            return "STATUS_EXPIRED";
        }

        long remainingAttempts = 3 - currentAttempts;
        return "REDIRECT_REMAINING_" + (remainingAttempts < 0 ? 0 : remainingAttempts);
    }

    // EVALUATES RATE LIMITS, GENERATES A REFRESHED OTP CRYPTO TOKEN, AND DISPATCHES IT TO THE AUTHENTICATED USER

    @Transactional
    public String processMfaResend(Authentication auth, HttpServletRequest request, HttpServletResponse response) {
        if (auth == null) return "RESEND_UNAUTHORIZED";

        String username = auth.getName();
        String cleanEmail = username.trim().toLowerCase();
        String lockKey = "login:lock:" + cleanEmail;
        String attemptsKey = "otp:attempts:" + cleanEmail;

        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            return "RESEND_BLOCKED";
        }

        HttpSession session = request.getSession(false);

        Long currentAttempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (currentAttempts != null && currentAttempts == 1) {
            redisTemplate.expire(attemptsKey, 60, TimeUnit.MINUTES);
        }

        if (currentAttempts != null && currentAttempts >= 3) {
            log.warn("MFA RESEND FLOODING: User {} blocked due to consecutive code requests.", safe (cleanEmail));
            return triggerLockoutIncrement(cleanEmail, session, "REDIRECT_BLOCKED_");
        }

        UserAccount userAccount = userRepository.findByEmailCanonical(cleanEmail);
        if (userAccount == null || session == null) return "RESEND_UNAUTHORIZED";

        String newCryptoToken = userSecurityService.generateAndSendOtp(userAccount.getId(), userAccount.getEmailCanonical());
        if (newCryptoToken == null) return "RESEND_UNAUTHORIZED";

        session.setAttribute("OTP_CRYPTO_TOKEN", newCryptoToken);
        return "RESEND_SUCCESS";
    }

}