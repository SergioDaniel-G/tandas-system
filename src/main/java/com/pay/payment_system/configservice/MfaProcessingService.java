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

    private static final String MFA_SESSION_ATTRIBUTE = "MFA_CRYPTO_TOKEN";
    private static final int MAX_DAILY_RESENDS = 5;

    @Transactional(noRollbackFor = {RuntimeException.class})
    public String processMfaValidation(String code, Authentication auth, HttpServletRequest request, HttpServletResponse response) {
        if (auth == null) return "REDIRECT_LOGIN";

        String username = auth.getName();
        String cleanEmail = username.trim().toLowerCase();
        String lockKey = "login:lock:" + cleanEmail;
        String delayKey = "otp:delay:" + cleanEmail;
        String attemptsKey = "otp:attempts:" + cleanEmail;

        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            Long expireSeconds = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);
            long remaining = (expireSeconds != null && expireSeconds > 0) ? expireSeconds : 900;
            return "REDIRECT_BLOCKED_" + remaining;
        }

        if (Boolean.TRUE.equals(redisTemplate.hasKey(delayKey))) {
            Long expireSeconds = redisTemplate.getExpire(delayKey, TimeUnit.SECONDS);
            long remaining = (expireSeconds != null && expireSeconds > 0) ? expireSeconds : 5;
            return "REDIRECT_DELAYED_" + remaining;
        }

        UserAccount userAccount = userRepository.findByEmailCanonical(cleanEmail);
        if (userAccount == null || userAccount.getSecurity() == null) return "REDIRECT_LOGIN";

        if (userAccount.getSecurity().isBlocked()) {
            return "REDIRECT_BLOCKED_900";
        }

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(MFA_SESSION_ATTRIBUTE) == null) {
            log.info("MFA SUSPICIOUS: Attempt with missing or expired session token for user: {}", safe(cleanEmail));
            if (session != null) session.removeAttribute(MFA_SESSION_ATTRIBUTE);
            return "STATUS_EXPIRED";
        }

        String sanitizedCode = (code != null) ? code.trim() : "";

        boolean isOtpValid = false;
        try {
            isOtpValid = userSecurityService.validateOtp(userAccount, sanitizedCode, session);
        } catch (RuntimeException e) {
            if (e.getMessage() != null && e.getMessage().contains("MFA_EXPIRED")) {
                log.warn("MFA EXPIRED ATTEMPT: User entered a structurally timed-out OTP code.");
                if (session != null) session.removeAttribute(MFA_SESSION_ATTRIBUTE);
                return "STATUS_EXPIRED";
            }

            log.error("MFA ERROR: Unexpected validation failure for user: {}", safe(cleanEmail), e);
            return handleProgressiveBackoff(cleanEmail, session);
        }

        if (isOtpValid) {
            session.removeAttribute(MFA_SESSION_ATTRIBUTE);
            redisTemplate.delete(attemptsKey);
            redisTemplate.delete(delayKey);
            redisTemplate.delete(lockKey);

            redisTemplate.delete("otp:resend:rate:" + cleanEmail);
            redisTemplate.delete("otp:resend:cooldown:" + cleanEmail);
            redisTemplate.delete("otp:resend:count:" + cleanEmail);
            redisTemplate.delete("otp:resend:daily:" + cleanEmail);

            evictUserSecurityCache(cleanEmail);

            ipService.registerAccessAttempt(userAccount, "SUCCESSFUL", null, request);
            mfaSecurityContextService.upgradeToFullAuthentication(auth, userAccount, request, response);
            return "REDIRECT_INDEX";
        } else {
            log.warn("MFA WRONG CODE: Input code does not match for user: {}", safe(cleanEmail));
            return handleProgressiveBackoff(cleanEmail, session);
        }
    }

    private String handleProgressiveBackoff(String cleanEmail, HttpSession session) {
        String attemptsKey = "otp:attempts:" + cleanEmail;
        String delayKey = "otp:delay:" + cleanEmail;
        String lockKey = "login:lock:" + cleanEmail;

        Long currentAttempts = redisTemplate.opsForValue().increment(attemptsKey);

        if (currentAttempts != null) {
            Long currentTtl = redisTemplate.getExpire(attemptsKey);
            if (currentTtl == null || currentTtl == -1 || currentAttempts == 1) {
                redisTemplate.expire(attemptsKey, 30, TimeUnit.MINUTES);
            }
        }

        long delaySeconds = 0;

        if (currentAttempts == 2) {
            delaySeconds = 5;
        } else if (currentAttempts == 3) {
            delaySeconds = 30;
        } else if (currentAttempts == 4) {
            delaySeconds = 120;
        } else if (currentAttempts >= 5) {
            redisTemplate.opsForValue().set(lockKey, "LOCKED", 15, TimeUnit.MINUTES);
            redisTemplate.delete(delayKey);

            evictUserSecurityCache(cleanEmail);

            if (session != null) {
                session.removeAttribute(MFA_SESSION_ATTRIBUTE);
            }

            log.error("MFA MAX ATTEMPTS EXCEEDED: Hard lockout (15m) activated for {}.", safe(cleanEmail));
            return "REDIRECT_BLOCKED_900";
        }

        if (delaySeconds > 0) {
            redisTemplate.opsForValue().set(delayKey, "DELAYED", delaySeconds, TimeUnit.SECONDS);
            return "REDIRECT_DELAYED_" + delaySeconds;
        }

        long remainingAttempts = 5 - currentAttempts;
        return "REDIRECT_REMAINING_" + remainingAttempts;
    }

    @Transactional
    public String processMfaResend(Authentication auth,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {

        HttpSession session = request.getSession(false);
        String username = null;

        if (auth != null) {
            username = auth.getName();
        } else if (session != null && session.getAttribute("SPRING_SECURITY_CONTEXT") != null) {
            try {
                org.springframework.security.core.context.SecurityContext context =
                        (org.springframework.security.core.context.SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
                if (context.getAuthentication() != null) {
                    username = context.getAuthentication().getName();
                }
            } catch (Exception e) {
                log.error("Error retrieving the security context of the backup session.", e);
            }
        }

        if (username == null) {
            log.warn("MFA RESEND DENIED: No valid authentication context or session found.");
            return "RESEND_UNAUTHORIZED";
        }

        String cleanEmail = username.trim().toLowerCase();

        String lockKey = "login:lock:" + cleanEmail;
        String resendCooldownKey = "otp:resend:cooldown:" + cleanEmail;
        String resendCountKey = "otp:resend:count:" + cleanEmail;
        String dailyLimitKey = "otp:resend:daily:" + cleanEmail;

        // FILTER: EXISTING HARD BLOCK (24H OR 15M)

        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            return "RESEND_BLOCKED";
        }

        // FILTER: GATEWAY COOLDOWN (60S, 180S, 300S)

        if (Boolean.TRUE.equals(redisTemplate.hasKey(resendCooldownKey))) {
            Long remainingTime = redisTemplate.getExpire(resendCooldownKey, TimeUnit.SECONDS);
            long remaining = (remainingTime != null && remainingTime > 0) ? remainingTime : 60;
            return "RESEND_DELAYED_" + remaining;
        }

        // DAILY CONTROL: Increment and validation of 5 resend limit

        Long dailyCount = redisTemplate.opsForValue().increment(dailyLimitKey);
        if (dailyCount != null && dailyCount == 1) {
            redisTemplate.expire(dailyLimitKey, 24, TimeUnit.HOURS);
        }

        // IF IT IS THE 6TH ATTEMPT OF THE DAY

        if (dailyCount != null && dailyCount > MAX_DAILY_RESENDS) {
            log.error("MFA DAILY LIMIT EXCEEDED: 24h Hard lockout activated for {}.", safe(cleanEmail));
            redisTemplate.opsForValue().set(lockKey, "LOCKED", 24, TimeUnit.HOURS);


            redisTemplate.delete(resendCooldownKey);
            redisTemplate.delete(resendCountKey);
            if (session != null) {
                session.removeAttribute(MFA_SESSION_ATTRIBUTE);
            }
            evictUserSecurityCache(cleanEmail);
            return "RESEND_DAILY_BLOCKED";
        }

        // HOURLY CONTROL: MAXIMUM BURST OF 3 CONSECUTIVE ATTEMPTS

        Long resendAttempts = redisTemplate.opsForValue().increment(resendCountKey);
        if (resendAttempts != null && resendAttempts == 1) {
            redisTemplate.expire(resendCountKey, 1, TimeUnit.HOURS);
        }

        if (resendAttempts != null && resendAttempts > 3) {
            log.error("MFA RESEND MAX LIMIT EXCEEDED: 15m lockout activated for {}.", safe(cleanEmail));
            redisTemplate.opsForValue().set(lockKey, "LOCKED", 15, TimeUnit.MINUTES);
            redisTemplate.delete(resendCooldownKey);
            redisTemplate.delete(resendCountKey);

            if (session != null) {
                session.removeAttribute(MFA_SESSION_ATTRIBUTE);
            }
            evictUserSecurityCache(cleanEmail);
            return "RESEND_BLOCKED";
        }

        UserAccount userAccount = userRepository.findByEmailCanonical(cleanEmail);
        if (userAccount == null) {
            return "RESEND_UNAUTHORIZED";
        }

        // OTP GENERATION AND SENDING

        if (session == null) {
            session = request.getSession(true);
        }

        String newCryptoToken = userSecurityService.generateAndSendOtp(
                userAccount.getId(),
                userAccount.getEmailCanonical(),
                session
        );

        if (newCryptoToken == null) {
            return "RESEND_UNAUTHORIZED";
        }

        session.setAttribute(MFA_SESSION_ATTRIBUTE, newCryptoToken);

        // APPLYING THE NEXT COOLDOWN

        long nextCooldownSeconds = 60;
        if (resendAttempts != null) {
            if (resendAttempts == 2) {
                nextCooldownSeconds = 180;
            } else if (resendAttempts == 3) {
                nextCooldownSeconds = 300;
            }
        }
        redisTemplate.opsForValue().set(resendCooldownKey, "WAIT", nextCooldownSeconds, TimeUnit.SECONDS);

        return "RESEND_SUCCESS";
    }

    private void evictUserSecurityCache(String email) {
        if (cacheManager.getCache("users_security") != null) {
            cacheManager.getCache("users_security").evict(email);
        }
    }
}