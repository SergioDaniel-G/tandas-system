package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginLockoutEvaluationService {

    private final StringRedisTemplate redisTemplate;
    private final UserRepository userRepository;

    private static final String ATTEMPTS_KEY_PREFIX = "login:attempts:";
    private static final String LOCK_KEY_PREFIX = "login:lock:";
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int MAX_REINCIDENCES_BEFORE_PERMANENT_LOCK = 4;

    public record LockoutResult(int currentAttempts, boolean dynamicLockTriggered, long lockoutMinutes, int lockoutCount) {}

    public LockoutResult registerFailedAttempt(String email) {

        if (email == null || email.trim().isEmpty()) {
            return new LockoutResult(0, false, 0, 0);
        }

        String cleanEmail = email.trim().toLowerCase();
        String attemptsKey = ATTEMPTS_KEY_PREFIX + cleanEmail;
        String lockKey = LOCK_KEY_PREFIX + cleanEmail;

        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            return handleAttemptWhileLocked(cleanEmail, lockKey);
        }

        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        int currentCount = attempts != null ? attempts.intValue() : 0;

        if (currentCount >= MAX_LOGIN_ATTEMPTS) {
            return triggerLockout(cleanEmail, lockKey, attemptsKey);
        } else if (currentCount == 1) {
            redisTemplate.expire(attemptsKey, 10, TimeUnit.MINUTES);
        }

        return new LockoutResult(currentCount, false, 0, 0);
    }

    private LockoutResult triggerLockout(String cleanEmail, String lockKey, String attemptsKey) {
        int lockReincidenceCount = incrementAndGetTemporaryLockCount(cleanEmail);

        redisTemplate.delete(attemptsKey);

        if (lockReincidenceCount > MAX_REINCIDENCES_BEFORE_PERMANENT_LOCK) {
            executePermanentDatabaseLock(cleanEmail);

            redisTemplate.opsForValue().set(lockKey, "PERMANENTLY_LOCKED", 24, TimeUnit.HOURS);

            return new LockoutResult(MAX_LOGIN_ATTEMPTS, true, 0, lockReincidenceCount);
        }

        long dynamicDurationMinutes = calculateDynamicLockoutTime(lockReincidenceCount);
        redisTemplate.opsForValue().set(lockKey, "LOCKED", dynamicDurationMinutes, TimeUnit.MINUTES);

        return new LockoutResult(MAX_LOGIN_ATTEMPTS, true, dynamicDurationMinutes, lockReincidenceCount);
    }

    private LockoutResult handleAttemptWhileLocked(String cleanEmail, String lockKey) {
        String lockStatus = redisTemplate.opsForValue().get(lockKey);

        if ("PERMANENTLY_LOCKED".equals(lockStatus)) {
            return new LockoutResult(MAX_LOGIN_ATTEMPTS, true, 0, MAX_REINCIDENCES_BEFORE_PERMANENT_LOCK + 1);
        }

        Long expire = redisTemplate.getExpire(lockKey, TimeUnit.MINUTES);
        long remainingMinutes = (expire != null && expire > 0) ? expire : 1;

        return new LockoutResult(MAX_LOGIN_ATTEMPTS, true, remainingMinutes, getTemporaryLockCount(cleanEmail));
    }

    @Transactional
    private void executePermanentDatabaseLock(String email) {
        try {
            UserAccount user = userRepository.findByEmail(email);
            if (user != null && user.getSecurity() != null) {
                UserSecurity security = user.getSecurity();
                security.setAccountNonLocked(false);
                userRepository.save(user);
                log.error("CRITICAL SECURITY HARDENING: User {} permanently locked in MySQL.",safe (email));
            }
        } catch (Exception e) {
            log.error("CRITICAL ERROR: Failed to execute permanent DB lock. Message: {}", safe(e.getMessage()));
        }
    }

    private long calculateDynamicLockoutTime(int lockCount) {
        return switch (lockCount) {
            case 1 -> 1;
            case 2 -> 5;
            case 3 -> 15;
            case 4 -> 30;
            default -> 30;
        };
    }

    public int getTemporaryLockCount(String email) {
        String key = "lock_count:" + email.trim().toLowerCase();
        String val = redisTemplate.opsForValue().get(key);
        return val != null ? Integer.parseInt(val) : 0;
    }

    public int incrementAndGetTemporaryLockCount(String email) {
        String key = "lock_count:" + email.trim().toLowerCase();
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, 24, TimeUnit.HOURS);
        }
        return count != null ? count.intValue() : 0;
    }

    public boolean isAccountLocked(String email, Exception exception) {
        if (email == null || email.isBlank()) return false;
        String cleanEmail = email.trim().toLowerCase();
        return Boolean.TRUE.equals(redisTemplate.hasKey(LOCK_KEY_PREFIX + cleanEmail));
    }

    public void resetAttempts(String email) {
        if (email == null) return;
        String cleanEmail = email.trim().toLowerCase();
        redisTemplate.delete(ATTEMPTS_KEY_PREFIX + cleanEmail);
        redisTemplate.delete(LOCK_KEY_PREFIX + cleanEmail);
        resetTemporaryLockCount(cleanEmail);
    }

    public void resetTemporaryLockCount(String email) {
        redisTemplate.delete("lock_count:" + email.trim().toLowerCase());
    }

    public long getRemainingLockoutTimeInSeconds(String email) {
        if (email == null || email.trim().isEmpty()) return 0;
        String cleanEmail = email.trim().toLowerCase();
        Long expire = redisTemplate.getExpire(LOCK_KEY_PREFIX + cleanEmail, TimeUnit.SECONDS);
        return (expire != null && expire > 0) ? expire : 0;
    }
}