package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaProcessingService {

    private final UserRepository userRepository;
    private final IpService ipService;
    private final MfaSecurityContextService mfaSecurityContextService;
    private final UserSecurityService userSecurityService;

    @Transactional
    public String processMfaValidation(String code, Authentication auth, HttpServletRequest request, HttpServletResponse response) {
        if (auth == null) {
            log.warn("MFA ATTEMPT: Unauthorized access try to validation endpoint.");
            return "REDIRECT_LOGIN";
        }

        String username = auth.getName();
        String sanitizedCode = (code != null) ? code.trim() : "";
        UserAccount userAccount = userRepository.findByEmail(username);

        if (userAccount == null) {
            log.error("MFA CRITICAL: Context authentication name '{}' not found in database.", username);
            return "REDIRECT_LOGIN";
        }

        UserSecurity security = userAccount.getSecurity();
        if (security == null) {
            log.error("MFA SECURITY ERROR: Security entity not found for user '{}'", username);
            return "REDIRECT_LOGIN";
        }

        if (security.otpLimitReached() || security.isBlocked()) {
            log.warn("MFA BLOCKED: User {} attempted verification but is already locked.", username);
            ipService.registerAccessAttempt(username, "FAIL", "User blocked due to maximum OTP attempts reached", request);

            HttpSession currentSession = request.getSession(false);
            if (currentSession != null) {
                currentSession.invalidate();
            }
            return "REDIRECT_BLOCKED";
        }

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("OTP_CRYPTO_TOKEN") == null) {
            log.warn("MFA ATTEMPT: No cryptographic OTP token found in session for user {}.", username);
            return "REDIRECT_LOGIN";
        }
        String cryptoToken = (String) session.getAttribute("OTP_CRYPTO_TOKEN");

        boolean isOtpValid = false;
        try {
            isOtpValid = userSecurityService.validateOtp(userAccount, sanitizedCode, cryptoToken);
        } catch (RuntimeException e) {
            log.error("MFA VALIDATION EXCEPTION for user " + username, e);

            if (e.getMessage() != null && e.getMessage().contains("MFA_EXPIRED")) {
                session.removeAttribute("OTP_CRYPTO_TOKEN");
                ipService.registerAccessAttempt(username, "FAIL", "Expired OTP token challenge", request);
                return "REDIRECT_LOGIN";
            }

            if (security.otpLimitReached() || security.isBlocked()) {
                if (session != null) session.invalidate();
                return "REDIRECT_BLOCKED";
            }

            return "REDIRECT_LOGIN";
        }

        if (isOtpValid) {
            session.removeAttribute("OTP_CRYPTO_TOKEN");
            security.setOtpFailedAttempts(0);
            userRepository.save(userAccount);

            ipService.registerAccessAttempt(username, "SUCCESSFUL", null, request);
            log.info("MFA CHALLENGE PASSED: User {} successfully authenticated.", username);

            mfaSecurityContextService.upgradeToFullAuthentication(auth, userAccount, request, response);
            return "REDIRECT_INDEX";
        } else {

            security.increaseOtpAttempts();
            int currentAttempts = security.getOtpFailedAttempts();

            userRepository.save(userAccount);

            String reason = "Incorrect OTP code. Attempt #" + currentAttempts;
            ipService.registerAccessAttempt(username, "FAIL", reason, request);

            log.warn("MFA CHALLENGE FAILED: Invalid OTP code provided by user {}. Attempt {}/3", username, currentAttempts);

            if (security.isBlocked() || security.otpLimitReached()) {
                if (session != null) session.invalidate();
                log.error("MFA LOCKOUT: User {} has been dynamically locked out due to failed OTP attempts.", username);
                return "REDIRECT_BLOCKED";
            }

            int remainingAttempts = 3 - currentAttempts;
            if (remainingAttempts < 0) remainingAttempts = 0;

            return "REDIRECT_REMAINING_" + remainingAttempts;
        }
    }
}