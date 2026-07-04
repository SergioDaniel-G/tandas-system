package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordRecoveryService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MessageSource messageSource;

    // VALIDATES CREDENTIAL MATCHES TO GENERATE A SECURE PASSWORD RESET TOKEN WITHOUT EXPOSING ACCOUNT EXISTENCE STATUS

    @Transactional
    public Map<String, Object> processForgotPassword(String email, String mobileNum) {
        log.info("PASSWORD RECOVERY: Attempt initiated for email: {}", safe (email));

        UserAccount userAccount = userRepository.findByEmailCanonicalAndMobileNumber(email, mobileNum);
        Map<String, Object> response = new HashMap<>();

        String genericMsg = messageSource.getMessage(
                "password.recovery.generic", null,
                "If the data matches our records, instructions will be processed.",
                LocaleContextHolder.getLocale());

        if (userAccount != null) {
            log.info("PASSWORD RECOVERY: Success for email: {}", safe (email));

            String secureToken = UUID.randomUUID().toString();

            UserSecurity security = userAccount.getSecurity();
            if (security == null) {
                security = new UserSecurity();
                userAccount.setSecurity(security);
            }

            security.setResetToken(secureToken);
            userRepository.save(userAccount);

            response.put("success", true);
            response.put("message", genericMsg);
            response.put("status", "OK");

        } else {
            log.warn("PASSWORD RECOVERY FAILED: {} / {}", safe (email), safe (mobileNum));

            response.put("success", true);
            response.put("message", genericMsg);
            response.put("status", "OK");
        }
        return response;
    }

    // VERIFIES COMPLIANCE BETWEEN SUBMITTED PASSWORDS AND CONSUMES THE INSTANTIATED RESET TOKEN UPON SUCCESSFUL RE-ENCRYPTION

    @Transactional
    public Map<String, Object> processResetPassword(String password, String cpassword, String token) {
        Map<String, Object> response = new HashMap<>();

        if (!Objects.equals(password, cpassword)) {
            log.warn("PASSWORD CHANGE FAILED: Passwords do not match for token: {}", safe (token));
            String msg = messageSource.getMessage(
                    "password.change.mismatch", null, "Passwords do not match.", LocaleContextHolder.getLocale());

            response.put("success", false);
            response.put("message", msg);
            response.put("status", "BAD_REQUEST");
            return response;
        }

        UserAccount userAccount = userRepository.findBySecurityResetToken(token);

        if (userAccount != null) {
            String encryptPsw = passwordEncoder.encode(password);
            userAccount.setPassword(encryptPsw);

            if (userAccount.getSecurity() != null) {
                userAccount.getSecurity().setResetToken(null);
            }

            userRepository.save(userAccount);

            log.info("PASSWORD CHANGE SUCCESS for user: {}", safe (userAccount.getEmailCanonical()));
            String successMsg = messageSource.getMessage(
                    "password.change.success", null, "¡Password changed successfully.!", LocaleContextHolder.getLocale());

            response.put("success", true);
            response.put("message", successMsg);
            response.put("redirectUrl", "/login");
            response.put("status", "OK");
        } else {
            log.error("PASSWORD CHANGE CRITICAL: Token {} is invalid, used or expired.", safe (token));
            String msg = messageSource.getMessage(
                    "password.change.user.notfound", null, "User not found.", LocaleContextHolder.getLocale());

            response.put("success", false);
            response.put("message", msg);
            response.put("status", "NOT_FOUND");
        }
        return response;
    }
}