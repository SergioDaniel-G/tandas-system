package com.pay.payment_system.DTO;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.passay.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    private static final Logger log = LoggerFactory.getLogger(PasswordConstraintValidator.class);

    private final Set<String> passwordBlacklist = new HashSet<>();

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        log.info("SECURITY: Loading password blacklist into memory");

        try (InputStream is = getClass().getResourceAsStream("/password-blacklist.txt")) {
            if (is == null) {
                log.error("SECURITY ERROR: File '/password-blacklist.txt' could not be found in the classpath.");
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String blacklistWord;
                while ((blacklistWord = reader.readLine()) != null) {
                    blacklistWord = blacklistWord.trim().toLowerCase();
                    if (!blacklistWord.isEmpty()) {
                        passwordBlacklist.add(blacklistWord);
                    }
                }
                log.info("SECURITY: Successfully loaded {} blacklisted passwords into memory.", passwordBlacklist.size());
            }
        } catch (Exception e) {

            log.error("SECURITY ERROR: Failed to read password blacklist file. Reason: {}", e.getMessage());
        }
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;

        List<String> errorMessages = new ArrayList<>();

        PasswordValidator lengthValidator = new PasswordValidator(new LengthRule(12, 64));
        if (!lengthValidator.validate(new PasswordData(password)).isValid()) {
            errorMessages.add("Password must be between 12 and 64 characters long.");
        }

        PasswordValidator complexityValidator = new PasswordValidator(
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                new CharacterRule(EnglishCharacterData.Digit, 1),
                new CharacterRule(EnglishCharacterData.Special, 1)
        );
        if (!complexityValidator.validate(new PasswordData(password)).isValid()) {
            errorMessages.add("Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.");
        }

        if (password.matches(".*(.)\\1\\1\\1.*")) {
            errorMessages.add("Password contains too many repeated characters.");
        }

        if (containsSequence(password)) {
            errorMessages.add("Password cannot contain obvious numerical or alphabetical sequences.");
        }

        String lowerPassword = password.toLowerCase();
        for (String blacklistWord : passwordBlacklist) {
            if (lowerPassword.contains(blacklistWord)) {
                errorMessages.add("Password is too common, use other one.");
                break;
            }
        }

        if (!errorMessages.isEmpty()) {
            String messageTemplate = String.join(" | ", errorMessages);
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(messageTemplate).addConstraintViolation();
            return false;
        }

        return true;
    }

    private boolean containsSequence(String password) {
        String lower = password.toLowerCase();
        String[] sequences = {"1234", "abcd", "qwer", "asdf"};
        for (String seq : sequences) {
            if (lower.contains(seq)) return true;
        }
        return false;
    }
}