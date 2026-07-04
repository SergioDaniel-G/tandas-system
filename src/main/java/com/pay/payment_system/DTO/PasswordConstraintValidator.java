package com.pay.payment_system.DTO;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.passay.*;
import java.util.ArrayList;
import java.util.List;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;

        List<String> errorMessages = new ArrayList<>();

        PasswordValidator lengthValidator = new PasswordValidator(new LengthRule(12, 64));
        if (!lengthValidator.validate(new PasswordData(password)).isValid()) {
            errorMessages.add("Password must be between 12 and 64 characters long.");
        }

        // EVALUATES PASSWORD LENGTH REQUIREMENT

        PasswordValidator complexityValidator = new PasswordValidator(
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                new CharacterRule(EnglishCharacterData.Digit, 1),
                new CharacterRule(EnglishCharacterData.Special, 1)
        );

        RuleResult complexityResult = complexityValidator.validate(new PasswordData(password));
        if (!complexityResult.isValid()) {
            errorMessages.add("Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.");
        }

        // CHECKS FOR EXCESSIVE CHARACTER REPETITIONS

        if (password.matches(".*(.)\\1\\1\\1.*")) {
            errorMessages.add("Password contains too many repeated characters.");
        }


        if (containsSequence(password)) {
            errorMessages.add("Password cannot contain obvious numerical or alphabetical sequences.");
        }

        // VALIDATES PASSWORD AGAINST A FILE-BASED BLACKLIST

        try {

            java.io.InputStream is = getClass().getResourceAsStream("/password-blacklist.txt");

            if (is == null) {
                errorMessages.add("Internal system error: Security file not found.");
            } else {

                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is));

                String blacklistWord;
                String lowerPassword = password.toLowerCase();

                while ((blacklistWord = reader.readLine()) != null) {
                    blacklistWord = blacklistWord.trim().toLowerCase();
                    if (!blacklistWord.isEmpty() && lowerPassword.contains(blacklistWord)) {
                        errorMessages.add("Password is too common, use other one.");
                        break;
                    }
                }
                reader.close();
            }
        } catch (Exception e) {

            e.printStackTrace();
        }

        if (!errorMessages.isEmpty()) {
            String messageTemplate = String.join(" | ", errorMessages);
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(messageTemplate).addConstraintViolation();
            return false;
        }

        return true;
    }

    // HELPER METHOD TO DETECT PREDEFINED WEAK SEQUENCES

    private boolean containsSequence(String password) {
        String lower = password.toLowerCase();
        String[] sequences = {"1234", "abcd", "qwer", "asdf"};
        for (String seq : sequences) {
            if (lower.contains(seq)) {
                return true;
            }
        }
        return false;
    }
}