package com.pay.payment_system.config;

public final class LogSanitizer {

    private LogSanitizer() {
        throw new IllegalStateException("Utility class");
    }

    // SANITIZES INPUT STRINGS BY REMOVING NEWLINES AND CONTROL CHARACTERS TO PREVENT LOG INJECTION ATTACKS

    public static String safe(String input) {
        if (input == null) {
            return "";
        }

        return input
                .replace("\r", "_")
                .replace("\n", "_")
                .replace("\u2028", "_")
                .replace("\u2029", "_")
                .replaceAll("\\p{Cntrl}", "");
    }

    public static String maskEmail(String email) {

        if (email == null || email.isBlank()) {
            return "unknown";
        }

        String[] parts = email.split("@");

        if (parts.length != 2) {
            return safe(email);
        }

        String username = parts[0];
        String domain = parts[1];

        if (username.length() <= 2) {
            return "**@" + domain;
        }

        return username.substring(0, 2)
                + "******@"
                + domain;
    }
}