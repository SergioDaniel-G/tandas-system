package com.pay.payment_system.config;

public final class LogSanitizer {

    private LogSanitizer() {
        throw new IllegalStateException("Utility class");
    }

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
}