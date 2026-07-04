package com.pay.payment_system.DTO;

import java.util.Set;

/* UTILITY CLASS FOR EMAIL CANONICALIZATION
 * STANDARDIZES EMAIL ADDRESSES BY REMOVING OVERRIDES (LIKE DOTS AND PLUS TAGS)
 * BASED ON SPECIFIC DOMAIN PROVIDER BEHAVIORS TO PREVENT DUPLICATE ACCOUNTS
 */

public final class EmailCanonicalizer {

    private static final Set<String> DOT_AND_PLUS_PROVIDERS = Set.of("gmail.com", "googlemail.com");
    private static final Set<String> ONLY_PLUS_PROVIDERS = Set.of("outlook.com", "hotmail.com", "live.com", "icloud.com");

    private EmailCanonicalizer() {

    }

    public static String canonicalize(String email) {
        if (email == null || !email.contains("@")) {
            return email != null ? email.trim().toLowerCase() : null;
        }

        String cleaned = email.trim().toLowerCase();
        String[] parts = cleaned.split("@", 2);
        String username = parts[0];
        String domain = parts[1];

        // APPLIES SPECIAL NORMS BASED ON THE DETECTED DOMAIN PROVIDER

        if (DOT_AND_PLUS_PROVIDERS.contains(domain)) {
            if (username.contains("+")) {
                username = username.split("\\+")[0];
            }
            username = username.replace(".", "");
        } else if (ONLY_PLUS_PROVIDERS.contains(domain)) {
            if (username.contains("+")) {
                username = username.split("\\+")[0];
            }
        }

        return username + "@" + domain;
    }
}
