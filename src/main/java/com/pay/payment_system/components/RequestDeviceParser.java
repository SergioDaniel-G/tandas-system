package com.pay.payment_system.components;

import org.springframework.stereotype.Component;

@Component
public class RequestDeviceParser {

    public boolean detectBot(String userAgent) {
        if (userAgent == null) return true;
        String uaLower = userAgent.toLowerCase();
        return uaLower.contains("bot") ||
                uaLower.contains("python") ||
                uaLower.contains("curl") ||
                uaLower.contains("postman") ||
                uaLower.contains("httpclient");
    }

    public String determineDeviceType(String userAgent) {
        if (userAgent == null) return "PC";

        String uaLower = userAgent.toLowerCase();

        if (uaLower.contains("mobi") || uaLower.contains("android") || uaLower.contains("iphone")) {
            return "MOBILE";
        }

        if (uaLower.contains("tablet") || uaLower.contains("ipad")) {
            return "TABLET";
        }

        return "PC";
    }
}