package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import static com.pay.payment_system.config.LogSanitizer.maskEmail;
import com.pay.payment_system.components.RequestDeviceParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final RequestDeviceParser deviceParser;

    // RECORDS DETAILED FAILED AUTHENTICATION ATTEMPTS WITH AUTOMATIC RISK ASSESSMENT AND DEVICE PARSING

    public void logFailedAttempt(String email, String ip, String agent, int attempts) {
        String device = deviceParser.determineDeviceType(agent);
        String riskLevel = (attempts >= 3) ? "MEDIUM" : "LOW";

        log.warn("SECURITY_AUDIT | Email: {} | IP: {} | Status: FAILED_PASSWORD | Risk: {} | Device: {} | Reason: INCORRECT PASSWORD. ATTEMPT #{} | UA: {}",
                safe(maskEmail(email)), safe (ip), riskLevel, safe(device), attempts, (agent != null ? safe (agent) : "UNKNOWN"));
    }

    // REGISTERS GENERAL SYSTEM SEGREGATED SECURITY OR AUTHENTICATION PIPELINE FAILURES

    public void logFailure(String email, String ip, String description) {
        log.warn("SECURITY_AUDIT | Email: {} | IP: {} | Status: FAILED | Reason: {}",
                safe(maskEmail(email)), safe (ip), safe (description));
    }

    // EMITS HIGH-PRIORITY ALERTS AND LOG ENTRIES FOR CRITICAL AND POTENTIALLY MALICIOUS OPERATIONS

    public void logCritical(String email, String ip, String action, String description) {
        log.error("CRITICAL_SECURITY_EVENT | Email: {} | IP: {} | Action: {} | Description: {}",
                safe(maskEmail(email)), safe (ip),  safe(action), safe (description));
    }
}