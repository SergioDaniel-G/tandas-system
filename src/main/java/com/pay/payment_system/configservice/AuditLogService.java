package com.pay.payment_system.configservice;

import com.pay.payment_system.components.RequestDeviceParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final RequestDeviceParser deviceParser;

    public void logFailedAttempt(String email, String ip, String agent, int attempts) {
        String device = deviceParser.determineDeviceType(agent);
        String riskLevel = (attempts >= 3) ? "MEDIUM" : "LOW";

        log.warn("SECURITY_AUDIT | Email: {} | IP: {} | Status: FAILED_PASSWORD | Risk: {} | Device: {} | Reason: INCORRECT PASSWORD. ATTEMPT #{} | UA: {}",
                email, ip, riskLevel, device, attempts, (agent != null ? agent : "UNKNOWN"));
    }

    public void logFailure(String email, String ip, String description) {
        log.warn("SECURITY_AUDIT | Email: {} | IP: {} | Status: FAILED | Reason: {}",
                email, ip, description);
    }

    public void logCritical(String email, String ip, String action, String description) {
        log.error("CRITICAL_SECURITY_EVENT | Email: {} | IP: {} | Action: {} | Description: {}",
                email, ip, action, description);
    }
}