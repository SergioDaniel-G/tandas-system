package com.pay.payment_system.controller;

import com.pay.payment_system.configservice.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/cron")
@RequiredArgsConstructor
public class CronController {

    private final NotificationService notificationService;

    @Value("${cron.secret.token}")
    private String secretToken;

    @PostMapping("/verify-payments")
    public ResponseEntity<String> triggerMonthlyPayments(
            @RequestHeader(value = "X-Cron-Token", required = false) String token) {

        // VALIDATE EXTERNAL CRON SECURITY TOKEN
        if (token == null || !token.equals(secretToken)) {
            log.warn("CRON SECURITY ALERT: Unauthorized attempt to trigger monthly payments. Invalid token provided.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Not authorized to perform this task.");
        }

        log.info("CRON TASK START: Validated token successfully. Initiating monthly payments check...");

        try {
            notificationService.verifyMonthlyPayments();
            log.info("CRON TASK SUCCESS: Monthly payment execution finished correctly.");
            return ResponseEntity.ok("Monthly payment check completed and SMS notifications sent.");
        } catch (Exception e) {
            log.error("CRON TASK ERROR: Failed executing monthly payments check. Reason: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred during the batch process: " + e.getMessage());
        }
    }
}