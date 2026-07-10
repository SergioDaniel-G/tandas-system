package com.pay.payment_system.controller;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.Payment;
import com.pay.payment_system.service.PaymentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/payments")
@Profile("dev")
public class PaymentController {

    private final PaymentService paymentService;

    // RETRIEVES A COMPLETE TRANSACTIONAL LEDGER CONTAINING ALL SYSTEM PAYMENTS UNDER DEVELOPMENT PROFILES

    @GetMapping
    public List<Payment> getTable() {
        log.info("Fetching all payments");
        return paymentService.findAllPayments();
    }

    // QUERIES THE DATA LAYER FOR A SINGLE PAYMENT TRANSACTION FILTERED BY UNIQUE DATABASE ID KEY

    @GetMapping("/{id}")
    public ResponseEntity<Payment> getById(@PathVariable Long id) {
        try {
            log.info("Searching payment with ID {}", id);
            return ResponseEntity.ok(paymentService.findPaymentById(id));
        } catch (IllegalArgumentException e) {
            log.warn("Payment not found with ID {}", id);
            return ResponseEntity.notFound().build();
        }
    }

    // SANITIZES INPUT AND DISPATCHES PAYLOADS TO THE BUSINESS PIPELINE FOR NEW PAYMENT TRANSACTION INGESTION

    @PostMapping("/create")
    public ResponseEntity<?> create(@Valid @RequestBody Payment request) {
        try {
            log.info("Creating payment for client {}", safe (request.getClient()));

            Payment saved = paymentService.savePayment(
                    request.getClient(),
                    request.getAmount(),
                    request.getDate()
            );

            log.info("Payment created successfully with ID {}", saved.getId());
            return ResponseEntity.ok(saved);

        } catch (Exception e) {
            log.error("Error creating payment: {}", safe (e.getMessage()));
            return ResponseEntity.badRequest().body("An error occurred while processing the payment.");
        }
    }

    // PROCESSES SECURE STATE MUTATIONS AND OVERWRITES TRANSACTIONAL FIELDS FOR REQUISITE PAYMENT IDENTIFIERS

    @PutMapping("/{id}")
    public ResponseEntity<?> updatePayment(
            @PathVariable Long id,
            @Valid @RequestBody Payment request) {

        try {
            log.info("Updating payment ID {}", id);

            Payment updated = paymentService.updatePayment(id, request);

            log.info("Payment updated successfully ID {}", id);
            return ResponseEntity.ok(updated);

        } catch (IllegalArgumentException e) {
            log.warn("Validation error updating ID {}: {}", id, safe(e.getMessage()));
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error updating ID {}: {}", id, safe(e.getMessage()));
            return ResponseEntity.internalServerError().body("Internal server error updating entity.");
        }
    }

    // EXECUTES PERSISTENCE PURGES TO ABSOLUTELY REMOVE THE TARGET PAYMENT RESOURCE FROM LEDGER CHANNELS

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        try {
            log.info("Deleting payment ID {}", id);

            paymentService.deletePayment(id);

            log.info("Payment deleted ID {}", id);
            return ResponseEntity.noContent().build();

        } catch (IllegalArgumentException e) {
            log.warn("Attempt to delete non-existent ID {}", id);
            return ResponseEntity.notFound().build();
        }
    }

    // COMMUTES TRANSACTION STATUS STATE MACHINERY FLIPPING BETWEEN UNPAID AND COMPLETED AUDIT DOMAINS

    @PutMapping("/{id}/toggle")
    public ResponseEntity<Payment> toggle(@PathVariable Long id) {
        log.info("Toggling payment status ID {}", id);

        Payment result = paymentService.togglePaymentStatus(id);

        log.info("Status toggled for ID {}", id);
        return ResponseEntity.ok(result);
    }
}