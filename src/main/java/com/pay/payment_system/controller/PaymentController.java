package com.pay.payment_system.controller;

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

    @GetMapping
    public List<Payment> getTable() {
        log.info("Fetching all payments");
        return paymentService.findAllPayments();
    }

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

    @PostMapping("/create")
    public ResponseEntity<?> create(@Valid @RequestBody Payment request) {
        try {
            log.info("Creating payment for client {}", request.getClient());

            Payment saved = paymentService.savePayment(
                    request.getClient(),
                    request.getAmount(),
                    request.getDate()
            );

            log.info("Payment created successfully with ID {}", saved.getId());
            return ResponseEntity.ok(saved);

        } catch (Exception e) {
            log.error("Error creating payment: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

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
            log.warn("Validation error updating ID {}: {}", id, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error updating ID {}: {}", id, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

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

    @PutMapping("/{id}/toggle")
    public ResponseEntity<Payment> toggle(@PathVariable Long id) {
        log.info("Toggling payment status ID {}", id);

        Payment result = paymentService.togglePaymentStatus(id);

        log.info("Status toggled for ID {}", id);
        return ResponseEntity.ok(result);
    }
}