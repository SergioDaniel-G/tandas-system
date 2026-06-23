package com.pay.payment_system.service;

import com.pay.payment_system.entity.Payment;
import com.pay.payment_system.payments.PaymentStatus;
import com.pay.payment_system.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class PaymentService {

    private final PaymentRepository repository;

    @Transactional
    public Payment savePayment(String client, BigDecimal amount, LocalDate date) {

        validatePaymentDate(date);

        return repository.save(
                Payment.builder()
                        .client(client)
                        .amount(amount)
                        .date(date)
                        .status(PaymentStatus.UNPAID)
                        .build()
        );
    }

    @Transactional
    public Payment togglePaymentStatus(Long id) {
        Payment p = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Payment not found: " + id));

        p.setStatus(p.getStatus() == PaymentStatus.PAID ? PaymentStatus.UNPAID : PaymentStatus.PAID);
        return repository.save(p);
    }

    @Transactional
    public void deletePayment(Long id) {
        if (!repository.existsById(id)) {
            throw new IllegalArgumentException("Payment does not exist: " + id);
        }
        repository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public Payment findPaymentById(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Payment not found: " + id));
    }

    @Transactional
    public Payment updatePayment(Long id, Payment updatedData) {
        Payment payment = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Payment not found: " + id));

        if (payment.getStatus() == PaymentStatus.PAID) {
            throw new IllegalStateException("Error: Cannot modify a payment that has already been PAID.");
        }

        if (updatedData.getDate() != null) {
            validatePaymentDate(updatedData.getDate());
            payment.setDate(updatedData.getDate());
        }

        if (updatedData.getClient() != null && !updatedData.getClient().isBlank()) {
            payment.setClient(updatedData.getClient());
        }

        if (updatedData.getAmount() != null) {
            if (updatedData.getAmount().compareTo(BigDecimal.ZERO) <= 0) {
                throw new IllegalArgumentException("Error: Amount must be greater than zero.");
            }
            payment.setAmount(updatedData.getAmount());
        }

        return repository.save(payment);
    }

    @Transactional(readOnly = true)
    public List<Payment> findAllPayments() {
        return repository.findAll();
    }

    private void validatePaymentDate(LocalDate inputDate) {
        if (inputDate == null) {
            throw new IllegalArgumentException("Error: Payment date cannot be null.");
        }

        LocalDate today = LocalDate.now();
        LocalDate maxFutureDate = today.plusYears(1);

        if (inputDate.isBefore(today)) {
            throw new IllegalArgumentException("Error: You cannot register a payment with a past date.");
        }

        if (inputDate.isAfter(maxFutureDate)) {
            throw new IllegalArgumentException("Error: The payment date cannot be more than one year in the future.");
        }
    }
}