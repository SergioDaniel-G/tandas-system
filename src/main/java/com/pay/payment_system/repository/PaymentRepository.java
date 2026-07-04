package com.pay.payment_system.repository;

import com.pay.payment_system.entity.Payment;
import com.pay.payment_system.payments.PaymentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDate;
import java.util.List;

@Repository
public interface PaymentRepository extends JpaRepository<Payment, Long> {

    // FETCHES PAYMENTS FILTERED BY SPECIFIC DATE AND STATUS (PAID/UNPAID)

    List<Payment> findByDateAndStatus(LocalDate date, PaymentStatus status);
}
