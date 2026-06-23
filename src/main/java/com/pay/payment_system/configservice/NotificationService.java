package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.Payment;
import com.pay.payment_system.payments.PaymentStatus;
import com.pay.payment_system.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.time.LocalDate;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final PaymentRepository paymentRepository;
    private final SmsService smsService;

    public void verifyMonthlyPayments() {
        LocalDate today = LocalDate.now();

        List<Payment> todayPayments = paymentRepository.findByDateAndStatus(today, PaymentStatus.UNPAID);

        for (Payment payment : todayPayments) {
            String smsMessage = String.format(
                    "LITZIA'S TANDA SYSTEM | It's your monthly payment day! You need to pay %s the amount of $%s. (NUMBER: %d)",
                    payment.getClient(), payment.getAmount(), payment.getId()
            );

            try {
                smsService.sendSmsAlert(smsMessage);
                log.info("SMS successfully sent for payment ID: {}", payment.getId());
            } catch (Exception e) {
                log.error("Failed to send SMS for payment ID: {}. Error: {}", payment.getId(), e.getMessage());
            }
        }
    }
}
