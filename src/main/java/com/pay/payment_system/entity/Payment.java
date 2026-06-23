package com.pay.payment_system.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.pay.payment_system.payments.PaymentStatus;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.format.annotation.DateTimeFormat;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Builder
@Entity
@Table(name = "payments")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "{payment.client.required}")
    @Size(max = 100, message = "{payment.client.toolong}")
    @Column(
            nullable = false,
            length = 100,
            columnDefinition = "VARCHAR(100) CHECK (TRIM(client) <> '')"
    )
    private String client;

    @NotNull(message = "{payment.amount.required}")
    @Positive(message = "{payment.amount.positive}")
    @Column(
            nullable = false,
            precision = 10,
            scale = 2,
            columnDefinition = "DECIMAL(10,2) CHECK (amount > 0)"
    )
    private BigDecimal amount;

    @NotNull(message = "{payment.date.required}")
    @DateTimeFormat(pattern = "dd-MM-yyyy")
    @JsonFormat(pattern = "dd-MM-yyyy")
    @Column(nullable = false)
    private LocalDate date;

    @Column(
            nullable = false,
            columnDefinition = "VARCHAR(20) CHECK (status IN ('PAID', 'UNPAID'))"
    )
    @ColumnDefault("'UNPAID'")
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private PaymentStatus status = PaymentStatus.UNPAID;

    @CreatedBy
    @Column(name = "created_by", updatable = false, length = 50)
    private String createdBy;

    @CreatedDate
    @Column(name = "created_date", updatable = false)
    private LocalDateTime createdDate;

    @LastModifiedBy
    @Column(name = "last_modified_by", length = 50)
    private String lastModifiedBy;

    @LastModifiedDate
    @Column(name = "last_modified_date")
    private LocalDateTime lastModifiedDate;
}