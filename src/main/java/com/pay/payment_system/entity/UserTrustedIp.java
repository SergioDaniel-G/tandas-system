package com.pay.payment_system.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_trusted_ips", indexes = {
        @Index(name = "idx_user_id_ip", columnList = "user_id, ip_address")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserTrustedIp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserAccount user;

    @Column(nullable = false, name = "ip_address")
    private String ipAddress;

    @Column(nullable = false, name = "last_used_at")
    private LocalDateTime lastUsedAt;
}