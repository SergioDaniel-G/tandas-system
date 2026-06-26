package com.pay.payment_system.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_security")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString(exclude = "user")
public class UserSecurity implements Serializable {

    private static final int MAX_LOGIN_ATTEMPTS = 5;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonBackReference
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            unique = true,
            foreignKey = @ForeignKey(name = "FK_user_security_users")
    )
    private UserAccount user;

    @Column(name = "account_non_locked")
    private boolean accountNonLocked = true;

    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Column(name = "lockout_date")
    private LocalDateTime lockoutDate;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "reset_token", length = 100)
    private String resetToken;

    public void increaseFailedAttempts() {
        failedAttempts++;
        if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
            lockAccount();
        }
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lockoutDate = null;
    }

    public void lockAccount() {
        this.accountNonLocked = false;
        this.lockoutDate = LocalDateTime.now();
    }

    public void unlockAccount() {
        this.accountNonLocked = true;
        this.failedAttempts = 0;
        this.lockoutDate = null;
    }

    public boolean isBlocked() {
        return !accountNonLocked;
    }

    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
    }
}