package com.pay.payment_system.repository;

import com.pay.payment_system.entity.UserTrustedIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserTrustedIpRepository extends JpaRepository<UserTrustedIp, Long> {

    boolean existsByEmailAndIpAddress(String email, String ipAddress);

    Optional<UserTrustedIp> findByEmailAndIpAddress(String email, String ipAddress);

}