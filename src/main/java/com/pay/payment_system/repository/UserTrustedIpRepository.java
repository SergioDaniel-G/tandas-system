package com.pay.payment_system.repository;

import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserTrustedIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserTrustedIpRepository extends JpaRepository<UserTrustedIp, Long> {

    // CHECKS IF A SPECIFIC IP ADDRESS IS ALREADY ASSOCIATED AND TRUSTED FOR A GIVEN USER EMAIL

    boolean existsByUserAndIpAddress(UserAccount user, String ipAddress);

    // RETRIEVES THE TRUSTED IP RECORD MATCHING BOTH THE USER EMAIL AND THE IP ADDRESS

    Optional<UserTrustedIp> findByUserAndIpAddress(UserAccount user, String ipAddress);

}