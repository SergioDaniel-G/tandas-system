package com.pay.payment_system.repository;

import com.pay.payment_system.entity.UserAccount;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserAccount, Long> {

    @Cacheable(value = "users_security", key = "#email")
    @Query("SELECT u FROM UserAccount u " +
            "LEFT JOIN FETCH u.roles " +
            "LEFT JOIN FETCH u.security " +
            "WHERE u.email = :email")
    Optional<UserAccount> findByEmailWithSecurityAndRoles(@Param("email") String email);

    UserAccount findByEmail(@Param("email") String email);

    @CacheEvict(value = "users_security", key = "#email")
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.transaction.annotation.Transactional
    @org.springframework.data.jpa.repository.Query("UPDATE UserSecurity s SET s.failedAttempts = :attempts " +
            "WHERE s.user.id = (SELECT u.id FROM UserAccount u WHERE u.email = :email)")
    void updateFailedAttemptsDirectly(@Param("email") String email, @Param("attempts") int attempts);

    UserAccount findByEmailAndMobileNumber(String email, String mobileNum);
    UserAccount findBySecurityResetToken(String token);

}
