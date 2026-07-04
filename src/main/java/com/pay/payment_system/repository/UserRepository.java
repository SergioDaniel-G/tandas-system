package com.pay.payment_system.repository;

import com.pay.payment_system.entity.UserAccount;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserAccount, Long> {

    // CACHES AND RETRIEVES A USER BY CANONICAL EMAIL WITH EAGER LOADING OF ROLES AND SECURITY DATA

    @Cacheable(value = "users_security", key = "#emailCanonical")
    @Query("SELECT u FROM UserAccount u " +
            "LEFT JOIN FETCH u.roles " +
            "LEFT JOIN FETCH u.security " +
            "WHERE u.emailCanonical = :emailCanonical")
    Optional<UserAccount> findByEmailCanonicalWithSecurityAndRoles(@Param("emailCanonical") String emailCanonical);

    UserAccount findByEmailCanonical(String emailCanonical);

    // EVICTS THE SECURITY CACHE AND DIRECTLY UPDATES FAILED LOGIN ATTEMPTS FOR A USER

    @CacheEvict(value = "users_security", key = "#emailCanonical")
    @Modifying
    @Transactional
    @Query("UPDATE UserSecurity s SET s.failedAttempts = :attempts " +
            "WHERE s.user.id = (SELECT u.id FROM UserAccount u WHERE u.emailCanonical = :emailCanonical)")
    void updateFailedAttemptsDirectly(@Param("emailCanonical") String emailCanonical, @Param("attempts") int attempts);

    UserAccount findByEmailCanonicalAndMobileNumber(String emailCanonical, String mobileNumber);
    UserAccount findBySecurityResetToken(String token);

    boolean existsByMobileNumber(String mobileNumber);

}
