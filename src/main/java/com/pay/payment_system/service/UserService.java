package com.pay.payment_system.service;

import com.pay.payment_system.DTO.UserRegistrationDto;
import com.pay.payment_system.entity.UserAccount;
import org.springframework.security.core.userdetails.UserDetailsService;
import java.time.LocalDateTime;
import java.util.List;

public interface UserService extends UserDetailsService {

        UserAccount save(UserRegistrationDto userRegistrationDto);
        List<UserAccount> findAllUsers();
        UserAccount findByEmail(String email);
        void updateLastLoginDate(String email, LocalDateTime loginDate);

}
