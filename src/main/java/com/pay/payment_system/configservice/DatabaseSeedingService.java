package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.Role;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.RoleRepository;
import com.pay.payment_system.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class DatabaseSeedingService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void seedDefaultAdminAndRoles(String adminEmail, String adminPassword, String adminName, String adminSurname, String adminMobile) {


        String normalizedAdminEmail = adminEmail.toLowerCase().trim();
        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(new Role("ROLE_ADMIN")));

        roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(new Role("ROLE_USER")));

        if (userRepository.findByEmail(normalizedAdminEmail) == null) {

            UserAccount admin = UserAccount.builder()
                    .name(adminName)
                    .lastname(adminSurname)
                    .email(normalizedAdminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .mobileNumber(adminMobile)
                    .roles(Collections.singleton(adminRole))
                    .build();

            UserSecurity security = UserSecurity.builder()
                    .user(admin)
                    .accountNonLocked(true)
                    .failedAttempts(0)
                    .build();

            admin.setSecurity(security);
            userRepository.save(admin);

            log.info("DATABASE SUCCESSFUL: DEFAULT ADMIN ACCOUNT AND SYSTEM ROLES INITIALIZED.");

        } else {

            log.info("DATABASE SKIPPED: ADMIN ACCOUNT ALREADY EXISTS.");
        }
    }
}
