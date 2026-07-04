package com.pay.payment_system.components;

import com.pay.payment_system.configservice.DatabaseSeedingService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/* DATA SEEDING COMPONENT TO INITIALIZE THE DATABASE ON STARTUP
 * THIS CLASS ENSURES THAT A DEFAULT ADMINISTRATIVE USER EXISTS,
 * LEVERAGING EXTERNALIZED CONFIGURATION FOR CREDENTIALS.
 */

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final DatabaseSeedingService databaseSeedingService;

    @Value("${app.admin.email}")
    private String adminEmail;

    @Value("${app.admin.password}")
    private String adminPassword;

    @Value("${app.admin.name}")
    private String adminName;

    @Value("${app.admin.surname}")
    private String adminSurname;

    @Value("${app.admin.mobile}")
    private String adminMobile;

    // EXECUTES DATABASE SEEDING FOR DEFAULT ROLES AND THE ADMINISTRATOR USER UPON APPLICATION STARTUP

    @Override
    public void run(String... args) {

        databaseSeedingService.seedDefaultAdminAndRoles(
                adminEmail,
                adminPassword,
                adminName,
                adminSurname,
                adminMobile
        );
    }
}