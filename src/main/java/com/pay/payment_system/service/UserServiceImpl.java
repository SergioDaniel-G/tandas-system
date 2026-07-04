package com.pay.payment_system.service;

import static com.pay.payment_system.config.LogSanitizer.safe;

import com.pay.payment_system.DTO.EmailCanonicalizer;
import com.pay.payment_system.DTO.UserRegistrationDto;
import com.pay.payment_system.configservice.LoginLockoutEvaluationService;
import com.pay.payment_system.entity.Role;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.RoleRepository;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginLockoutEvaluationService lockoutEvaluationService;

    // REGISTERS AND SAVES A NEW USER IN THE DATABASE WITH A DEFAULT ROLE

    @Override
    @Transactional
    public UserAccount save(UserRegistrationDto dto, String canonicalEmail) {
        log.info("USER SERVICE: Registering new user account with email: {}", safe(canonicalEmail));

        if (userRepository.existsByMobileNumber(dto.getMobileNumber())) {
            log.warn("REGISTRATION BLOCKED: Mobile number {} is already linked to another account.", safe(dto.getMobileNumber()));
            throw new IllegalArgumentException("PHONE_ALREADY_IN_USE");
        }

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER could not be found in the database."));

        UserAccount user = UserAccount.builder()
                .name(dto.getName())
                .lastname(dto.getLastname())
                .emailCanonical(canonicalEmail)
                .emailDispatch(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .mobileNumber(dto.getMobileNumber())
                .roles(Set.of(defaultRole))
                .build();

        UserSecurity security = UserSecurity.builder().user(user).build();
        user.setSecurity(security);

        return userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username == null || username.isBlank()) {
            throw new UsernameNotFoundException("Username cannot be null or empty.");
        }

        String canonicalLoginEmail = EmailCanonicalizer.canonicalize(username);

        // EVALUATES TEMPORARY ACCOUNT LOCKOUT DUE TO SEVERAL REPEATED ATTEMPTS

        if (lockoutEvaluationService.isAccountLocked(canonicalLoginEmail, null)) {
            long remainingSeconds = lockoutEvaluationService.getRemainingLockoutTimeInSeconds(canonicalLoginEmail);

            throw new UsernameNotFoundException(
                    "Too many failed attempts. Account temporarily frozen. Retry after " + remainingSeconds + " seconds."
            );
        }


        UserAccount user = userRepository.findByEmailCanonicalWithSecurityAndRoles(canonicalLoginEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username or password."));

        UserSecurity security = user.getSecurity();
        if (security == null) {
            log.error("SECURITY CRITICAL: User {} exists but has no UserSecurity profile linked.", safe(canonicalLoginEmail));
            throw new UsernameNotFoundException("Invalid username or password.");
        }

        boolean isLockedInMySQL = !security.isAccountNonLocked();
        if (isLockedInMySQL) {
            log.warn("SECURITY LOCK: User {} is locked permanently in MySQL.", safe(canonicalLoginEmail));
            throw new org.springframework.security.authentication.LockedException("Account permanently locked.");
        }

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            request.setAttribute("LOCKOUT_EMAIL", canonicalLoginEmail);
        }

        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        return new User(
                user.getEmailCanonical(),
                user.getPassword(),
                true,
                true,
                true,
                true,
                authorities
        );
    }

    @Override
    @Transactional(readOnly = true)
    public UserAccount findByCanonicalEmail(String canonicalEmail) {
        if (canonicalEmail == null || canonicalEmail.isBlank()) {
            return null;
        }
        return userRepository.findByEmailCanonical(canonicalEmail.trim().toLowerCase());
    }

    // UPDATES ACCOUNT AUDIT HISTORY RECORDS WITH LAST TIME STAMP OF SUCCESSFUL ACCESS

    @Override
    @Transactional
    public void updateLastLoginDate(String canonicalEmail, LocalDateTime loginDate) {
        if (canonicalEmail == null || canonicalEmail.isBlank()) return;

        UserAccount user = userRepository.findByEmailCanonical(canonicalEmail.trim().toLowerCase());
        if (user != null && user.getSecurity() != null) {
            user.getSecurity().setLastLogin(loginDate);
            userRepository.save(user);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserAccount> findAllUsers() {
        log.info("USER SERVICE: Fetching all users.");
        return userRepository.findAll();
    }


    @Override
    @Transactional(readOnly = true)
    public UserAccount findByEmail(String email) {
        return findByCanonicalEmail(EmailCanonicalizer.canonicalize(email));
    }
}
